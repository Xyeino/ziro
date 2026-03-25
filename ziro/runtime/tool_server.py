from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError


SANDBOX_MODE = os.getenv("ZIRO_SANDBOX_MODE", "false").lower() == "true"
if not SANDBOX_MODE:
    raise RuntimeError("Tool server should only run in sandbox mode (ZIRO_SANDBOX_MODE=true)")

parser = argparse.ArgumentParser(description="Start Ziro tool server")
parser.add_argument("--token", required=True, help="Authentication token")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
parser.add_argument("--port", type=int, required=True, help="Port to bind to")
parser.add_argument(
    "--timeout",
    type=int,
    default=120,
    help="Hard timeout in seconds for each request execution (default: 120)",
)

args = parser.parse_args()

if not args.port or args.port < 1 or args.port > 65535:
    parser.error(f"Invalid port number: {args.port}. Must be between 1 and 65535.")

if not args.token or not args.token.strip():
    parser.error("Authentication token must not be empty.")

EXPECTED_TOKEN = args.token
REQUEST_TIMEOUT = args.timeout

app = FastAPI()
security = HTTPBearer()
security_dependency = Depends(security)

agent_tasks: dict[str, asyncio.Task[Any]] = {}


def verify_token(credentials: HTTPAuthorizationCredentials) -> str:
    if not credentials or credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None


async def _run_tool(agent_id: str, tool_name: str, kwargs: dict[str, Any]) -> Any:
    from ziro.tools.argument_parser import convert_arguments
    from ziro.tools.context import set_current_agent_id
    from ziro.tools.registry import get_tool_by_name

    set_current_agent_id(agent_id)

    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)
    return await asyncio.to_thread(tool_func, **converted_kwargs)


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest, credentials: HTTPAuthorizationCredentials = security_dependency
) -> ToolExecutionResponse:
    verify_token(credentials)

    agent_id = request.agent_id

    if agent_id in agent_tasks:
        old_task = agent_tasks[agent_id]
        if not old_task.done():
            old_task.cancel()

    task = asyncio.create_task(
        asyncio.wait_for(
            _run_tool(agent_id, request.tool_name, request.kwargs), timeout=REQUEST_TIMEOUT
        )
    )
    agent_tasks[agent_id] = task

    try:
        result = await task
        return ToolExecutionResponse(result=result)

    except asyncio.CancelledError:
        return ToolExecutionResponse(error="Cancelled by newer request")

    except TimeoutError:
        return ToolExecutionResponse(error=f"Tool timed out after {REQUEST_TIMEOUT}s")

    except ValidationError as e:
        return ToolExecutionResponse(error=f"Invalid arguments: {e}")

    except (ValueError, RuntimeError, ImportError) as e:
        return ToolExecutionResponse(error=f"Tool execution error: {e}")

    except Exception as e:  # noqa: BLE001
        return ToolExecutionResponse(error=f"Unexpected error: {e}")

    finally:
        if agent_tasks.get(agent_id) is task:
            del agent_tasks[agent_id]


@app.post("/register_agent")
async def register_agent(
    agent_id: str, credentials: HTTPAuthorizationCredentials = security_dependency
) -> dict[str, str]:
    verify_token(credentials)
    return {"status": "registered", "agent_id": agent_id}


@app.get("/health")
async def health_check() -> dict[str, Any]:
    checks: dict[str, str] = {}
    overall_healthy = True

    # Check tool registry is loadable
    try:
        from ziro.tools.registry import get_tool_by_name

        get_tool_by_name("run_terminal_command")
        checks["tool_registry"] = "ok"
    except Exception as e:  # noqa: BLE001
        checks["tool_registry"] = f"error: {e}"
        overall_healthy = False

    # Check tmux/libtmux availability (required for terminal tools)
    try:
        import shutil

        if shutil.which("tmux"):
            checks["tmux"] = "ok"
        else:
            checks["tmux"] = "not found"
            overall_healthy = False
    except Exception as e:  # noqa: BLE001
        checks["tmux"] = f"error: {e}"
        overall_healthy = False

    status = "healthy" if overall_healthy else "degraded"

    return {
        "status": status,
        "sandbox_mode": str(SANDBOX_MODE),
        "environment": "sandbox" if SANDBOX_MODE else "main",
        "auth_configured": "true" if EXPECTED_TOKEN else "false",
        "active_agents": len(agent_tasks),
        "agents": list(agent_tasks.keys()),
        "checks": checks,
    }


def signal_handler(_signum: int, _frame: Any) -> None:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    for task in agent_tasks.values():
        task.cancel()
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
