import threading
from datetime import UTC, datetime
from typing import Any, Literal

from ziro.tools.registry import register_tool


_graph_lock = threading.Lock()

_agent_graph: dict[str, Any] = {
    "nodes": {},
    "edges": [],
}

_root_agent_id: str | None = None

_agent_messages: dict[str, list[dict[str, Any]]] = {}

_running_agents: dict[str, threading.Thread] = {}

_agent_instances: dict[str, Any] = {}

_agent_states: dict[str, Any] = {}


def _run_agent_in_thread(
    agent: Any, state: Any, inherited_messages: list[dict[str, Any]]
) -> dict[str, Any]:
    try:
        if inherited_messages:
            state.add_message("user", "<inherited_context_from_parent>")
            for msg in inherited_messages:
                state.add_message(msg["role"], msg["content"])
            state.add_message("user", "</inherited_context_from_parent>")

        with _graph_lock:
            parent_info = _agent_graph["nodes"].get(state.parent_id, {})
            parent_name = parent_info.get("name", "Unknown Parent")

        context_status = (
            "inherited conversation context from your parent for background understanding"
            if inherited_messages
            else "started with a fresh context"
        )

        # Compact delegation message. Most rules below were repeated boilerplate
        # the model already knows from the system prompt — kept only the
        # task-specific facts (identity, parent, context status).
        task_xml = (
            f"<agent_delegation>\n"
            f"You are sub-agent {state.agent_name} ({state.agent_id}), "
            f"reporting to {parent_name} ({state.parent_id}).\n"
            f"Task: {state.task}\n"
            f"Context: {context_status}. "
            f"Workspace at /workspace shared with peer agents. "
            f"Call agent_finish when complete.\n"
            f"</agent_delegation>"
        )

        state.add_message("user", task_xml)

        with _graph_lock:
            _agent_states[state.agent_id] = state
            _agent_graph["nodes"][state.agent_id]["state"] = state.model_dump()

        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(agent.agent_loop(state.task))
        finally:
            loop.close()

    except Exception as e:
        with _graph_lock:
            _agent_graph["nodes"][state.agent_id]["status"] = "error"
            _agent_graph["nodes"][state.agent_id]["finished_at"] = datetime.now(UTC).isoformat()
            _agent_graph["nodes"][state.agent_id]["result"] = {"error": str(e)}
            _running_agents.pop(state.agent_id, None)
            _agent_instances.pop(state.agent_id, None)

            # Notify parent agent about the crash
            if state.parent_id:
                if state.parent_id not in _agent_messages:
                    _agent_messages[state.parent_id] = []
                _agent_messages[state.parent_id].append(
                    {
                        "id": f"crash_{state.agent_id[:8]}",
                        "from": state.agent_id,
                        "to": state.parent_id,
                        "content": (
                            f"<agent_crash_report>\n"
                            f"  <agent_name>{state.agent_name}</agent_name>\n"
                            f"  <agent_id>{state.agent_id}</agent_id>\n"
                            f"  <error>{e}</error>\n"
                            f"  <task>{state.task}</task>\n"
                            f"</agent_crash_report>"
                        ),
                        "message_type": "information",
                        "priority": "urgent",
                        "timestamp": datetime.now(UTC).isoformat(),
                        "delivered": True,
                        "read": False,
                    }
                )
        raise
    else:
        with _graph_lock:
            if state.stop_requested:
                _agent_graph["nodes"][state.agent_id]["status"] = "stopped"
            else:
                _agent_graph["nodes"][state.agent_id]["status"] = "completed"
            _agent_graph["nodes"][state.agent_id]["finished_at"] = datetime.now(UTC).isoformat()
            _agent_graph["nodes"][state.agent_id]["result"] = result
            _running_agents.pop(state.agent_id, None)
            _agent_instances.pop(state.agent_id, None)

        return {"result": result}


@register_tool(sandbox_execution=False)
def view_agent_graph(agent_state: Any) -> dict[str, Any]:
    try:
        # Snapshot under lock to avoid races during tree traversal
        with _graph_lock:
            nodes_snapshot = {k: dict(v) for k, v in _agent_graph["nodes"].items()}
            edges_snapshot = list(_agent_graph["edges"])
            root_id_snapshot = _root_agent_id

        structure_lines = ["=== AGENT GRAPH STRUCTURE ==="]

        def _build_tree(agent_id: str, depth: int = 0) -> None:
            node = nodes_snapshot[agent_id]
            indent = "  " * depth

            you_indicator = " ← This is you" if agent_id == agent_state.agent_id else ""

            structure_lines.append(f"{indent}* {node['name']} ({agent_id}){you_indicator}")
            structure_lines.append(f"{indent}  Task: {node['task']}")
            structure_lines.append(f"{indent}  Status: {node['status']}")

            children = [
                edge["to"]
                for edge in edges_snapshot
                if edge["from"] == agent_id and edge["type"] == "delegation"
            ]

            if children:
                structure_lines.append(f"{indent}   Children:")
                for child_id in children:
                    if child_id in nodes_snapshot:
                        _build_tree(child_id, depth + 2)

        root_agent_id = root_id_snapshot
        if not root_agent_id and nodes_snapshot:
            for agent_id, node in nodes_snapshot.items():
                if node.get("parent_id") is None:
                    root_agent_id = agent_id
                    break
            if not root_agent_id:
                root_agent_id = next(iter(nodes_snapshot.keys()))

        if root_agent_id and root_agent_id in nodes_snapshot:
            _build_tree(root_agent_id)
        else:
            structure_lines.append("No agents in the graph yet")

        graph_structure = "\n".join(structure_lines)

        total_nodes = len(nodes_snapshot)
        running_count = sum(
            1 for node in nodes_snapshot.values() if node["status"] == "running"
        )
        waiting_count = sum(
            1 for node in nodes_snapshot.values() if node["status"] == "waiting"
        )
        stopping_count = sum(
            1 for node in nodes_snapshot.values() if node["status"] == "stopping"
        )
        completed_count = sum(
            1 for node in nodes_snapshot.values() if node["status"] == "completed"
        )
        stopped_count = sum(
            1 for node in nodes_snapshot.values() if node["status"] == "stopped"
        )
        failed_count = sum(
            1 for node in nodes_snapshot.values() if node["status"] in ["failed", "error"]
        )

    except Exception as e:  # noqa: BLE001
        return {
            "error": f"Failed to view agent graph: {e}",
            "graph_structure": "Error retrieving graph structure",
        }
    else:
        return {
            "graph_structure": graph_structure,
            "summary": {
                "total_agents": total_nodes,
                "running": running_count,
                "waiting": waiting_count,
                "stopping": stopping_count,
                "completed": completed_count,
                "stopped": stopped_count,
                "failed": failed_count,
            },
        }


@register_tool(sandbox_execution=False)
def create_agent(
    agent_state: Any,
    task: str,
    name: str,
    inherit_context: bool = True,
    skills: str | None = None,
    threat_actor: str | None = None,
) -> dict[str, Any]:
    try:
        parent_id = agent_state.agent_id

        from ziro.skills import parse_skill_list, validate_requested_skills

        skill_list = parse_skill_list(skills)
        validation_error = validate_requested_skills(skill_list)
        if validation_error:
            return {
                "success": False,
                "error": validation_error,
                "agent_id": None,
            }

        from ziro.agents import ZiroAgent
        from ziro.agents.state import AgentState
        from ziro.llm.config import LLMConfig

        with _graph_lock:
            parent_agent = _agent_instances.get(parent_id)

        timeout = None
        scan_mode = "deep"
        interactive = False
        inherited_threat_actor: str | None = None
        if parent_agent and hasattr(parent_agent, "llm_config"):
            if hasattr(parent_agent.llm_config, "timeout"):
                timeout = parent_agent.llm_config.timeout
            if hasattr(parent_agent.llm_config, "scan_mode"):
                scan_mode = parent_agent.llm_config.scan_mode
            interactive = getattr(parent_agent.llm_config, "interactive", False)
            inherited_threat_actor = getattr(parent_agent.llm_config, "threat_actor", None)

        # Sub-agent threat actor: explicit argument takes precedence over parent's.
        effective_threat_actor = threat_actor or inherited_threat_actor

        state = AgentState(
            task=task,
            agent_name=name,
            parent_id=parent_id,
            max_iterations=300,
            waiting_timeout=300 if interactive else 600,
        )

        llm_config = LLMConfig(
            skills=skill_list,
            timeout=timeout,
            scan_mode=scan_mode,
            interactive=interactive,
            threat_actor=effective_threat_actor,
        )

        agent_config = {
            "llm_config": llm_config,
            "state": state,
        }

        agent = ZiroAgent(agent_config)

        # Propagate user_instructions to sub-agent's system prompt context
        try:
            from ziro.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer and tracer.scan_config:
                user_instructions = tracer.scan_config.get("user_instructions", "")
                if user_instructions and hasattr(agent, "llm"):
                    existing_context = getattr(agent.llm, "_system_prompt_context", {}) or {}
                    existing_context["user_instructions"] = user_instructions
                    agent.llm.set_system_prompt_context(existing_context)
        except (ImportError, AttributeError):
            pass

        inherited_messages = []
        if inherit_context:
            inherited_messages = agent_state.get_conversation_history()

        with _graph_lock:
            _agent_instances[state.agent_id] = agent

        thread = threading.Thread(
            target=_run_agent_in_thread,
            args=(agent, state, inherited_messages),
            daemon=True,
            name=f"Agent-{name}-{state.agent_id}",
        )
        thread.start()
        with _graph_lock:
            _running_agents[state.agent_id] = thread

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to create agent: {e}", "agent_id": None}
    else:
        return {
            "success": True,
            "agent_id": state.agent_id,
            "message": f"Agent '{name}' created and started asynchronously",
            "agent_info": {
                "id": state.agent_id,
                "name": name,
                "status": "running",
                "parent_id": parent_id,
            },
        }


@register_tool(sandbox_execution=False)
def send_message_to_agent(
    agent_state: Any,
    target_agent_id: str,
    message: str,
    message_type: Literal["query", "instruction", "information"] = "information",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> dict[str, Any]:
    try:
        sender_id = agent_state.agent_id

        from uuid import uuid4

        message_id = f"msg_{uuid4().hex[:8]}"
        message_data = {
            "id": message_id,
            "from": sender_id,
            "to": target_agent_id,
            "content": message,
            "message_type": message_type,
            "priority": priority,
            "timestamp": datetime.now(UTC).isoformat(),
            "delivered": False,
            "read": False,
        }

        with _graph_lock:
            if target_agent_id not in _agent_graph["nodes"]:
                return {
                    "success": False,
                    "error": f"Target agent '{target_agent_id}' not found in graph",
                    "message_id": None,
                }

            if target_agent_id not in _agent_messages:
                _agent_messages[target_agent_id] = []

            _agent_messages[target_agent_id].append(message_data)

            _agent_graph["edges"].append(
                {
                    "from": sender_id,
                    "to": target_agent_id,
                    "type": "message",
                    "message_id": message_id,
                    "message_type": message_type,
                    "priority": priority,
                    "created_at": datetime.now(UTC).isoformat(),
                }
            )

            message_data["delivered"] = True

            target_name = _agent_graph["nodes"][target_agent_id]["name"]
            sender_name = _agent_graph["nodes"][sender_id]["name"]
            target_status = _agent_graph["nodes"][target_agent_id]["status"]

        return {
            "success": True,
            "message_id": message_id,
            "message": f"Message sent from '{sender_name}' to '{target_name}'",
            "delivery_status": "delivered",
            "target_agent": {
                "id": target_agent_id,
                "name": target_name,
                "status": target_status,
            },
        }

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to send message: {e}", "message_id": None}


@register_tool(sandbox_execution=False)
def agent_finish(
    agent_state: Any,
    result_summary: str,
    findings: list[str] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> dict[str, Any]:
    try:
        if not hasattr(agent_state, "parent_id") or agent_state.parent_id is None:
            return {
                "agent_completed": False,
                "error": (
                    "This tool can only be used by subagents. "
                    "Root/main agents must use finish_scan instead."
                ),
                "parent_notified": False,
            }

        agent_id = agent_state.agent_id

        with _graph_lock:
            if agent_id not in _agent_graph["nodes"]:
                return {"agent_completed": False, "error": "Current agent not found in graph"}

            agent_node = _agent_graph["nodes"][agent_id]

            agent_node["status"] = "finished" if success else "failed"
            agent_node["finished_at"] = datetime.now(UTC).isoformat()
            agent_node["result"] = {
                "summary": result_summary,
                "findings": findings or [],
                "success": success,
                "recommendations": final_recommendations or [],
            }

        parent_notified = False

        with _graph_lock:
            parent_id_val = agent_node.get("parent_id")

        if report_to_parent and parent_id_val:
            parent_id = parent_id_val

            with _graph_lock:
                parent_exists = parent_id in _agent_graph["nodes"]

            if parent_exists:
                # Compact completion report — half the tokens of the previous
                # nested XML form. The findings/recommendations are still
                # listed line-by-line, just without the extra wrapper tags.
                status_str = "SUCCESS" if success else "FAILED"
                findings_block = ""
                if findings:
                    findings_block = "\nFindings:\n" + "\n".join(
                        f"- {f}" for f in findings
                    )
                recs_block = ""
                if final_recommendations:
                    recs_block = "\nRecommendations:\n" + "\n".join(
                        f"- {r}" for r in final_recommendations
                    )
                report_message = (
                    f"<agent_completion_report from=\"{agent_node['name']}\" "
                    f"status=\"{status_str}\">\n"
                    f"Task: {agent_node['task']}\n"
                    f"Summary: {result_summary}"
                    f"{findings_block}{recs_block}\n"
                    f"</agent_completion_report>"
                )

                from uuid import uuid4

                with _graph_lock:
                    if parent_id not in _agent_messages:
                        _agent_messages[parent_id] = []

                    _agent_messages[parent_id].append(
                        {
                            "id": f"report_{uuid4().hex[:8]}",
                            "from": agent_id,
                            "to": parent_id,
                            "content": report_message,
                            "message_type": "information",
                            "priority": "high",
                            "timestamp": datetime.now(UTC).isoformat(),
                            "delivered": True,
                            "read": False,
                        }
                    )

                parent_notified = True

        with _graph_lock:
            _running_agents.pop(agent_id, None)

        return {
            "agent_completed": True,
            "parent_notified": parent_notified,
            "completion_summary": {
                "agent_id": agent_id,
                "agent_name": agent_node["name"],
                "task": agent_node["task"],
                "success": success,
                "findings_count": len(findings or []),
                "has_recommendations": bool(final_recommendations),
                "finished_at": agent_node["finished_at"],
            },
        }

    except Exception as e:  # noqa: BLE001
        return {
            "agent_completed": False,
            "error": f"Failed to complete agent: {e}",
            "parent_notified": False,
        }


def stop_agent(agent_id: str) -> dict[str, Any]:
    try:
        with _graph_lock:
            if agent_id not in _agent_graph["nodes"]:
                return {
                    "success": False,
                    "error": f"Agent '{agent_id}' not found in graph",
                    "agent_id": agent_id,
                }

            agent_node = _agent_graph["nodes"][agent_id]

            if agent_node["status"] in ["completed", "error", "failed", "stopped"]:
                return {
                    "success": True,
                    "message": f"Agent '{agent_node['name']}' was already stopped",
                    "agent_id": agent_id,
                    "previous_status": agent_node["status"],
                }

            agent_state = _agent_states.get(agent_id)
            agent_instance = _agent_instances.get(agent_id)

        # Call request_stop/cancel outside lock to avoid holding it during potentially slow ops
        if agent_state:
            agent_state.request_stop()

        if agent_instance:
            if hasattr(agent_instance, "state"):
                agent_instance.state.request_stop()
            if hasattr(agent_instance, "cancel_current_execution"):
                agent_instance.cancel_current_execution()

        with _graph_lock:
            agent_node["status"] = "stopping"
            agent_node["result"] = {
                "summary": "Agent stop requested by user",
                "success": False,
                "stopped_by_user": True,
            }
            agent_name = agent_node["name"]

        try:
            from ziro.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer:
                tracer.update_agent_status(agent_id, "stopping")
        except (ImportError, AttributeError):
            pass

        return {
            "success": True,
            "message": f"Stop request sent to agent '{agent_name}'",
            "agent_id": agent_id,
            "agent_name": agent_name,
            "note": "Agent will stop gracefully after current iteration",
        }

    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to stop agent: {e}",
            "agent_id": agent_id,
        }


def send_user_message_to_agent(agent_id: str, message: str) -> dict[str, Any]:
    try:
        from uuid import uuid4

        message_data = {
            "id": f"user_msg_{uuid4().hex[:8]}",
            "from": "user",
            "to": agent_id,
            "content": message,
            "message_type": "instruction",
            "priority": "high",
            "timestamp": datetime.now(UTC).isoformat(),
            "delivered": True,
            "read": False,
        }

        with _graph_lock:
            if agent_id not in _agent_graph["nodes"]:
                return {
                    "success": False,
                    "error": f"Agent '{agent_id}' not found in graph",
                    "agent_id": agent_id,
                }

            agent_name = _agent_graph["nodes"][agent_id]["name"]

            if agent_id not in _agent_messages:
                _agent_messages[agent_id] = []
            _agent_messages[agent_id].append(message_data)

        return {
            "success": True,
            "message": f"Message sent to agent '{agent_name}'",
            "agent_id": agent_id,
            "agent_name": agent_name,
        }

    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to send message to agent: {e}",
            "agent_id": agent_id,
        }


@register_tool(sandbox_execution=False)
def wait_for_message(
    agent_state: Any,
    reason: str = "Waiting for messages from other agents",
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_name = agent_state.agent_name

        agent_state.enter_waiting_state()

        with _graph_lock:
            if agent_id in _agent_graph["nodes"]:
                _agent_graph["nodes"][agent_id]["status"] = "waiting"
                _agent_graph["nodes"][agent_id]["waiting_reason"] = reason

        try:
            from ziro.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer:
                tracer.update_agent_status(agent_id, "waiting")
        except (ImportError, AttributeError):
            pass

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to enter waiting state: {e}", "status": "error"}
    else:
        return {
            "success": True,
            "status": "waiting",
            "message": f"Agent '{agent_name}' is now waiting for messages",
            "reason": reason,
            "agent_info": {
                "id": agent_id,
                "name": agent_name,
                "status": "waiting",
            },
            "resume_conditions": [
                "Message from another agent",
                "Message from user",
                "Direct communication",
                "Waiting timeout reached",
            ],
        }
