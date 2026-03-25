"""API Spec Parser — parses OpenAPI/Swagger specs into testable endpoint lists.

Extracts endpoints, methods, parameters, auth requirements, and generates
a prioritized test plan for the security agent.
"""

import json
import logging
from typing import Any
from urllib.parse import urljoin

from ziro.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Parameters that are high-value targets for injection
_INJECTION_PARAMS = {"id", "user_id", "userId", "email", "username", "token", "query", "q",
                     "search", "filter", "sort", "order", "page", "limit", "offset",
                     "file", "path", "url", "redirect", "callback", "next", "return"}

# HTTP methods ranked by risk
_METHOD_RISK = {"DELETE": 5, "PUT": 4, "PATCH": 4, "POST": 3, "GET": 2, "HEAD": 1, "OPTIONS": 0}


@register_tool(sandbox_execution=False)
def parse_api_spec(
    spec_content: str,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Parse an OpenAPI/Swagger specification and extract a security test plan."""
    if not spec_content or not spec_content.strip():
        return {"success": False, "error": "Spec content cannot be empty"}

    try:
        spec = json.loads(spec_content)
    except json.JSONDecodeError:
        # Try YAML
        try:
            import yaml  # type: ignore[import-untyped]
            spec = yaml.safe_load(spec_content)
        except (ImportError, Exception):
            return {"success": False, "error": "Could not parse spec as JSON or YAML. Provide valid OpenAPI/Swagger."}

    if not isinstance(spec, dict):
        return {"success": False, "error": "Spec must be a JSON/YAML object"}

    # Detect spec version
    version = _detect_version(spec)
    if not version:
        return {"success": False, "error": "Not a valid OpenAPI/Swagger spec (missing openapi or swagger field)"}

    # Extract base URL
    resolved_base = base_url or _extract_base_url(spec)

    # Extract endpoints
    endpoints = _extract_endpoints(spec, resolved_base)
    if not endpoints:
        return {"success": False, "error": "No endpoints found in spec"}

    # Extract auth schemes
    auth_schemes = _extract_auth(spec)

    # Prioritize for security testing
    prioritized = _prioritize_endpoints(endpoints)

    # Generate attack surface summary
    summary = _generate_summary(endpoints, auth_schemes)

    return {
        "success": True,
        "spec_version": version,
        "base_url": resolved_base,
        "total_endpoints": len(endpoints),
        "auth_schemes": auth_schemes,
        "summary": summary,
        "test_plan": prioritized[:50],  # Top 50 endpoints by risk
        "all_endpoints": endpoints,
    }


def _detect_version(spec: dict) -> str | None:
    if "openapi" in spec:
        return f"OpenAPI {spec['openapi']}"
    if "swagger" in spec:
        return f"Swagger {spec['swagger']}"
    return None


def _extract_base_url(spec: dict) -> str:
    # OpenAPI 3.x
    servers = spec.get("servers", [])
    if servers and isinstance(servers, list):
        return servers[0].get("url", "")

    # Swagger 2.x
    host = spec.get("host", "localhost")
    base_path = spec.get("basePath", "/")
    schemes = spec.get("schemes", ["https"])
    scheme = schemes[0] if schemes else "https"
    return f"{scheme}://{host}{base_path}"


def _extract_endpoints(spec: dict, base_url: str) -> list[dict[str, Any]]:
    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if not isinstance(operation, dict):
                continue

            method_upper = method.upper()
            full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

            endpoint: dict[str, Any] = {
                "path": path,
                "method": method_upper,
                "url": full_url,
                "operation_id": operation.get("operationId", ""),
                "summary": operation.get("summary", ""),
                "description": (operation.get("description", "") or "")[:200],
                "tags": operation.get("tags", []),
                "parameters": [],
                "request_body": None,
                "auth_required": bool(operation.get("security", spec.get("security"))),
                "deprecated": operation.get("deprecated", False),
            }

            # Extract parameters
            params = operation.get("parameters", []) + methods.get("parameters", [])
            for param in params:
                if not isinstance(param, dict):
                    continue
                # Resolve $ref if needed
                if "$ref" in param:
                    param = _resolve_ref(spec, param["$ref"]) or param

                p = {
                    "name": param.get("name", ""),
                    "in": param.get("in", "query"),
                    "required": param.get("required", False),
                    "type": _extract_type(param),
                    "injectable": param.get("name", "").lower() in _INJECTION_PARAMS,
                }
                endpoint["parameters"].append(p)

            # Extract request body (OpenAPI 3.x)
            request_body = operation.get("requestBody", {})
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                for media_type, schema_obj in content.items():
                    endpoint["request_body"] = {
                        "media_type": media_type,
                        "required": request_body.get("required", False),
                        "schema": _simplify_schema(schema_obj.get("schema", {}), spec),
                    }
                    break  # Take first content type

            endpoints.append(endpoint)

    return endpoints


def _extract_auth(spec: dict) -> list[dict[str, str]]:
    schemes = []

    # OpenAPI 3.x
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    # Swagger 2.x
    if not security_schemes:
        security_schemes = spec.get("securityDefinitions", {})

    for name, scheme in security_schemes.items():
        if not isinstance(scheme, dict):
            continue
        schemes.append({
            "name": name,
            "type": scheme.get("type", "unknown"),
            "scheme": scheme.get("scheme", ""),
            "in": scheme.get("in", ""),
            "description": (scheme.get("description", "") or "")[:100],
        })

    return schemes


def _prioritize_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score and sort endpoints by security testing priority."""
    scored = []
    for ep in endpoints:
        score = 0

        # Method risk
        score += _METHOD_RISK.get(ep["method"], 1) * 2

        # Injectable parameters
        injectable_count = sum(1 for p in ep["parameters"] if p.get("injectable"))
        score += injectable_count * 3

        # Has request body (more attack surface)
        if ep.get("request_body"):
            score += 3

        # Auth required (auth bypass testing)
        if ep.get("auth_required"):
            score += 2

        # Path contains IDs (IDOR potential)
        if "{" in ep["path"]:
            score += 2

        # File/upload related
        path_lower = ep["path"].lower()
        if any(kw in path_lower for kw in ("upload", "file", "import", "export")):
            score += 4

        # Admin/auth related
        if any(kw in path_lower for kw in ("admin", "auth", "login", "register", "password", "token")):
            score += 3

        ep_with_score = dict(ep)
        ep_with_score["risk_score"] = score
        scored.append(ep_with_score)

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return scored


def _generate_summary(endpoints: list[dict[str, Any]], auth_schemes: list[dict[str, str]]) -> dict[str, Any]:
    methods = {}
    tags = set()
    injectable_params = 0
    auth_endpoints = 0
    idor_candidates = 0

    for ep in endpoints:
        m = ep["method"]
        methods[m] = methods.get(m, 0) + 1
        tags.update(ep.get("tags", []))
        injectable_params += sum(1 for p in ep["parameters"] if p.get("injectable"))
        if ep.get("auth_required"):
            auth_endpoints += 1
        if "{" in ep["path"]:
            idor_candidates += 1

    return {
        "methods": methods,
        "tags": sorted(tags),
        "injectable_parameters": injectable_params,
        "auth_required_endpoints": auth_endpoints,
        "idor_candidates": idor_candidates,
        "auth_schemes": [s["type"] for s in auth_schemes],
        "attack_surface": (
            f"{len(endpoints)} endpoints, {injectable_params} injectable params, "
            f"{idor_candidates} IDOR candidates, {auth_endpoints} auth-required endpoints"
        ),
    }


def _extract_type(param: dict) -> str:
    schema = param.get("schema", {})
    if isinstance(schema, dict):
        return schema.get("type", param.get("type", "string"))
    return param.get("type", "string")


def _simplify_schema(schema: dict, spec: dict, depth: int = 0) -> dict[str, Any]:
    """Simplify a schema for display, resolving refs up to 2 levels deep."""
    if depth > 2:
        return {"type": "object", "note": "schema too deep"}

    if "$ref" in schema:
        resolved = _resolve_ref(spec, schema["$ref"])
        if resolved:
            return _simplify_schema(resolved, spec, depth + 1)

    result: dict[str, Any] = {"type": schema.get("type", "object")}

    if "properties" in schema:
        result["properties"] = {
            k: _simplify_schema(v, spec, depth + 1)
            for k, v in schema["properties"].items()
        }
    if "required" in schema:
        result["required"] = schema["required"]
    if "items" in schema and isinstance(schema["items"], dict):
        result["items"] = _simplify_schema(schema["items"], spec, depth + 1)
    if "enum" in schema:
        result["enum"] = schema["enum"]

    return result


def _resolve_ref(spec: dict, ref: str) -> dict | None:
    """Resolve a JSON $ref pointer."""
    if not ref.startswith("#/"):
        return None

    parts = ref[2:].split("/")
    current: Any = spec
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None

    return current if isinstance(current, dict) else None
