"""API surface auto-discovery — OpenAPI/Swagger/GraphQL from common paths.

Crawling alone typically finds only the endpoints that the frontend happens to
call from visible pages. Most web apps expose their full API contract at one
of a handful of well-known paths — this tool hits them all in parallel, parses
what comes back, and returns an enriched endpoint inventory.

For GraphQL specifically, attempts an introspection query regardless of whether
introspection is "disabled" on the client (the standard header may still be
accepted server-side by misconfigured servers).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from ziro.tools.registry import register_tool


# Common OpenAPI/Swagger spec paths
OPENAPI_CANDIDATES = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/swagger-ui.html",
    "/api-docs",
    "/api-docs.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/v1/api-docs",
    "/api-spec.json",
    "/docs/openapi.json",
    "/docs/swagger.json",
    "/docs/api.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/.well-known/openapi.json",
    "/rest/api-docs",
    "/redoc",
    "/scalar",
    "/scalar.json",
    "/rapidoc",
]

# Common GraphQL endpoint paths
GRAPHQL_CANDIDATES = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/api/query",
    "/api/gql",
    "/graphiql",
    "/playground",
    "/apollo",
    "/.netlify/functions/graphql",
    "/api/__graphql",
    "/_graphql",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name description type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
      inputFields { name description type { name kind ofType { name kind } } }
      interfaces { name }
      enumValues { name }
      possibleTypes { name }
    }
    directives { name description locations args { name } }
  }
}
"""


def _normalize_base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}"


@register_tool(sandbox_execution=True)
def discover_api_spec(
    agent_state: Any,
    target: str,
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    timeout: int = 8,
    include_yaml: bool = True,
) -> dict[str, Any]:
    """Try ~30 well-known paths for an OpenAPI/Swagger spec on the target.

    Hits each candidate with a GET; any 200 response that contains `"openapi"`
    or `"swagger"` (JSON) or a YAML-shaped `openapi:` / `swagger:` (YAML) is
    considered a hit. Returns the full list of found specs with their raw
    content, along with a parsed summary of the first one.

    Follow up with parse_api_spec on any of the `found_specs` entries for
    detailed endpoint extraction, or just read them from the returned content.
    """
    try:
        import requests

        base = _normalize_base(target)
        headers = {"User-Agent": user_agent, "Accept": "application/json, */*"}
        found_specs: list[dict[str, Any]] = []
        checked: list[dict[str, Any]] = []

        candidates = OPENAPI_CANDIDATES
        if not include_yaml:
            candidates = [c for c in candidates if not c.endswith((".yaml", ".yml"))]

        for path in candidates:
            url = base + path
            try:
                r = requests.get(url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
            except Exception as e:
                checked.append({"url": url, "error": str(e)[:100]})
                continue

            status = r.status_code
            ctype = r.headers.get("content-type", "")
            body = r.text
            hit = False
            kind = None

            if status == 200 and len(body) > 50:
                body_lower = body[:4000].lower()
                if (
                    '"openapi"' in body[:4000]
                    or '"swagger"' in body[:4000]
                    or "openapi:" in body_lower[:4000]
                    or "swagger:" in body_lower[:4000]
                ):
                    hit = True
                    kind = "openapi-like"

                # Detect if it's an HTML swagger-ui page pointing to a real spec
                if (
                    "swagger-ui" in body_lower[:2000]
                    or "redoc" in body_lower[:2000]
                    or "rapidoc" in body_lower[:2000]
                ):
                    # Try to extract the spec url from the HTML
                    spec_url_match = re.search(
                        r'url:\s*["\']([^"\']+\.(?:json|yaml|yml))["\']',
                        body[:20000],
                    )
                    if spec_url_match:
                        inner = spec_url_match.group(1)
                        if inner.startswith("/"):
                            inner = base + inner
                        elif not inner.startswith(("http://", "https://")):
                            inner = urljoin(url, inner)
                        try:
                            ir = requests.get(inner, timeout=timeout, headers=headers, verify=False)
                            if ir.status_code == 200 and len(ir.text) > 50:
                                found_specs.append(
                                    {
                                        "url": inner,
                                        "content_type": ir.headers.get("content-type", ""),
                                        "size": len(ir.text),
                                        "kind": "openapi-extracted-from-ui",
                                        "content": ir.text[:200_000],
                                    }
                                )
                        except Exception:
                            pass
                        hit = True
                        kind = kind or "swagger-ui-html"

            checked.append({"url": url, "status": status, "hit": hit})
            if hit and kind != "swagger-ui-html":
                found_specs.append(
                    {
                        "url": url,
                        "content_type": ctype,
                        "size": len(body),
                        "kind": kind or "unknown",
                        "content": body[:200_000],
                    }
                )

        # Dedupe found specs by URL
        unique: dict[str, dict[str, Any]] = {}
        for spec in found_specs:
            unique.setdefault(spec["url"], spec)
        found_specs = list(unique.values())

        # Extract endpoints from the first real JSON spec if any
        quick_summary: dict[str, Any] = {}
        for spec in found_specs:
            try:
                data = json.loads(spec["content"])
            except Exception:
                continue
            paths = data.get("paths", {})
            if paths:
                methods_count: dict[str, int] = {}
                for path_obj in paths.values():
                    if isinstance(path_obj, dict):
                        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
                            if method in path_obj:
                                methods_count[method.upper()] = methods_count.get(method.upper(), 0) + 1
                quick_summary = {
                    "spec_url": spec["url"],
                    "title": (data.get("info") or {}).get("title", ""),
                    "version": (data.get("info") or {}).get("version", ""),
                    "openapi_version": data.get("openapi") or data.get("swagger", ""),
                    "total_paths": len(paths),
                    "method_counts": methods_count,
                    "first_20_paths": list(paths.keys())[:20],
                }
                break

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"discover_api_spec failed: {e!s}"}
    else:
        return {
            "success": True,
            "target": target,
            "base": base,
            "candidates_checked": len(checked),
            "specs_found": len(found_specs),
            "found_specs": [{k: v for k, v in s.items() if k != "content"} | {"content_preview": s["content"][:2000]} for s in found_specs],
            "quick_summary": quick_summary,
            "hits": [c for c in checked if c.get("hit")],
        }


@register_tool(sandbox_execution=True)
def discover_graphql_endpoint(
    agent_state: Any,
    target: str,
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    timeout: int = 10,
    try_introspection: bool = True,
    try_apollo_variants: bool = True,
) -> dict[str, Any]:
    """Find GraphQL endpoints by probing ~15 common paths, attempt introspection.

    Probes each candidate with a minimal `{ __typename }` POST first. If the
    response looks like a GraphQL error or data envelope, marks it as a hit.
    If try_introspection=true and a hit is found, runs the full IntrospectionQuery
    against it — many servers advertise introspection disabled via a flag but
    still respond to the POST, and some have middleware that only blocks
    GET-introspection while allowing POST.

    Also tries Apollo-specific variants (persisted queries, trace headers) when
    try_apollo_variants=true to detect servers that accept only those shapes.
    """
    try:
        import requests

        base = _normalize_base(target)
        headers = {
            "User-Agent": user_agent,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        hits: list[dict[str, Any]] = []
        introspection_result: dict[str, Any] | None = None

        # Minimal probe
        probe_payload = {"query": "{ __typename }"}

        for path in GRAPHQL_CANDIDATES:
            url = base + path
            try:
                r = requests.post(
                    url,
                    json=probe_payload,
                    timeout=timeout,
                    headers=headers,
                    verify=False,
                    allow_redirects=True,
                )
            except Exception:
                continue

            body = r.text[:4000]
            looks_like_graphql = False
            reason = ""
            if r.status_code == 200:
                if '"data"' in body and '"__typename"' in body:
                    looks_like_graphql = True
                    reason = "data envelope with __typename"
                elif '"errors"' in body and ("graphql" in body.lower() or '"path"' in body or '"locations"' in body):
                    looks_like_graphql = True
                    reason = "errors envelope with graphql markers"
            elif r.status_code in (400, 405) and '"errors"' in body and "graphql" in body.lower():
                looks_like_graphql = True
                reason = f"HTTP {r.status_code} with graphql error envelope"

            if looks_like_graphql:
                hits.append(
                    {
                        "url": url,
                        "status": r.status_code,
                        "reason": reason,
                        "preview": body[:500],
                    }
                )

        # Attempt full introspection on the first hit
        if hits and try_introspection:
            first = hits[0]["url"]
            try:
                ir = requests.post(
                    first,
                    json={"query": INTROSPECTION_QUERY},
                    timeout=timeout * 3,
                    headers=headers,
                    verify=False,
                )
                if ir.status_code == 200:
                    try:
                        data = ir.json()
                        schema = (data.get("data") or {}).get("__schema")
                        if schema:
                            types = schema.get("types") or []
                            query_type = (schema.get("queryType") or {}).get("name", "")
                            mutation_type = (schema.get("mutationType") or {}).get("name", "")
                            query_fields: list[str] = []
                            mutation_fields: list[str] = []
                            for t in types:
                                if t.get("name") == query_type and t.get("fields"):
                                    query_fields = [f.get("name", "") for f in t["fields"]]
                                elif t.get("name") == mutation_type and t.get("fields"):
                                    mutation_fields = [f.get("name", "") for f in t["fields"]]

                            introspection_result = {
                                "success": True,
                                "endpoint": first,
                                "query_type": query_type,
                                "mutation_type": mutation_type,
                                "total_types": len(types),
                                "query_fields": query_fields[:100],
                                "mutation_fields": mutation_fields[:100],
                                "user_defined_types": [
                                    t.get("name", "")
                                    for t in types
                                    if t.get("name")
                                    and not t["name"].startswith("__")
                                    and t.get("kind") in ("OBJECT", "INPUT_OBJECT", "INTERFACE", "ENUM", "UNION")
                                ][:100],
                            }
                        elif "errors" in data:
                            introspection_result = {
                                "success": False,
                                "endpoint": first,
                                "error": "Introspection disabled or blocked",
                                "errors": data.get("errors", [])[:3],
                            }
                    except Exception as e:
                        introspection_result = {
                            "success": False,
                            "endpoint": first,
                            "error": f"Introspection parse failed: {e!s}",
                        }
            except Exception as e:
                introspection_result = {
                    "success": False,
                    "endpoint": first,
                    "error": f"Introspection request failed: {e!s}",
                }

        # Apollo variants — sometimes servers only accept persisted queries
        apollo_notes: list[dict[str, Any]] = []
        if hits and try_apollo_variants:
            first = hits[0]["url"]
            for variant_name, variant_headers in [
                ("apollo-persisted-query", {"apollographql-client-name": "probe", "x-apollo-operation-name": "IntrospectionQuery"}),
                ("apollo-trace", {"apollographql-client-name": "probe", "apollo-federation-include-trace": "ftv1"}),
            ]:
                try:
                    vh = {**headers, **variant_headers}
                    vr = requests.post(first, json=probe_payload, timeout=timeout, headers=vh, verify=False)
                    apollo_notes.append(
                        {
                            "variant": variant_name,
                            "status": vr.status_code,
                            "differs_from_plain": vr.text[:100] != hits[0].get("preview", "")[:100],
                        }
                    )
                except Exception:
                    pass

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"discover_graphql_endpoint failed: {e!s}"}
    else:
        return {
            "success": True,
            "target": target,
            "base": base,
            "hits": hits,
            "hit_count": len(hits),
            "introspection": introspection_result,
            "apollo_variants": apollo_notes,
        }
