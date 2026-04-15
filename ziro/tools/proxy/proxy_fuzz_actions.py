"""Higher-level replay: parameter fuzzing and response diffing over captured requests.

Builds on the existing repeat_request/list_requests primitives to give agents
a fast loop for 'take this captured request, swap out parameter X with each
payload in this list, tell me which ones looked interesting'. Also diffs
two responses (baseline vs probe) so the agent can spot injection/bypass
effects without scrolling through raw HTTP blobs.
"""

from __future__ import annotations

import difflib
from typing import Any

from ziro.tools.registry import register_tool


def _score_response_interest(
    baseline: dict[str, Any], probe: dict[str, Any]
) -> dict[str, Any]:
    """Heuristic 'is this probe interesting vs baseline?' score."""
    base_status = baseline.get("status_code") or baseline.get("status") or 0
    probe_status = probe.get("status_code") or probe.get("status") or 0
    base_len = baseline.get("response_size") or len(str(baseline.get("body", ""))) or 0
    probe_len = probe.get("response_size") or len(str(probe.get("body", ""))) or 0
    base_time = baseline.get("response_time") or 0
    probe_time = probe.get("response_time") or 0

    reasons: list[str] = []
    score = 0

    # Different status code is a huge signal
    if probe_status != base_status:
        reasons.append(f"status changed {base_status}->{probe_status}")
        score += 30
        if probe_status >= 500:
            reasons.append(f"server error {probe_status}")
            score += 30

    # Length difference
    if base_len:
        ratio = abs(probe_len - base_len) / max(base_len, 1)
        if ratio > 0.5:
            reasons.append(f"length differs by {int(ratio * 100)}%")
            score += 15
        elif ratio > 0.1:
            reasons.append(f"length differs by {int(ratio * 100)}%")
            score += 5

    # Timing delta (SQLi / time-based blind)
    if base_time and probe_time:
        if probe_time > base_time * 3 and probe_time > 2.0:
            reasons.append(f"response time {probe_time:.1f}s vs baseline {base_time:.1f}s")
            score += 25

    return {"score": score, "reasons": reasons}


@register_tool
def fuzz_request_parameter(
    request_id: str,
    parameter: str,
    payloads: list[str],
    parameter_location: str = "query",
    max_parallel: int = 1,
    interest_threshold: int = 10,
) -> dict[str, Any]:
    """Replay a captured request many times, swapping a parameter with each payload.

    Reuses `repeat_request` internally — looks up the original captured request,
    then for each payload in the list makes a modified copy with the parameter
    overridden, sends it, and scores the response against the unmodified baseline.

    parameter_location:
    - "query": URL query string parameter
    - "body":  form/JSON body parameter
    - "header": HTTP header
    - "cookie": cookie value
    - "path":   substitute into URL path segment (requires parameter to literally
                appear in the path)

    Returns per-payload rows sorted by interest score. Agent should read the
    top 3-5 and use repeat_request or view_request to inspect the full response
    for the interesting ones.
    """
    from .proxy_manager import get_proxy_manager

    try:
        manager = get_proxy_manager()

        # Baseline — replay unmodified to get reference metrics
        baseline_resp = manager.repeat_request(request_id, modifications={})
        if "error" in baseline_resp:
            return {
                "success": False,
                "error": f"Baseline replay failed: {baseline_resp['error']}",
            }

        baseline_info = {
            "status_code": baseline_resp.get("status_code") or baseline_resp.get("status"),
            "response_size": baseline_resp.get("response_size")
            or len(str(baseline_resp.get("body") or baseline_resp.get("response_body") or "")),
            "response_time": baseline_resp.get("response_time") or 0,
        }

        rows: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for i, payload in enumerate(payloads[:200]):  # hard cap 200
            if parameter_location == "query":
                mods = {"query_params": {parameter: payload}}
            elif parameter_location == "body":
                mods = {"body_params": {parameter: payload}}
            elif parameter_location == "header":
                mods = {"headers": {parameter: payload}}
            elif parameter_location == "cookie":
                mods = {"cookies": {parameter: payload}}
            elif parameter_location == "path":
                mods = {"path_substitutions": {parameter: payload}}
            else:
                return {
                    "success": False,
                    "error": f"Unknown parameter_location: {parameter_location}",
                }

            try:
                probe = manager.repeat_request(request_id, modifications=mods)
            except Exception as e:  # noqa: BLE001
                errors.append({"payload": payload[:80], "error": str(e)[:200]})
                continue

            if "error" in probe:
                errors.append({"payload": payload[:80], "error": probe["error"][:200]})
                continue

            probe_info = {
                "status_code": probe.get("status_code") or probe.get("status"),
                "response_size": probe.get("response_size")
                or len(str(probe.get("body") or probe.get("response_body") or "")),
                "response_time": probe.get("response_time") or 0,
            }
            interest = _score_response_interest(baseline_info, probe_info)

            if interest["score"] >= interest_threshold:
                rows.append(
                    {
                        "payload": payload[:200],
                        "status_code": probe_info["status_code"],
                        "response_size": probe_info["response_size"],
                        "response_time": probe_info["response_time"],
                        "interest_score": interest["score"],
                        "reasons": interest["reasons"],
                        "new_request_id": probe.get("new_request_id"),
                    }
                )

        rows.sort(key=lambda r: -r["interest_score"])

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"fuzz_request_parameter failed: {e!s}"}
    else:
        return {
            "success": True,
            "request_id": request_id,
            "parameter": parameter,
            "parameter_location": parameter_location,
            "payloads_sent": min(len(payloads), 200),
            "baseline": baseline_info,
            "interesting_count": len(rows),
            "interesting": rows[:50],
            "errors": errors[:10],
        }


@register_tool
def diff_responses(
    request_id_a: str,
    request_id_b: str,
    max_diff_lines: int = 100,
    ignore_headers: list[str] | None = None,
) -> dict[str, Any]:
    """Diff two captured HTTP responses (or response bodies) side-by-side.

    Handy after fuzz_request_parameter when one payload had an interesting
    delta — this zooms in and shows exactly which bytes/lines differ. Also
    useful for comparing authenticated vs unauthenticated responses, user-A
    vs user-B, or WAF-bypass variant vs baseline.

    Strips noise headers by default (Date, X-Request-Id, Set-Cookie, Server-Timing,
    X-Trace-Id) unless you override via ignore_headers.
    """
    from .proxy_manager import get_proxy_manager

    ignore_headers = ignore_headers or [
        "Date",
        "X-Request-Id",
        "X-Trace-Id",
        "Server-Timing",
        "Set-Cookie",
        "ETag",
        "Last-Modified",
    ]
    ignore_set = {h.lower() for h in ignore_headers}

    try:
        manager = get_proxy_manager()

        a = manager.view_request(request_id_a, "response")
        if "error" in a:
            return {"success": False, "error": f"A view failed: {a['error']}"}
        b = manager.view_request(request_id_b, "response")
        if "error" in b:
            return {"success": False, "error": f"B view failed: {b['error']}"}

        def _strip(raw: str) -> tuple[list[str], list[str]]:
            lines = raw.splitlines()
            header_lines: list[str] = []
            body_start = len(lines)
            for i, line in enumerate(lines):
                if not line.strip():
                    body_start = i + 1
                    break
                if ":" in line:
                    name = line.split(":", 1)[0].strip().lower()
                    if name not in ignore_set:
                        header_lines.append(line)
                else:
                    header_lines.append(line)
            body_lines = lines[body_start:]
            return header_lines, body_lines

        a_headers, a_body = _strip(a.get("content", ""))
        b_headers, b_body = _strip(b.get("content", ""))

        header_diff = list(
            difflib.unified_diff(a_headers, b_headers, lineterm="", n=1)
        )[:max_diff_lines]
        body_diff = list(
            difflib.unified_diff(a_body, b_body, lineterm="", n=2)
        )[:max_diff_lines]

        identical = not header_diff and not body_diff
        size_delta = len("\n".join(b_body)) - len("\n".join(a_body))

    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"diff_responses failed: {e!s}"}
    else:
        return {
            "success": True,
            "request_id_a": request_id_a,
            "request_id_b": request_id_b,
            "identical": identical,
            "body_size_delta_bytes": size_delta,
            "header_diff": header_diff,
            "body_diff": body_diff,
            "ignored_headers": ignore_headers,
        }
