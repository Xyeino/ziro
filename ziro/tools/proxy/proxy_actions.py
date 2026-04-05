from typing import Any, Literal

from ziro.tools.registry import register_tool


RequestPart = Literal["request", "response"]


@register_tool
def list_requests(
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 50,
    sort_by: Literal[
        "timestamp",
        "host",
        "method",
        "path",
        "status_code",
        "response_time",
        "response_size",
        "source",
    ] = "timestamp",
    sort_order: Literal["asc", "desc"] = "desc",
    scope_id: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_requests(
        httpql_filter, start_page, end_page, page_size, sort_by, sort_order, scope_id
    )


@register_tool
def view_request(
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_request(request_id, part, search_pattern, page, page_size)


@register_tool
def send_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if headers is None:
        headers = {}
    manager = get_proxy_manager()
    return manager.send_simple_request(method, url, headers, body, timeout)


@register_tool
def repeat_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if modifications is None:
        modifications = {}
    manager = get_proxy_manager()
    return manager.repeat_request(request_id, modifications)


@register_tool
def scope_rules(
    action: Literal["get", "list", "create", "update", "delete"],
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.scope_rules(action, allowlist, denylist, scope_id, scope_name)


@register_tool
def list_sitemap(
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: Literal["DIRECT", "ALL"] = "DIRECT",
    page: int = 1,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_sitemap(scope_id, parent_id, depth, page)


@register_tool
def view_sitemap_entry(
    entry_id: str,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_sitemap_entry(entry_id)


@register_tool
def search_burp_proxy_history(
    search: str = "",
    host: str = "",
    method: str = "",
    status_min: int = 0,
    status_max: int = 999,
    hide_assets: bool = False,
    page_size: int = 25,
) -> dict[str, Any]:
    """Search captured HTTP proxy traffic (Caido). Convenience wrapper matching common proxy search patterns.

    Use this to find specific requests in the proxy history — login endpoints,
    API calls, interesting parameters, authentication tokens, etc.
    """
    from .proxy_manager import get_proxy_manager

    # Build HTTPQL filter from human-friendly params
    filters: list[str] = []
    if host:
        filters.append(f'req.host.regex:"{host}"')
    if method:
        filters.append(f'req.method.regex:"{method.upper()}"')
    if search:
        filters.append(f'req.raw.regex:"{search}"')
    if status_min > 0:
        filters.append(f"resp.code.gte:{status_min}")
    if status_max < 999:
        filters.append(f"resp.code.lte:{status_max}")
    if hide_assets:
        # Exclude common static assets
        filters.append('req.ext.ne:"css"')
        filters.append('req.ext.ne:"js"')
        filters.append('req.ext.ne:"png"')
        filters.append('req.ext.ne:"jpg"')
        filters.append('req.ext.ne:"gif"')
        filters.append('req.ext.ne:"svg"')
        filters.append('req.ext.ne:"woff"')
        filters.append('req.ext.ne:"woff2"')

    httpql = " AND ".join(filters) if filters else None

    manager = get_proxy_manager()
    return manager.list_requests(
        httpql_filter=httpql,
        start_page=1,
        end_page=1,
        page_size=page_size,
        sort_by="timestamp",
        sort_order="desc",
    )
