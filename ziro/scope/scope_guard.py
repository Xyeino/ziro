"""Scope Guard — enforces target boundaries during scans.

Prevents the agent from making requests to domains/IPs outside the
explicitly allowed scope. This is critical for professional pentesting
where going out of scope can have legal consequences.
"""

import ipaddress
import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_global_scope_guard: "ScopeGuard | None" = None


def get_scope_guard() -> "ScopeGuard | None":
    return _global_scope_guard


def set_scope_guard(guard: "ScopeGuard | None") -> None:
    global _global_scope_guard  # noqa: PLW0603
    _global_scope_guard = guard


class ScopeGuard:
    """Enforces allowed targets for scan operations.

    Initialized from scan_config targets. Supports:
    - Exact domains (example.com)
    - Wildcard subdomains (*.example.com)
    - IP addresses (10.0.0.1)
    - CIDR ranges (10.0.0.0/24)
    - Ports (example.com:8080)
    """

    def __init__(self, targets: list[dict[str, Any]] | None = None):
        self._allowed_domains: set[str] = set()
        self._allowed_wildcard_domains: set[str] = set()  # stored without "*."
        self._allowed_ips: set[str] = set()
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._allowed_ports: dict[str, set[int]] = {}  # host -> {ports}
        self._violations: list[dict[str, str]] = []
        self._enabled = True

        if targets:
            self._parse_targets(targets)

    @property
    def enabled(self) -> bool:
        return self._enabled and (
            bool(self._allowed_domains)
            or bool(self._allowed_wildcard_domains)
            or bool(self._allowed_ips)
            or bool(self._allowed_networks)
        )

    @property
    def violations(self) -> list[dict[str, str]]:
        return list(self._violations)

    def disable(self) -> None:
        """Disable scope enforcement (for CTF/lab environments)."""
        self._enabled = False
        logger.warning("Scope guard disabled — all targets are allowed")

    def _parse_targets(self, targets: list[dict[str, Any]]) -> None:
        for target in targets:
            details = target.get("details", {})

            # Web application URLs
            url = details.get("target_url", "")
            if url:
                self._add_url(url)

            # Repositories (allow the repo host)
            repo = details.get("target_repo", "")
            if repo:
                self._add_url(repo)

            # IP addresses
            ip = details.get("target_ip", "")
            if ip:
                self._add_ip_or_cidr(ip)

            # Local code paths don't add network targets
            # but we don't restrict them either

        logger.info(
            "Scope guard initialized: %d domains, %d wildcards, %d IPs, %d networks",
            len(self._allowed_domains),
            len(self._allowed_wildcard_domains),
            len(self._allowed_ips),
            len(self._allowed_networks),
        )

    def _add_url(self, url: str) -> None:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port

            if not host:
                return

            if self._is_ip(host):
                self._allowed_ips.add(host)
            else:
                self._allowed_domains.add(host.lower())

            if port:
                self._allowed_ports.setdefault(host.lower(), set()).add(port)
        except (ValueError, AttributeError):
            pass

    def _add_ip_or_cidr(self, value: str) -> None:
        value = value.strip()
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=False)
                self._allowed_networks.append(network)
            else:
                ipaddress.ip_address(value)
                self._allowed_ips.add(value)
        except ValueError:
            # Maybe it's a hostname
            self._allowed_domains.add(value.lower())

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def add_target(self, target: str) -> None:
        """Manually add a target to the allowed scope."""
        target = target.strip()
        if target.startswith("*."):
            self._allowed_wildcard_domains.add(target[2:].lower())
        elif self._is_ip(target):
            self._allowed_ips.add(target)
        elif "/" in target and self._looks_like_cidr(target):
            try:
                network = ipaddress.ip_network(target, strict=False)
                self._allowed_networks.append(network)
            except ValueError:
                self._allowed_domains.add(target.lower())
        elif "://" in target:
            self._add_url(target)
        else:
            self._allowed_domains.add(target.lower())

    @staticmethod
    def _looks_like_cidr(value: str) -> bool:
        return bool(re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", value))

    def is_in_scope(self, target: str) -> bool:
        """Check if a URL, domain, or IP is within the allowed scope.

        Returns True if in scope, False if out of scope.
        Always returns True if scope guard is disabled or has no targets.
        """
        if not self.enabled:
            return True

        # Extract host from URL or use as-is
        host = self._extract_host(target)
        if not host:
            return True  # Can't determine host, allow by default

        host_lower = host.lower()

        # Check exact domain match
        if host_lower in self._allowed_domains:
            return True

        # Check wildcard domain match (*.example.com matches sub.example.com)
        for wildcard in self._allowed_wildcard_domains:
            if host_lower == wildcard or host_lower.endswith("." + wildcard):
                return True

        # Check parent domain match (sub.example.com is in scope if example.com is)
        parts = host_lower.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._allowed_domains:
                return True

        # Check IP match
        if self._is_ip(host):
            if host in self._allowed_ips:
                return True
            try:
                addr = ipaddress.ip_address(host)
                for network in self._allowed_networks:
                    if addr in network:
                        return True
            except ValueError:
                pass

        # Localhost is always allowed (for local testing)
        if host_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True

        return False

    def check_and_log(self, target: str, tool_name: str = "") -> bool:
        """Check scope and log a violation if out of scope.

        Returns True if in scope, False if out of scope.
        """
        if self.is_in_scope(target):
            return True

        host = self._extract_host(target)
        violation = {
            "target": target,
            "host": host or target,
            "tool": tool_name,
        }
        self._violations.append(violation)

        logger.warning(
            "SCOPE VIOLATION: %s attempted to reach %s (tool: %s)",
            "Agent",
            target,
            tool_name or "unknown",
        )

        return False

    @staticmethod
    def _extract_host(target: str) -> str | None:
        """Extract hostname from URL or return as-is if it's a host/IP."""
        target = target.strip()

        # URL
        if "://" in target:
            try:
                parsed = urlparse(target)
                return parsed.hostname
            except (ValueError, AttributeError):
                return None

        # host:port
        if ":" in target and not target.startswith("["):
            host_part = target.rsplit(":", 1)[0]
            return host_part

        return target if target else None

    def summary(self) -> dict[str, Any]:
        """Return a summary of the scope configuration."""
        return {
            "enabled": self.enabled,
            "allowed_domains": sorted(self._allowed_domains),
            "allowed_wildcards": sorted(f"*.{d}" for d in self._allowed_wildcard_domains),
            "allowed_ips": sorted(self._allowed_ips),
            "allowed_networks": [str(n) for n in self._allowed_networks],
            "violation_count": len(self._violations),
        }
