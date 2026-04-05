"""
Ziro Telegram Bot — control panel via Telegram with inline keyboards.

Usage:
  1. Create bot via @BotFather, get token
  2. Add token to Settings → Telegram Bot Token
  3. Add your chat ID to Settings → Telegram Chat ID
  4. Bot starts automatically with the panel

Commands:
  /start — Main menu
  /scan <target> — Start new scan
  /status — Current scan status
  /vulns — List vulnerabilities
  /stop — Stop scan
  /report — Get report
  /ask <message> — Talk to AI agent
"""

import asyncio
import json
import logging
import threading
from typing import Any

import requests

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org/bot{token}"


class ZiroTelegramBot:
    def __init__(self, bot_token: str, chat_id: str, panel_port: int = 8420):
        self.token = bot_token
        self.chat_id = chat_id
        self.api = TELEGRAM_API.format(token=bot_token)
        self.panel_url = f"http://127.0.0.1:{panel_port}/api"
        self._running = False
        self._offset = 0
        self._thread: threading.Thread | None = None
        self._notified_vulns: set[str] = set()

    def start(self) -> None:
        """Start bot polling in background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("Telegram bot started (chat_id=%s)", self.chat_id)

    def stop(self) -> None:
        self._running = False

    def _poll_loop(self) -> None:
        """Long-polling loop for Telegram updates."""
        while self._running:
            try:
                resp = requests.get(
                    f"{self.api}/getUpdates",
                    params={"offset": self._offset, "timeout": 10},
                    timeout=15,
                )
                if resp.ok:
                    data = resp.json()
                    for update in data.get("result", []):
                        self._offset = update["update_id"] + 1
                        self._handle_update(update)

                # Check for new vulns to notify
                self._check_new_vulns()
            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                logger.debug("Telegram poll error: %s", e)
                import time
                time.sleep(5)

    def _handle_update(self, update: dict[str, Any]) -> None:
        """Route incoming messages and callbacks."""
        # Callback query (inline button press)
        if "callback_query" in update:
            cb = update["callback_query"]
            cb_data = cb.get("data", "")
            chat_id = cb["message"]["chat"]["id"]
            msg_id = cb["message"]["message_id"]

            # Answer callback to remove loading state
            requests.post(f"{self.api}/answerCallbackQuery", json={"callback_query_id": cb["id"]})

            if cb_data == "status":
                self._cmd_status(chat_id)
            elif cb_data == "vulns":
                self._cmd_vulns(chat_id)
            elif cb_data == "stop":
                self._cmd_stop(chat_id)
            elif cb_data == "report":
                self._cmd_report(chat_id)
            elif cb_data == "new_scan":
                self._send(chat_id, "Send target domain:\n\n`/scan example.com`", parse_mode="Markdown")
            elif cb_data == "ask_agent":
                self._send(chat_id, "Send message to agent:\n\n`/ask your question here`", parse_mode="Markdown")
            elif cb_data == "mode_standard":
                self._start_scan_with_mode(chat_id, "standard")
            elif cb_data == "mode_deep":
                self._start_scan_with_mode(chat_id, "full")
            elif cb_data.startswith("retest:"):
                vuln_title = cb_data[7:]
                self._cmd_retest(chat_id, vuln_title)
            elif cb_data.startswith("vuln_detail:"):
                idx = int(cb_data[12:])
                self._cmd_vuln_detail(chat_id, idx)
            return

        # Text message
        msg = update.get("message", {})
        text = msg.get("text", "").strip()
        chat_id = msg.get("chat", {}).get("id")
        if not text or not chat_id:
            return

        if text == "/start":
            self._cmd_start(chat_id)
        elif text.startswith("/scan "):
            target = text[6:].strip()
            self._pending_target = target
            self._send(chat_id, f"🎯 Target: `{target}`\n\nSelect scan mode:", parse_mode="Markdown",
                       keyboard=[[
                           {"text": "🔍 Standard", "callback_data": "mode_standard"},
                           {"text": "💀 Deep + Exploit", "callback_data": "mode_deep"},
                       ]])
        elif text == "/status":
            self._cmd_status(chat_id)
        elif text == "/vulns":
            self._cmd_vulns(chat_id)
        elif text == "/stop":
            self._cmd_stop(chat_id)
        elif text == "/report":
            self._cmd_report(chat_id)
        elif text.startswith("/ask "):
            message = text[5:].strip()
            self._cmd_ask(chat_id, message)
        elif text == "/help":
            self._cmd_start(chat_id)
        else:
            # Treat as message to agent
            if text.startswith("/"):
                self._send(chat_id, "Unknown command. Use /help")
            else:
                self._cmd_ask(chat_id, text)

    # --- Commands ---

    def _cmd_start(self, chat_id: int) -> None:
        self._send(
            chat_id,
            "⚡ <b>Ziro Security Scanner</b>\n\n"
            "AI-powered penetration testing from Telegram.\n\n"
            "Quick start: <code>/scan example.com</code>",
            parse_mode="HTML",
            keyboard=[
                [{"text": "➕ New Scan", "callback_data": "new_scan"}, {"text": "📊 Status", "callback_data": "status"}],
                [{"text": "🔴 Vulnerabilities", "callback_data": "vulns"}, {"text": "📋 Report", "callback_data": "report"}],
                [{"text": "💬 Ask Agent", "callback_data": "ask_agent"}, {"text": "⏹ Stop", "callback_data": "stop"}],
            ],
        )

    def _cmd_status(self, chat_id: int) -> None:
        try:
            status = requests.get(f"{self.panel_url}/status", timeout=5).json()
            agents = requests.get(f"{self.panel_url}/agents", timeout=5).json()
            stats = requests.get(f"{self.panel_url}/llm-stats", timeout=5).json()

            agent_list = agents.get("agents", [])
            running = sum(1 for a in agent_list if a.get("status") == "running")
            total = len(agent_list)
            tokens = stats.get("total_tokens", 0)
            cost = stats.get("total", {}).get("cost", 0)

            sc = status.get("severity_counts", {})
            target = status.get("targets", [{}])[0].get("original", "—") if status.get("targets") else "—"

            text = (
                f"📊 <b>Scan Status</b>\n\n"
                f"🎯 Target: <code>{target}</code>\n"
                f"📍 Status: <b>{status.get('status', '?')}</b>\n\n"
                f"🤖 Agents: {running} active / {total} total\n"
                f"🔴 Critical: {sc.get('critical', 0)} | 🟠 High: {sc.get('high', 0)}\n"
                f"🟡 Medium: {sc.get('medium', 0)} | 🔵 Low: {sc.get('low', 0)}\n\n"
                f"📝 Tokens: {tokens:,} | 💰 Cost: ${cost:.2f}"
            )
            self._send(chat_id, text, parse_mode="HTML", keyboard=[
                [{"text": "🔄 Refresh", "callback_data": "status"}, {"text": "🔴 Vulns", "callback_data": "vulns"}],
                [{"text": "📋 Report", "callback_data": "report"}, {"text": "🏠 Menu", "callback_data": "start"}],
            ])
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _cmd_vulns(self, chat_id: int) -> None:
        try:
            vulns = requests.get(f"{self.panel_url}/vulnerabilities", timeout=5).json()
            if not vulns:
                self._send(chat_id, "No vulnerabilities found yet.", keyboard=[
                    [{"text": "🔄 Refresh", "callback_data": "vulns"}, {"text": "🏠 Menu", "callback_data": "start"}],
                ])
                return

            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            lines = [f"<b>🔍 Vulnerabilities ({len(vulns)})</b>\n"]
            buttons = []

            for i, v in enumerate(vulns[:10]):
                sev = v.get("severity", "info").lower()
                emoji = sev_emoji.get(sev, "⚪")
                target = v.get("target", v.get("endpoint", ""))
                lines.append(f"{emoji} <b>{v.get('title', '?')}</b>")
                if target:
                    lines.append(f"   <code>{target[:60]}</code>")
                buttons.append([{"text": f"#{i+1} Details", "callback_data": f"vuln_detail:{i}"}])

            if len(vulns) > 10:
                lines.append(f"\n... and {len(vulns) - 10} more")

            buttons.append([{"text": "🔄 Refresh", "callback_data": "vulns"}, {"text": "🏠 Menu", "callback_data": "start"}])
            self._send(chat_id, "\n".join(lines), parse_mode="HTML", keyboard=buttons)
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _cmd_vuln_detail(self, chat_id: int, idx: int) -> None:
        try:
            vulns = requests.get(f"{self.panel_url}/vulnerabilities", timeout=5).json()
            if idx >= len(vulns):
                self._send(chat_id, "Vulnerability not found")
                return

            v = vulns[idx]
            sev = v.get("severity", "info").upper()
            text = f"<b>[{sev}] {v.get('title', '?')}</b>\n\n"
            if v.get("target"):
                text += f"🎯 <code>{v['target']}</code>\n"
            if v.get("cvss"):
                text += f"CVSS: {v['cvss']}"
            if v.get("cve"):
                text += f" | CVE: {v['cve']}"
            if v.get("cwe"):
                text += f" | CWE: {v['cwe']}"
            text += "\n\n"
            if v.get("description"):
                text += f"{v['description'][:500]}\n\n"
            if v.get("poc_script_code"):
                text += f"<b>PoC:</b>\n<pre>{v['poc_script_code'][:800]}</pre>\n\n"
            if v.get("remediation_steps"):
                text += f"✅ <b>Fix:</b> {v['remediation_steps'][:300]}"

            self._send(chat_id, text, parse_mode="HTML", keyboard=[
                [{"text": f"🔄 Retest", "callback_data": f"retest:{v.get('title', '')[:50]}"}],
                [{"text": "⬅ Back", "callback_data": "vulns"}, {"text": "🏠 Menu", "callback_data": "start"}],
            ])
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _cmd_stop(self, chat_id: int) -> None:
        try:
            requests.delete(f"{self.panel_url}/scans", timeout=5)
            self._send(chat_id, "⏹ Scan stopped.", keyboard=[
                [{"text": "🏠 Menu", "callback_data": "start"}],
            ])
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _cmd_report(self, chat_id: int) -> None:
        try:
            vulns = requests.get(f"{self.panel_url}/vulnerabilities", timeout=5).json()
            status = requests.get(f"{self.panel_url}/status", timeout=5).json()
            target = status.get("targets", [{}])[0].get("original", "?") if status.get("targets") else "?"
            sc = status.get("severity_counts", {})

            text = (
                f"📋 <b>Ziro Report: {target}</b>\n\n"
                f"🔴 Critical: {sc.get('critical', 0)}\n"
                f"🟠 High: {sc.get('high', 0)}\n"
                f"🟡 Medium: {sc.get('medium', 0)}\n"
                f"🔵 Low: {sc.get('low', 0)}\n"
                f"Total: {len(vulns)} vulnerabilities\n\n"
            )

            for v in vulns[:5]:
                sev = v.get("severity", "?").upper()
                text += f"• [{sev}] {v.get('title', '?')}\n"

            if len(vulns) > 5:
                text += f"\n... +{len(vulns) - 5} more\n"

            text += f"\n📄 Full report: web panel → Export"
            self._send(chat_id, text, parse_mode="HTML", keyboard=[
                [{"text": "🔴 All Vulns", "callback_data": "vulns"}, {"text": "🏠 Menu", "callback_data": "start"}],
            ])
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _cmd_ask(self, chat_id: int, message: str) -> None:
        try:
            resp = requests.post(
                f"{self.panel_url}/agent-message",
                json={"message": message, "agent_id": ""},
                timeout=5,
            )
            if resp.ok:
                self._send(chat_id, f"💬 Sent to agent: <i>{message[:200]}</i>", parse_mode="HTML")
            else:
                self._send(chat_id, f"❌ Agent not available: {resp.text[:100]}")
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _cmd_retest(self, chat_id: int, vuln_title: str) -> None:
        try:
            requests.post(
                f"{self.panel_url}/agent-message",
                json={"message": f'Retest vulnerability: "{vuln_title}". Check if it is still exploitable.', "agent_id": ""},
                timeout=5,
            )
            self._send(chat_id, f"🔄 Retesting: <i>{vuln_title}</i>", parse_mode="HTML")
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")

    def _start_scan_with_mode(self, chat_id: int, mode: str) -> None:
        target = getattr(self, "_pending_target", "")
        if not target:
            self._send(chat_id, "No target set. Use /scan <domain>")
            return

        try:
            resp = requests.post(
                f"{self.panel_url}/scans",
                json={
                    "target": target,
                    "scan_mode": "deep" if mode == "full" else "standard",
                    "red_team": mode == "full",
                    "zeroday": mode == "full",
                },
                timeout=10,
            )
            if resp.ok:
                data = resp.json()
                self._send(
                    chat_id,
                    f"✅ Scan started!\n\n🎯 {target}\n🔧 Mode: {'Deep + Exploit' if mode == 'full' else 'Standard'}\n📛 Run: {data.get('run_name', '?')}",
                    keyboard=[
                        [{"text": "📊 Status", "callback_data": "status"}, {"text": "🔴 Vulns", "callback_data": "vulns"}],
                    ],
                )
            else:
                self._send(chat_id, f"❌ Failed: {resp.text[:200]}")
        except Exception as e:
            self._send(chat_id, f"❌ Error: {e}")
        self._pending_target = ""

    # --- Auto-notifications ---

    def _check_new_vulns(self) -> None:
        """Send notification for new Critical/High vulnerabilities."""
        try:
            vulns = requests.get(f"{self.panel_url}/vulnerabilities", timeout=3).json()
            for v in vulns:
                sev = v.get("severity", "").lower()
                title = v.get("title", "")
                key = f"{sev}:{title}"
                if sev in ("critical", "high") and key not in self._notified_vulns:
                    self._notified_vulns.add(key)
                    emoji = "🔴" if sev == "critical" else "🟠"
                    target = v.get("target", v.get("endpoint", ""))
                    text = f"{emoji} <b>New {sev.upper()} vulnerability found!</b>\n\n<b>{title}</b>"
                    if target:
                        text += f"\n<code>{target}</code>"
                    self._send(
                        int(self.chat_id), text, parse_mode="HTML",
                        keyboard=[[{"text": "View Details", "callback_data": "vulns"}]],
                    )
        except Exception:
            pass

    # --- Helpers ---

    def _send(self, chat_id: int, text: str, parse_mode: str = "HTML",
              keyboard: list[list[dict[str, str]]] | None = None) -> None:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
        }
        if keyboard:
            payload["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
        try:
            requests.post(f"{self.api}/sendMessage", json=payload, timeout=10)
        except Exception as e:
            logger.debug("Telegram send error: %s", e)


# --- Bot lifecycle ---

_bot_instance: ZiroTelegramBot | None = None


def start_telegram_bot(panel_port: int = 8420) -> None:
    """Start Telegram bot if credentials are configured."""
    global _bot_instance
    try:
        from ziro.panel.server import get_api_key

        bot_token = get_api_key("telegram_bot")
        chat_id = get_api_key("telegram_chat")

        if bot_token and chat_id:
            _bot_instance = ZiroTelegramBot(bot_token, chat_id, panel_port)
            _bot_instance.start()
        else:
            logger.debug("Telegram bot not configured (missing token or chat_id)")
    except Exception as e:
        logger.debug("Telegram bot start error: %s", e)


def stop_telegram_bot() -> None:
    global _bot_instance
    if _bot_instance:
        _bot_instance.stop()
        _bot_instance = None
