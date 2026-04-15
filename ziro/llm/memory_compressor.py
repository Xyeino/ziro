import logging
import os
from typing import Any

import litellm

from ziro.config.config import Config, resolve_llm_config


logger = logging.getLogger(__name__)


# Default ceiling used when the model's context window cannot be detected.
# Will be overridden by the model's actual context size if available.
DEFAULT_MAX_TOTAL_TOKENS = 100_000
MIN_RECENT_MESSAGES = 15
# Compress when the conversation reaches this fraction of the model's context window.
# 0.7 means: with a 200K context model, compression starts at 140K; with a 2M
# context model, at 1.4M. Previously a hard 90K cap meant grok-4 (2M context)
# wasted compression cycles starting at 4.5% of available context.
COMPRESSION_THRESHOLD_RATIO = 0.7
# How many old messages to bundle per summarization LLM call. Larger chunks
# mean fewer LLM calls during compression — each summary is itself an LLM
# request, so 5 -> 20 cuts compression overhead by 4x.
DEFAULT_SUMMARY_CHUNK_SIZE = 20

# Token-count cache on message dicts. Memory compression re-counts the same
# old messages every time it runs — caching on the message itself avoids
# repeated tiktoken work during long scans.
_TOKEN_CACHE_KEY = "_ziro_token_count"

# Hardcoded context windows for models litellm.get_model_info() does not
# know about yet. Used as a fallback before falling back further to the
# DEFAULT_MAX_TOTAL_TOKENS conservative cap.
_KNOWN_CONTEXT_WINDOWS: dict[str, int] = {
    # xAI Grok family
    "grok-4-1-fast-reasoning": 2_000_000,
    "grok-4-1-fast-non-reasoning": 2_000_000,
    "grok-4-fast-reasoning": 2_000_000,
    "grok-4-fast-non-reasoning": 2_000_000,
    "grok-4-0709": 256_000,
    "grok-4": 256_000,
    "grok-3": 131_000,
    "grok-3-mini": 131_000,
    "grok-code-fast-1": 256_000,
    # OpenAI
    "gpt-5.4": 1_000_000,
    "gpt-5.2": 400_000,
    "gpt-5.1": 400_000,
    # Google Gemini
    "gemini-3-pro-preview": 2_000_000,
    "gemini-3-flash-preview": 1_000_000,
    # Z.ai GLM
    "glm-5": 1_000_000,
    "glm-4.7": 200_000,
}

SUMMARY_PROMPT_TEMPLATE = """You are an agent performing context
condensation for a security agent. Your job is to compress scan data while preserving
ALL operationally critical information for continuing the security assessment.

CRITICAL ELEMENTS TO PRESERVE:
- Discovered vulnerabilities and potential attack vectors
- Scan results and tool outputs (compressed but maintaining key findings)
- Access credentials, tokens, or authentication details found
- System architecture insights and potential weak points
- Progress made in the assessment
- Failed attempts and dead ends (to avoid duplication)
- Any decisions made about the testing approach

COMPRESSION GUIDELINES:
- Preserve exact technical details (URLs, paths, parameters, payloads)
- Summarize verbose tool outputs while keeping critical findings
- Maintain version numbers, specific technologies identified
- Keep exact error messages that might indicate vulnerabilities
- Compress repetitive or similar findings into consolidated form

Remember: Another security agent will use this summary to continue the assessment.
They must be able to pick up exactly where you left off without losing any
operational advantage or context needed to find vulnerabilities.

CONVERSATION SEGMENT TO SUMMARIZE:
{conversation}

Provide a technically precise summary that preserves all operational security context while
keeping the summary concise and to the point."""


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.exception("Failed to count tokens")
        return len(text) // 4  # Rough estimate


def _get_message_tokens(msg: dict[str, Any], model: str) -> int:
    """Return cached token count for a message, computing it once if missing.

    The cache lives on the message dict itself, so subsequent compression
    passes do not re-tokenize old, immutable messages. Cache is invalidated
    when content changes (caller must clear _ziro_token_count then).
    """
    cached = msg.get(_TOKEN_CACHE_KEY)
    if isinstance(cached, int):
        return cached

    content = msg.get("content", "")
    total = 0
    if isinstance(content, str):
        total = _count_tokens(content, model)
    elif isinstance(content, list):
        total = sum(
            _count_tokens(item.get("text", ""), model)
            for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        )

    msg[_TOKEN_CACHE_KEY] = total
    return total


def _resolve_max_tokens(model: str) -> int:
    """Resolve the compression threshold for the given model.

    Order of precedence:
    1. ZIRO_MAX_CONTEXT_TOKENS env var (explicit override)
    2. litellm.get_model_info() max_input_tokens * COMPRESSION_THRESHOLD_RATIO
    3. DEFAULT_MAX_TOTAL_TOKENS fallback for unknown models
    """
    override = os.getenv("ZIRO_MAX_CONTEXT_TOKENS", "").strip()
    if override.isdigit():
        return int(override)

    try:
        info = litellm.get_model_info(model=model)
        max_input = info.get("max_input_tokens") or info.get("max_tokens")
        if isinstance(max_input, int) and max_input > 0:
            return int(max_input * COMPRESSION_THRESHOLD_RATIO)
    except Exception:  # noqa: BLE001
        pass

    # Fallback: hardcoded windows for models litellm hasn't catalogued yet
    bare = model.split("/")[-1].lower()
    for known, ctx in _KNOWN_CONTEXT_WINDOWS.items():
        if known in bare or bare in known:
            return int(ctx * COMPRESSION_THRESHOLD_RATIO)

    return DEFAULT_MAX_TOTAL_TOKENS


def _extract_message_text(msg: dict[str, Any]) -> str:
    content = msg.get("content", "")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "image_url":
                    parts.append("[IMAGE]")
        return " ".join(parts)

    return str(content)


def _summarize_messages(
    messages: list[dict[str, Any]],
    model: str,
    timeout: int = 30,
) -> dict[str, Any]:
    if not messages:
        empty_summary = "<context_summary message_count='0'>{text}</context_summary>"
        return {
            "role": "user",
            "content": empty_summary.format(text="No messages to summarize"),
        }

    formatted = []
    for msg in messages:
        role = msg.get("role", "unknown")
        text = _extract_message_text(msg)
        formatted.append(f"{role}: {text}")

    conversation = "\n".join(formatted)
    prompt = SUMMARY_PROMPT_TEMPLATE.format(conversation=conversation)

    _, api_key, api_base = resolve_llm_config()

    try:
        completion_args: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": timeout,
        }
        if api_key:
            completion_args["api_key"] = api_key
        if api_base:
            completion_args["api_base"] = api_base

        response = litellm.completion(**completion_args)
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            logger.warning("LLM returned empty summary, keeping original %d messages", len(messages))
            return {
                "role": "user",
                "content": "<context_summary message_count='{count}'>{text}</context_summary>".format(
                    count=len(messages), text="\n".join(formatted)
                ),
            }
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "user",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception:
        logger.exception("Failed to summarize messages, keeping original %d messages", len(messages))
        # Return a concatenation of original messages instead of just messages[0]
        fallback_text = "\n".join(formatted)
        return {
            "role": "user",
            "content": "<context_summary message_count='{count}'>{text}</context_summary>".format(
                count=len(messages), text=fallback_text
            ),
        }


def _handle_images(messages: list[dict[str, Any]], max_images: int) -> None:
    image_count = 0
    for msg in reversed(messages):
        content = msg.get("content", [])
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "image_url":
                    if image_count >= max_images:
                        item.update(
                            {
                                "type": "text",
                                "text": "[Previously attached image removed to preserve context]",
                            }
                        )
                    else:
                        image_count += 1


class MemoryCompressor:
    def __init__(
        self,
        max_images: int = 3,
        model_name: str | None = None,
        timeout: int | None = None,
    ):
        self.max_images = max_images
        self.model_name = model_name or Config.get("ziro_llm")
        self.timeout = timeout or int(Config.get("ziro_memory_compressor_timeout") or "120")

        if not self.model_name:
            raise ValueError("ZIRO_LLM environment variable must be set and not empty")

    def compress_history(
        self,
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compress conversation history to stay within token limits.

        Strategy:
        1. Handle image limits first
        2. Keep all system messages
        3. Keep minimum recent messages
        4. Summarize older messages when total tokens exceed limit

        The compression preserves:
        - All system messages unchanged
        - Most recent messages intact
        - Critical security context in summaries
        - Recent images for visual context
        - Technical details and findings
        """
        if not messages:
            return messages

        _handle_images(messages, self.max_images)

        system_msgs = []
        regular_msgs = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msgs.append(msg)
            else:
                regular_msgs.append(msg)

        recent_msgs = regular_msgs[-MIN_RECENT_MESSAGES:]
        old_msgs = regular_msgs[:-MIN_RECENT_MESSAGES]

        # Type assertion since we ensure model_name is not None in __init__
        model_name: str = self.model_name  # type: ignore[assignment]

        total_tokens = sum(
            _get_message_tokens(msg, model_name) for msg in system_msgs + regular_msgs
        )

        max_total = _resolve_max_tokens(model_name)
        if total_tokens <= max_total:
            return messages

        logger.info(
            "Memory compressor triggered: %d tokens > %d threshold (model=%s)",
            total_tokens,
            max_total,
            model_name,
        )

        compressed = []
        chunk_size = int(os.getenv("ZIRO_SUMMARY_CHUNK_SIZE", "") or DEFAULT_SUMMARY_CHUNK_SIZE)
        for i in range(0, len(old_msgs), chunk_size):
            chunk = old_msgs[i : i + chunk_size]
            summary = _summarize_messages(chunk, model_name, self.timeout)
            if summary:
                compressed.append(summary)

        return system_msgs + compressed + recent_msgs
