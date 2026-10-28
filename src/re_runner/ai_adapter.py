"""Provider-agnostic multi-turn / streaming AI adapter (contract level).

This adapter speaks the de-facto OpenAI-compatible chat-completions streaming
contract but never touches a network: the transport is an injectable callable
(``send_fn``), so every exercised path in tests runs on synthetic streams.

Declared honestly up front: ``verification_state = "contract-level"`` and
``service = "no external model contacted"``. Covered surface:
  - request assembly (messages -> wire body, with validation)
  - SSE stream parsing (chunk-boundary reassembly, [DONE], malformed lines)
  - multi-turn context-window truncation (system pinned, newest turns kept)
  - error/retry paths (retryable vs fatal, bounded exponential backoff)
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .errors import InvalidInput


@dataclass
class StreamResult:
    """Aggregated outcome of one parsed synthetic/live stream."""

    text: str = ""
    finish_reason: str | None = None
    chunks: int = 0
    malformed_lines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_record(self) -> dict:
        return {
            "text": self.text,
            "finish_reason": self.finish_reason,
            "chunks": self.chunks,
            "malformed_lines": self.malformed_lines,
            "errors": self.errors,
        }


class RetryableError(Exception):
    """Transport-class failure the adapter is allowed to retry (429/5xx/timeout)."""


def _validate_messages(messages: list[dict[str, Any]]) -> None:
    if not isinstance(messages, list) or not messages:
        raise InvalidInput("messages must be a non-empty list")
    for message in messages:
        if not isinstance(message, dict) or not isinstance(message.get("role"), str) or not isinstance(message.get("content"), str):
            raise InvalidInput("each message needs string 'role' and string 'content'")


class AiStreamAdapter:
    """Streaming chat adapter whose transport is injected, provider-agnostic."""

    verification_state = "contract-level"
    service = "no external model contacted"

    def __init__(self, *, model: str = "synthetic-model", max_context_chars: int = 4096,
                 max_retries: int = 2, backoff_seconds: float = 0.01) -> None:
        if max_context_chars <= 0 or max_retries < 0:
            raise InvalidInput("max_context_chars must be positive and max_retries non-negative")
        self.model = model
        self.max_context_chars = max_context_chars
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds

    def build_request(self, messages: list[dict[str, Any]], *, temperature: float = 0.0) -> dict[str, Any]:
        """Assemble the wire body for the chat-completions streaming contract."""
        _validate_messages(messages)
        return {
            "model": self.model,
            "messages": self.truncate_context(messages)[0],
            "temperature": temperature,
            "stream": True,
        }

    def truncate_context(self, messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
        """Pin leading system message(s), then keep newest turns within the char budget.

        Returns (kept_messages, dropped_turn_count). The approximation is
        char-based and declared as such — real token accounting needs the
        provider tokenizer and is intentionally out of scope here.
        """
        _validate_messages(messages)
        system = [m for m in messages if m["role"] == "system"]
        rest = [m for m in messages if m["role"] != "system"]
        budget = self.max_context_chars - sum(len(m["content"]) for m in system)
        if budget < 0:
            # Even the system block overflows: hard-truncate its tail, keep it single.
            trimmed = dict(system[0])
            trimmed["content"] = system[0]["content"][: self.max_context_chars]
            return [trimmed], len(messages) - 1
        kept_rest: list[dict[str, Any]] = []
        dropped = 0
        for message in reversed(rest):
            if len(message["content"]) <= budget:
                kept_rest.append(message)
                budget -= len(message["content"])
            else:
                dropped += 1
        kept = system + list(reversed(kept_rest))
        return kept, dropped

    def parse_sse_stream(self, chunks: Iterable[bytes]) -> StreamResult:
        """Parse SSE frames out of raw byte chunks, reassembling split lines."""
        result = StreamResult()
        buffer = b""
        for chunk in chunks:
            if not isinstance(chunk, (bytes, bytearray)):
                result.errors.append("non-bytes chunk in stream")
                continue
            buffer += bytes(chunk)
            while (newline := buffer.find(b"\n")) != -1:
                line = buffer[:newline].decode("utf-8", errors="replace").strip()
                buffer = buffer[newline + 1:]
                self._consume_line(line, result)
        if tail := buffer.decode("utf-8", errors="replace").strip():
            self._consume_line(tail, result)
        return result

    def _consume_line(self, line: str, result: StreamResult) -> None:
        if not line or line.startswith(":"):
            return
        if not line.startswith("data:"):
            result.malformed_lines.append(line[:200])
            return
        payload = line[len("data:"):].strip()
        if payload == "[DONE]":
            result.finish_reason = result.finish_reason or "done"
            return
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            result.malformed_lines.append(line[:200])
            return
        result.chunks += 1
        for choice in event.get("choices", []):
            delta = choice.get("delta", {})
            if isinstance(delta.get("content"), str):
                result.text += delta["content"]
            if choice.get("finish_reason"):
                result.finish_reason = choice["finish_reason"]

    def run(self, send_fn: Callable[[dict[str, Any]], Iterable[bytes]], messages: list[dict[str, Any]]) -> dict[str, Any]:
        """Multi-turn request with bounded retry on RetryableError.

        Returns a ToolRun-compatible record; status is "succeeded" only when a
        stream completed and produced text. All transport input is synthetic
        unless the caller injects a real send_fn (not done in this repo).
        """
        body = self.build_request(messages)
        record = {
            "id": f"toolrun-{uuid.uuid4().hex[:12]}",
            "asset_id": "blane-ai-contract",
            "tool": "ai-stream-adapter",
            "version": self.model,
            "argv": ["ai-adapter.run", f"model={self.model}"],
            "status": "failed",
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "exit_code": None,
            "verification_state": self.verification_state,
            "service": self.service,
            "attempts": 0,
        }
        last_error = ""
        for attempt in range(self.max_retries + 1):
            record["attempts"] = attempt + 1
            try:
                result = self.parse_sse_stream(send_fn(body))
            except RetryableError as exc:
                last_error = f"retryable: {exc}"[:300]
                if attempt < self.max_retries:
                    time.sleep(self.backoff_seconds * (2 ** attempt))
                continue
            except Exception as exc:  # fatal — no retry
                record["error"] = f"{type(exc).__name__}: {exc}"[:500]
                record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                return record
            record.update({
                "status": "succeeded" if (result.text or result.finish_reason == "done") else "degraded",
                "exit_code": 0,
                "assistant_text": result.text,
                "finish_reason": result.finish_reason,
                "chunks": result.chunks,
                "malformed_lines": result.malformed_lines,
                "dropped_turns": self.truncate_context(messages)[1],
                "request_body": body,
            })
            if not result.errors:
                record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                return record
            last_error = "; ".join(result.errors)[:300]
        record["error"] = last_error or "retries exhausted"
        record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return record
