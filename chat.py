import json
import logging
import time
import anthropic
from anthropic.types import ToolParam

import telemetry

logger = logging.getLogger(__name__)

class CVEChat:

    def __init__(self, client: anthropic.Anthropic, tools: list[ToolParam], tool_registry: dict, system: str = "", messages=None):
        self.client = client
        self.tools = tools
        self.tool_registry = tool_registry
        self.system = system
        self.messages = messages if messages is not None else []

    def send(self, user_input: str) -> str:
        """Blocking send — unchanged behaviour, used when streaming isn't needed."""
        self.messages.append({"role": "user", "content": user_input})
        return self._blocking_loop()

    def stream_reply(self, user_input: str):
        """Generator that yields SSE-ready tuples for the Flask response.
        Yields ("token", chunk) for each text delta on the FINAL assistant turn.
        Tool-use rounds are blocking (structured JSON, not worth streaming).
        Yields ("done", full_reply_str) exactly once when the model finishes.
        Raises on unrecoverable errors — caller should catch and yield an error event.

        Why a generator instead of a callback?
        Callbacks require a greenlet bridge to push values into a Flask generator
        (you can't `yield` from inside a callback into an outer frame). A generator
        method lets the Flask route do `yield from chat.stream_reply(...)` with no
        threading at all — tokens flow directly from the Anthropic SDK into the
        HTTP response buffer, one `yield` per chunk."""
        self.messages.append({"role": "user", "content": user_input})
        yield from self._stream_loop()

    # ── Internal loops ────────────────────────────────────────────────────────

    def _blocking_loop(self) -> str:
        """Fully blocking agentic loop. Handles tool_use → end_turn recursion."""
        while True:
            create_kwargs = self._create_kwargs()
            _t0 = time.perf_counter()
            try:
                response = self.client.messages.create(**create_kwargs)  # type: ignore
            except Exception:
                telemetry.record_llm("sonnet_loop", create_kwargs["model"], None,
                                     (time.perf_counter() - _t0) * 1000, ok=False)
                raise
            _elapsed = time.perf_counter() - _t0
            _usage   = getattr(response, "usage", None)
            logger.info("sonnet blocking — %.1fs stop=%s in=%s out=%s",
                        _elapsed, response.stop_reason,
                        getattr(_usage, "input_tokens", "?"),
                        getattr(_usage, "output_tokens", "?"))
            telemetry.record_llm("sonnet_loop", getattr(response, "model", create_kwargs["model"]),
                                 _usage, _elapsed * 1000, ok=response.stop_reason != "error")

            if response.stop_reason == "tool_use":
                self.messages.append({"role": "assistant", "content": response.content})
                self.messages.append({"role": "user", "content": self._run_tools(response.content)})
            elif response.stop_reason == "end_turn":
                self.messages.append({"role": "assistant", "content": response.content})
                for block in response.content:
                    if block.type == "text":
                        return block.text
                return "I didn't have anything to add. What would you like to know?"
            elif response.stop_reason == "max_tokens":
                self.messages.append({"role": "assistant", "content": response.content})
                for block in response.content:
                    if block.type == "text":
                        return block.text + "\n\n*(Response was cut off. Ask me to continue.)*"
                return "*(Response was cut off before any text was generated. Please try again.)*"
            else:
                return f"*(Unexpected stop reason: {response.stop_reason}. Please try again.)*"

    def _stream_loop(self):
        """Generator loop. For tool_use rounds: blocking (no tokens to stream).
        For the final text turn: yields ("token", chunk) per delta, then ("done", full_text).
        The Flask route does `yield from chat.stream_reply(msg)` — no threads needed."""
        while True:
            create_kwargs = self._create_kwargs()
            _t0 = time.perf_counter()
            accumulated = ""
            stop_reason = None
            final_msg   = None

            try:
                with self.client.messages.stream(**create_kwargs) as stream:  # type: ignore
                    is_tool_turn = False

                    for event in stream:
                        etype = type(event).__name__
                        if etype == "RawContentBlockStartEvent":
                            if event.content_block.type == "tool_use":
                                is_tool_turn = True
                        elif etype == "RawContentBlockDeltaEvent":
                            delta = event.delta
                            if delta.type == "text_delta" and not is_tool_turn:
                                accumulated += delta.text
                                yield ("token", delta.text)   # ← direct yield, zero buffering

                    final_msg   = stream.get_final_message()
                    stop_reason = final_msg.stop_reason
                    _usage      = getattr(final_msg, "usage", None)

            except Exception:
                telemetry.record_llm("sonnet_loop", create_kwargs["model"], None,
                                     (time.perf_counter() - _t0) * 1000, ok=False)
                raise

            _elapsed = time.perf_counter() - _t0
            _usage   = getattr(final_msg, "usage", None)
            logger.info("sonnet stream — %.1fs stop=%s streamed=%s in=%s out=%s",
                        _elapsed, stop_reason, not is_tool_turn,
                        getattr(_usage, "input_tokens", "?"),
                        getattr(_usage, "output_tokens", "?"))
            telemetry.record_llm("sonnet_loop", create_kwargs["model"],
                                 _usage, _elapsed * 1000, ok=stop_reason != "error")

            if stop_reason == "tool_use":
                self.messages.append({"role": "assistant", "content": final_msg.content})
                self.messages.append({"role": "user", "content": self._run_tools(final_msg.content)})
                # loop continues — next iteration streams the text reply

            elif stop_reason in ("end_turn", "max_tokens"):
                self.messages.append({"role": "assistant", "content": final_msg.content})
                if stop_reason == "max_tokens":
                    suffix = "\n\n*(Response was cut off. Ask me to continue.)*"
                    accumulated += suffix
                    yield ("token", suffix)
                yield ("done", accumulated or "I didn't have anything to add. What would you like to know?")
                return

            else:
                yield ("done", f"*(Unexpected stop reason: {stop_reason}. Please try again.)*")
                return

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _create_kwargs(self) -> dict:
        kw = dict(model="claude-sonnet-4-6", max_tokens=4096,
                  tools=self.tools, messages=self.messages)
        if self.system:
            kw["system"] = self.system
        return kw

    def _run_tools(self, content_blocks) -> list:
        """Execute all tool_use blocks, return tool_result list for message history."""
        tool_results = []
        for block in content_blocks:
            if block.type != "tool_use":
                continue
            logger.debug("tool call → %s(%s)", block.name, str(block.input)[:120])
            _t = time.perf_counter()
            try:
                result   = self.tool_registry[block.name](**block.input)  # type: ignore
                content  = json.dumps(result)
                is_error = False
            except Exception as exc:
                content  = str(exc)
                is_error = True
            if is_error:
                logger.warning("tool ✗ %s %.1fs ERROR: %s",
                               block.name, time.perf_counter() - _t,
                               content[:120].replace("\n", " "))
            else:
                logger.debug("tool ✓ %s %.1fs %s",
                             block.name, time.perf_counter() - _t,
                             content[:120].replace("\n", " "))
            tool_results.append({
                "type": "tool_result", "tool_use_id": block.id,
                "content": content, "is_error": is_error,
            })
        return tool_results

