"""CaMeL-secured agent loop."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Awaitable

from loguru import logger

from nanobot.agent.context import ContextBuilder
from nanobot.agent.memory import MemoryStore
from nanobot.agent.tools.cron import CronTool
from nanobot.agent.tools.filesystem import (
    EditFileTool,
    ListDirTool,
    ReadFileTool,
    WriteFileTool,
)
from nanobot.agent.tools.message import MessageTool
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.agent.tools.shell import ExecTool
from nanobot.agent.tools.spawn import SpawnTool
from nanobot.agent.tools.web import WebFetchTool, WebSearchTool
from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.camel.capabilities import CapabilityValue, unwrap
from nanobot.camel.interpreter import CamelInterpreter, InterpreterError, SecurityError
from nanobot.camel.p_llm import PrivilegedLLM
from nanobot.camel.policies import PolicyEngine, PolicyViolation
from nanobot.camel.q_llm import QuarantinedLLM
from nanobot.providers.base import LLMProvider
from nanobot.session.manager import Session, SessionManager

if TYPE_CHECKING:
    from nanobot.config.schema import ChannelsConfig, ExecToolConfig
    from nanobot.cron.service import CronService


class CamelAgentLoop:
    """
    CaMeL-secured agent loop.

    Security guarantees:
    1. Control flow integrity: Tool sequence determined only by trusted user query
    2. Data flow integrity: Untrusted data cannot flow to sensitive operations
    3. Capability soundness: All operations validated against explicit policies

    This replaces the standard AgentLoop with a secure alternative.
    """

    def __init__(
        self,
        bus: MessageBus,
        provider: LLMProvider,
        workspace: Path,
        model: str | None = None,
        p_llm_model: str | None = None,
        q_llm_model: str | None = None,
        max_iterations: int = 40,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        memory_window: int = 100,
        reasoning_effort: str | None = None,
        brave_api_key: str | None = None,
        exec_config: ExecToolConfig | None = None,
        cron_service: CronService | None = None,
        restrict_to_workspace: bool = False,
        session_manager: SessionManager | None = None,
        mcp_servers: dict | None = None,
        channels_config: ChannelsConfig | None = None,
        strict_mode: bool = False,
    ):
        from nanobot.agent.subagent import SubagentManager
        from nanobot.config.schema import ExecToolConfig

        self.bus = bus
        self.channels_config = channels_config
        self.provider = provider
        self.workspace = workspace
        self.model = model or provider.get_default_model()
        self.max_iterations = max_iterations
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.memory_window = memory_window
        self.reasoning_effort = reasoning_effort
        self.brave_api_key = brave_api_key
        self.exec_config = exec_config or ExecToolConfig()
        self.cron_service = cron_service
        self.restrict_to_workspace = restrict_to_workspace
        self.strict_mode = strict_mode

        # Session and context (must be before tool registration)
        self.context = ContextBuilder(workspace)
        self.sessions = session_manager or SessionManager(workspace)
        self.subagents = SubagentManager(
            provider=provider,
            workspace=workspace,
            bus=bus,
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            reasoning_effort=reasoning_effort,
            brave_api_key=brave_api_key,
            exec_config=self.exec_config,
            restrict_to_workspace=restrict_to_workspace,
        )

        # Tool registry (after subagents is initialized)
        self.tools = ToolRegistry()
        self._register_default_tools()

        # Policy engine
        self.policy_engine = PolicyEngine(strict_mode=strict_mode)

        # P-LLM and Q-LLM
        self.p_llm = PrivilegedLLM(
            provider=provider,
            model=p_llm_model or self.model,
            tool_definitions=self._format_tool_definitions(),
            workspace=workspace,
            temperature=temperature,
        )
        self.q_llm = QuarantinedLLM(
            provider=provider,
            model=q_llm_model or self.model,
            temperature=temperature,
        )

        self._running = False
        self._mcp_servers = mcp_servers or {}
        self._mcp_stack: AsyncExitStack | None = None
        self._mcp_connected = False
        self._mcp_connecting = False
        self._active_tasks: dict[str, list[asyncio.Task]] = {}
        self._processing_lock = asyncio.Lock()
        self._pending_confirmations: dict[str, asyncio.Future] = {}

    def _register_default_tools(self) -> None:
        """Register the default set of tools."""
        allowed_dir = self.workspace if self.restrict_to_workspace else None

        for cls in (ReadFileTool, WriteFileTool, EditFileTool, ListDirTool):
            self.tools.register(cls(workspace=self.workspace, allowed_dir=allowed_dir))

        self.tools.register(
            ExecTool(
                working_dir=str(self.workspace),
                timeout=self.exec_config.timeout,
                restrict_to_workspace=self.restrict_to_workspace,
                path_append=self.exec_config.path_append,
            )
        )
        self.tools.register(WebSearchTool(api_key=self.brave_api_key))
        self.tools.register(WebFetchTool())
        self.tools.register(MessageTool(send_callback=self.bus.publish_outbound))
        self.tools.register(SpawnTool(manager=self.subagents))

        if self.cron_service:
            self.tools.register(CronTool(self.cron_service))

    def _format_tool_definitions(self) -> str:
        """Format tool definitions for P-LLM system prompt."""
        lines = []
        for tool in self.tools._tools.values():
            params = tool.parameters.get("properties", {})
            required = tool.parameters.get("required", [])

            param_parts = []
            for k, v in params.items():
                param_type = v.get("type", "any")
                desc = v.get("description", "")
                req_marker = "" if k in required else "?"
                param_parts.append(f"{k}{req_marker}: {param_type}")

            param_str = ", ".join(param_parts)
            lines.append(f"- {tool.name}({param_str})")
            lines.append(f"  {tool.description}")

        return "\n".join(lines)

    async def _connect_mcp(self) -> None:
        """Connect to configured MCP servers (one-time, lazy)."""
        if self._mcp_connected or self._mcp_connecting or not self._mcp_servers:
            return
        self._mcp_connecting = True
        from nanobot.agent.tools.mcp import connect_mcp_servers

        try:
            self._mcp_stack = AsyncExitStack()
            await self._mcp_stack.__aenter__()
            await connect_mcp_servers(self._mcp_servers, self.tools, self._mcp_stack)
            self._mcp_connected = True
            # Update P-LLM with new tool definitions
            self.p_llm.update_tool_definitions(self._format_tool_definitions())
        except Exception as e:
            logger.error("Failed to connect MCP servers: {}", e)
            if self._mcp_stack:
                try:
                    await self._mcp_stack.aclose()
                except Exception:
                    pass
                self._mcp_stack = None
        finally:
            self._mcp_connecting = False

    def _set_tool_context(
        self, channel: str, chat_id: str, message_id: str | None = None
    ) -> None:
        """Update context for all tools that need routing info."""
        for name in ("message", "spawn", "cron"):
            if tool := self.tools.get(name):
                if hasattr(tool, "set_context"):
                    tool.set_context(
                        channel, chat_id, *([message_id] if name == "message" else [])
                    )

    async def run(self) -> None:
        """Run the CaMeL agent loop."""
        self._running = True
        await self._connect_mcp()
        logger.info("CaMeL Agent Loop started (secure mode)")

        while self._running:
            try:
                msg = await asyncio.wait_for(self.bus.consume_inbound(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Check for confirmation responses
            if self._is_confirmation_response(msg):
                await self._handle_confirmation_response(msg)
                continue

            if msg.content.strip().lower() == "/stop":
                await self._handle_stop(msg)
            else:
                task = asyncio.create_task(self._dispatch(msg))
                self._active_tasks.setdefault(msg.session_key, []).append(task)
                task.add_done_callback(
                    lambda t, k=msg.session_key: self._active_tasks.get(k, [])
                    and t in self._active_tasks.get(k, [])
                    and self._active_tasks[k].remove(t)
                )

    def _is_confirmation_response(self, msg: InboundMessage) -> bool:
        """Check if this message is a response to a security confirmation prompt."""
        content = msg.content.strip().lower()
        return msg.session_key in self._pending_confirmations and content in (
            "y",
            "yes",
            "n",
            "no",
        )

    async def _handle_confirmation_response(self, msg: InboundMessage) -> None:
        """Handle a user's response to a security confirmation prompt."""
        future = self._pending_confirmations.pop(msg.session_key, None)
        if future and not future.done():
            confirmed = msg.content.strip().lower() in ("y", "yes")
            future.set_result(confirmed)

            if confirmed:
                await self.bus.publish_outbound(
                    OutboundMessage(
                        channel=msg.channel,
                        chat_id=msg.chat_id,
                        content="✓ Confirmed. Proceeding with the operation.",
                    )
                )
            else:
                await self.bus.publish_outbound(
                    OutboundMessage(
                        channel=msg.channel,
                        chat_id=msg.chat_id,
                        content="✗ Cancelled. The operation was blocked for your safety.",
                    )
                )

    async def _handle_stop(self, msg: InboundMessage) -> None:
        """Cancel all active tasks for the session."""
        tasks = self._active_tasks.pop(msg.session_key, [])
        cancelled = sum(1 for t in tasks if not t.done() and t.cancel())

        for t in tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

        sub_cancelled = await self.subagents.cancel_by_session(msg.session_key)
        total = cancelled + sub_cancelled

        content = f"⏹ Stopped {total} task(s)." if total else "No active task to stop."
        await self.bus.publish_outbound(
            OutboundMessage(channel=msg.channel, chat_id=msg.chat_id, content=content)
        )

    async def _dispatch(self, msg: InboundMessage) -> None:
        """Process a message."""
        async with self._processing_lock:
            try:
                response = await self._process_message(msg)
                if response is not None:
                    await self.bus.publish_outbound(response)
            except asyncio.CancelledError:
                logger.info("Task cancelled for session {}", msg.session_key)
                raise
            except Exception:
                logger.exception("Error processing message for session {}", msg.session_key)
                await self.bus.publish_outbound(
                    OutboundMessage(
                        channel=msg.channel,
                        chat_id=msg.chat_id,
                        content="Sorry, I encountered an error processing your request.",
                    )
                )

    async def _process_message(self, msg: InboundMessage) -> OutboundMessage | None:
        """Process a message through the CaMeL architecture."""
        # Handle slash commands
        cmd = msg.content.strip().lower()
        session = self.sessions.get_or_create(msg.session_key)

        if cmd == "/new":
            session.clear()
            self.sessions.save(session)
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content="New session started. (CaMeL secure mode)",
            )

        if cmd == "/help":
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=(
                    "🔒 nanobot (CaMeL secure mode)\n\n"
                    "Commands:\n"
                    "/new — Start a new conversation\n"
                    "/stop — Stop the current task\n"
                    "/help — Show this help\n\n"
                    "Security: This agent uses CaMeL architecture to protect against "
                    "prompt injection attacks. You may be asked to confirm sensitive operations."
                ),
            )

        # Set tool context
        self._set_tool_context(msg.channel, msg.chat_id, msg.metadata.get("message_id"))

        if message_tool := self.tools.get("message"):
            if isinstance(message_tool, MessageTool):
                message_tool.start_turn()

        # Set up confirmation callback
        async def confirmation_callback(message: str, value: Any) -> bool:
            """Request user confirmation for a risky operation."""
            # Send confirmation prompt
            await self.bus.publish_outbound(
                OutboundMessage(
                    channel=msg.channel,
                    chat_id=msg.chat_id,
                    content=f"{message}\n\nReply 'y' to allow or 'n' to block.",
                )
            )

            # Wait for response
            future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()
            self._pending_confirmations[msg.session_key] = future

            try:
                return await asyncio.wait_for(future, timeout=60.0)
            except asyncio.TimeoutError:
                self._pending_confirmations.pop(msg.session_key, None)
                await self.bus.publish_outbound(
                    OutboundMessage(
                        channel=msg.channel,
                        chat_id=msg.chat_id,
                        content="⏱ Confirmation timed out. Operation cancelled for safety.",
                    )
                )
                return False

        self.policy_engine.set_confirmation_callback(confirmation_callback)

        user_query = msg.content
        logger.info(
            "Processing through CaMeL: {}",
            user_query[:80] + "..." if len(user_query) > 80 else user_query,
        )

        # Step 1: P-LLM generates execution plan
        try:
            execution_plan = await self.p_llm.generate_plan(user_query)
            logger.debug("Generated execution plan:\n{}", execution_plan)
        except Exception as e:
            logger.error("P-LLM failed: {}", e)
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content="I couldn't understand that request. Please try rephrasing.",
            )

        # Handle empty or invalid plans - P-LLM may return plain text for simple queries
        if not execution_plan or not execution_plan.strip():
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content="I'm not sure how to help with that. Could you rephrase?",
            )

        # Step 2: Create interpreter and execute plan
        interpreter = CamelInterpreter(
            tools=self.tools,
            policy_engine=self.policy_engine,
            q_llm=self.q_llm,
        )

        try:
            result = await interpreter.execute(
                execution_plan,
                user_context={"user_query": user_query},
            )

            # Check if message tool already sent response
            if (mt := self.tools.get("message")) and isinstance(mt, MessageTool):
                if mt._sent_in_turn:
                    return None

            # Format response
            if result is not None:
                content = str(unwrap(result))
            else:
                content = "Task completed."

            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=content,
            )

        except PolicyViolation as e:
            logger.warning("Policy violation: {}", e)
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=(
                    f"🛡️ Security: Operation blocked\n\n"
                    f"{e.reason}\n\n"
                    "This protection prevents prompt injection attacks from "
                    "manipulating the agent through external content."
                ),
            )

        except SecurityError as e:
            logger.warning("Security error: {}", e)
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=f"🛡️ Security check failed: {e}",
            )

        except InterpreterError as e:
            logger.error("Interpreter error: {} | Plan was:\n{}", e, execution_plan)
            # If it's a syntax error, the P-LLM probably returned prose instead of code
            if "syntax" in str(e).lower():
                # Try to extract any useful content from the failed plan
                return OutboundMessage(
                    channel=msg.channel,
                    chat_id=msg.chat_id,
                    content=f"I had trouble processing that request. Here's what I was trying to do:\n\n{execution_plan[:500]}",
                )
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=f"I encountered an error executing the plan: {e}",
            )

        except SyntaxError as e:
            logger.error("Syntax error in generated plan: {} | Plan was:\n{}", e, execution_plan)
            # P-LLM returned prose instead of code - show it to user
            return OutboundMessage(
                channel=msg.channel,
                chat_id=msg.chat_id,
                content=execution_plan[:1000] if execution_plan else "I'm not sure how to respond to that.",
            )

    async def close_mcp(self) -> None:
        """Close MCP connections."""
        if self._mcp_stack:
            try:
                await self._mcp_stack.aclose()
            except (RuntimeError, BaseExceptionGroup):
                pass
            self._mcp_stack = None

    def stop(self) -> None:
        """Stop the agent loop."""
        self._running = False
        logger.info("CaMeL Agent Loop stopping")

    async def process_direct(
        self,
        content: str,
        session_key: str = "cli:direct",
        channel: str = "cli",
        chat_id: str = "direct",
        on_progress: Callable[[str], Awaitable[None]] | None = None,
    ) -> str:
        """Process a message directly (for CLI or cron usage)."""
        await self._connect_mcp()
        msg = InboundMessage(
            channel=channel, sender_id="user", chat_id=chat_id, content=content
        )
        response = await self._process_message(msg)
        return response.content if response else ""
