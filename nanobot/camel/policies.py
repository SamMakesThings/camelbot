"""Policy engine for enforcing security policies on tool invocations."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Awaitable

from nanobot.camel.capabilities import CapabilityValue, TrustLevel

if TYPE_CHECKING:
    pass


class PolicyViolation(Exception):
    """Raised when a security policy is violated."""

    def __init__(self, tool: str, param: str, reason: str, value: Any = None):
        self.tool = tool
        self.param = param
        self.reason = reason
        self.value = value
        super().__init__(f"Policy violation in {tool}.{param}: {reason}")


@dataclass
class PolicyCheck:
    """Result of a policy check."""

    allowed: bool
    requires_confirmation: bool
    message: str
    tool: str
    param: str
    value: Any


# Type for confirmation callback: async (message, value) -> bool
ConfirmationCallback = Callable[[str, Any], Awaitable[bool]]


class PolicyEngine:
    """
    Enforces security policies on tool invocations.

    Policies can either:
    - Allow the operation
    - Block the operation (in strict mode)
    - Require user confirmation (in non-strict mode)
    """

    # Tools that produce untrusted output (fetch external data)
    UNTRUSTED_PRODUCERS = {"web_fetch", "web_search", "read_file"}

    # Sensitive parameters that need policy enforcement
    SENSITIVE_PARAMS = {
        "message": ["chat_id", "recipient", "to"],
        "send_email": ["recipient", "to"],
        "write_file": ["path", "file_path"],
        "edit_file": ["path", "file_path"],
        "exec": ["command"],
    }

    def __init__(self, strict_mode: bool = False):
        """
        Initialize the policy engine.

        Args:
            strict_mode: If True, policy violations are hard blocks.
                        If False, risky operations prompt for user confirmation.
        """
        self.strict_mode = strict_mode
        self._confirmation_callback: ConfirmationCallback | None = None

    def set_confirmation_callback(self, callback: ConfirmationCallback) -> None:
        """Set the callback for requesting user confirmation."""
        self._confirmation_callback = callback

    def check_policy(
        self, tool_name: str, param_name: str, value: CapabilityValue
    ) -> PolicyCheck:
        """
        Check if a parameter value is allowed for a tool.

        Returns a PolicyCheck indicating whether the operation is allowed,
        requires confirmation, or should be blocked.
        """
        # Get sensitive params for this tool
        sensitive = self.SENSITIVE_PARAMS.get(tool_name, [])

        # If not a sensitive parameter, allow
        if param_name not in sensitive:
            return PolicyCheck(
                allowed=True,
                requires_confirmation=False,
                message="",
                tool=tool_name,
                param=param_name,
                value=value.value,
            )

        # Check trust level
        if value.trust_level == TrustLevel.TRUSTED:
            return PolicyCheck(
                allowed=True,
                requires_confirmation=False,
                message="",
                tool=tool_name,
                param=param_name,
                value=value.value,
            )

        # Untrusted value in sensitive parameter — check capabilities
        cap_for_param = self._get_required_capability(tool_name, param_name)

        if value.is_allowed(cap_for_param):
            # Has explicit capability, allow
            return PolicyCheck(
                allowed=True,
                requires_confirmation=False,
                message="",
                tool=tool_name,
                param=param_name,
                value=value.value,
            )

        # Policy violation detected
        message = self._format_violation_message(tool_name, param_name, value)

        if self.strict_mode:
            return PolicyCheck(
                allowed=False,
                requires_confirmation=False,
                message=message,
                tool=tool_name,
                param=param_name,
                value=value.value,
            )

        # Non-strict mode: require confirmation
        return PolicyCheck(
            allowed=False,
            requires_confirmation=True,
            message=message,
            tool=tool_name,
            param=param_name,
            value=value.value,
        )

    def _get_required_capability(self, tool_name: str, param_name: str) -> str:
        """Get the capability required for a tool parameter."""
        if tool_name in ("message", "send_email") and param_name in (
            "chat_id",
            "recipient",
            "to",
        ):
            return "can_send_to"
        if tool_name in ("write_file", "edit_file") and param_name in (
            "path",
            "file_path",
        ):
            return "can_write_to"
        if tool_name == "exec" and param_name == "command":
            return "can_execute"
        return "can_display"

    def _format_violation_message(
        self, tool_name: str, param_name: str, value: CapabilityValue
    ) -> str:
        """Format a human-readable policy violation message."""
        val_preview = str(value.value)
        if len(val_preview) > 100:
            val_preview = val_preview[:97] + "..."

        origin_desc = self._describe_origin(value.origin)

        if tool_name in ("message", "send_email"):
            return (
                f"⚠️ Security Check: The recipient '{val_preview}' was {origin_desc}.\n"
                f"This could be a prompt injection attempting to exfiltrate data.\n"
                f"Allow sending to this recipient?"
            )
        if tool_name in ("write_file", "edit_file"):
            return (
                f"⚠️ Security Check: The file path '{val_preview}' was {origin_desc}.\n"
                f"This could be a prompt injection attempting to write malicious content.\n"
                f"Allow writing to this path?"
            )
        if tool_name == "exec":
            return (
                f"⚠️ Security Check: The command '{val_preview}' was {origin_desc}.\n"
                f"This could be a prompt injection attempting to execute malicious code.\n"
                f"Allow executing this command?"
            )

        return (
            f"⚠️ Security Check: The value '{val_preview}' for {tool_name}.{param_name} "
            f"was {origin_desc}. Allow this operation?"
        )

    def _describe_origin(self, origin: str) -> str:
        """Describe the origin of a value in human-readable terms."""
        if origin == "q_llm":
            return "extracted from external content by AI"
        if origin.startswith("tool:"):
            tool = origin.split(":", 1)[1]
            if tool == "web_fetch":
                return "extracted from a web page"
            if tool == "web_search":
                return "extracted from search results"
            if tool == "read_file":
                return "extracted from a file"
            return f"derived from {tool} output"
        if origin == "user":
            return "provided by you"
        if origin == "literal":
            return "specified in the request"
        return f"from {origin}"

    async def validate(
        self, tool_name: str, params: dict[str, CapabilityValue]
    ) -> None:
        """
        Validate all parameters against policies.

        Raises PolicyViolation if any policy is violated and not confirmed.
        """
        for param_name, value in params.items():
            if not isinstance(value, CapabilityValue):
                continue

            check = self.check_policy(tool_name, param_name, value)

            if check.allowed:
                continue

            if check.requires_confirmation:
                # Request user confirmation
                confirmed = await self._request_confirmation(check)
                if confirmed:
                    continue  # User approved

            # Either strict mode or user declined
            raise PolicyViolation(
                tool=tool_name,
                param=param_name,
                reason=check.message,
                value=check.value,
            )

    async def _request_confirmation(self, check: PolicyCheck) -> bool:
        """Request user confirmation for a policy violation."""
        if self._confirmation_callback is None:
            # No callback set, default to deny
            return False

        try:
            return await self._confirmation_callback(check.message, check.value)
        except Exception:
            # On error, default to deny
            return False

    def get_result_trust(
        self, tool_name: str, params: dict[str, CapabilityValue]
    ) -> TrustLevel:
        """Determine the trust level for a tool's result based on the tool and inputs."""
        # Tools that fetch external data produce untrusted results
        if tool_name in self.UNTRUSTED_PRODUCERS:
            return TrustLevel.UNTRUSTED

        # Otherwise, propagate taint from inputs
        from nanobot.camel.capabilities import propagate_taint

        cap_vals = [v for v in params.values() if isinstance(v, CapabilityValue)]
        return propagate_taint(cap_vals) if cap_vals else TrustLevel.TRUSTED

    def get_result_capabilities(self, tool_name: str) -> dict[str, bool]:
        """Determine capabilities for a tool's result."""
        # Results from contact lookups can be sent to
        if tool_name == "lookup_contact":
            return {
                "can_send_to": True,
                "from_contacts": True,
                "can_display": True,
            }

        # File reads are displayable but not actionable
        if tool_name in ("read_file", "web_fetch", "web_search"):
            return {"can_display": True}

        # Default: can display only
        return {"can_display": True}
