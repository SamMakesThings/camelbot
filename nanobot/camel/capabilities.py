"""Capability system for tracking trust and permissions on values."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustLevel(Enum):
    """Trust classification for values."""

    TRUSTED = "trusted"  # From user input or trusted sources
    UNTRUSTED = "untrusted"  # From Q-LLM extraction or external data
    DERIVED = "derived"  # Computed from other values (inherits lowest trust)


@dataclass
class CapabilityValue:
    """
    A value wrapped with capability metadata for security tracking.

    Every value in the CaMeL interpreter is wrapped in this class to track:
    - Where it came from (origin)
    - How much we trust it (trust_level)
    - What operations are allowed (capabilities)
    """

    value: Any
    trust_level: TrustLevel
    origin: str  # Source identifier: "user", "q_llm", "tool:web_fetch", "literal", etc.
    capabilities: dict[str, bool] = field(default_factory=dict)

    # Standard capability flags:
    # - can_send_to: Can be used as message/email recipient
    # - can_write_to: Can be used as file path for writing
    # - can_execute: Can be used as shell command
    # - can_display: Can be shown to user
    # - user_provided: Explicitly provided by user in their query
    # - from_contacts: Came from trusted contacts lookup

    def is_allowed(self, operation: str) -> bool:
        """Check if this value can be used for a given operation."""
        return self.capabilities.get(operation, False)

    def with_capability(self, cap: str, value: bool = True) -> CapabilityValue:
        """Return new CapabilityValue with added/modified capability."""
        new_caps = {**self.capabilities, cap: value}
        return CapabilityValue(
            value=self.value,
            trust_level=self.trust_level,
            origin=self.origin,
            capabilities=new_caps,
        )

    def with_trust(self, trust_level: TrustLevel) -> CapabilityValue:
        """Return new CapabilityValue with different trust level."""
        return CapabilityValue(
            value=self.value,
            trust_level=trust_level,
            origin=self.origin,
            capabilities=self.capabilities.copy(),
        )

    @property
    def is_trusted(self) -> bool:
        """Check if this value is fully trusted."""
        return self.trust_level == TrustLevel.TRUSTED

    @property
    def is_untrusted(self) -> bool:
        """Check if this value is untrusted."""
        return self.trust_level == TrustLevel.UNTRUSTED

    def __repr__(self) -> str:
        val_repr = repr(self.value)
        if len(val_repr) > 50:
            val_repr = val_repr[:47] + "..."
        return f"CapabilityValue({val_repr}, {self.trust_level.value}, {self.origin})"


def propagate_taint(inputs: list[CapabilityValue]) -> TrustLevel:
    """
    Propagate taint through computation: any untrusted input taints the output.

    This implements conservative taint tracking — if any input is untrusted,
    the result is untrusted.
    """
    if not inputs:
        return TrustLevel.TRUSTED

    if any(i.trust_level == TrustLevel.UNTRUSTED for i in inputs):
        return TrustLevel.UNTRUSTED

    if any(i.trust_level == TrustLevel.DERIVED for i in inputs):
        return TrustLevel.DERIVED

    return TrustLevel.TRUSTED


def merge_capabilities(inputs: list[CapabilityValue]) -> dict[str, bool]:
    """
    Merge capabilities from multiple inputs conservatively.

    A capability is only present if ALL inputs have it.
    """
    if not inputs:
        return {}

    # Start with first input's capabilities
    result = inputs[0].capabilities.copy()

    # Intersect with remaining inputs
    for cap_val in inputs[1:]:
        result = {
            k: v and cap_val.capabilities.get(k, False) for k, v in result.items()
        }

    return {k: v for k, v in result.items() if v}


def wrap_trusted(value: Any, origin: str = "user") -> CapabilityValue:
    """Wrap a value as fully trusted with all capabilities."""
    return CapabilityValue(
        value=value,
        trust_level=TrustLevel.TRUSTED,
        origin=origin,
        capabilities={
            "can_send_to": True,
            "can_write_to": True,
            "can_execute": True,
            "can_display": True,
            "user_provided": origin == "user",
        },
    )


def wrap_untrusted(value: Any, origin: str = "q_llm") -> CapabilityValue:
    """Wrap a value as untrusted with minimal capabilities."""
    return CapabilityValue(
        value=value,
        trust_level=TrustLevel.UNTRUSTED,
        origin=origin,
        capabilities={
            "can_display": True,  # Can always show to user
        },
    )


def wrap_literal(value: Any) -> CapabilityValue:
    """Wrap a literal value from P-LLM generated code (trusted)."""
    return CapabilityValue(
        value=value,
        trust_level=TrustLevel.TRUSTED,
        origin="literal",
        capabilities={
            "can_send_to": True,
            "can_write_to": True,
            "can_execute": True,
            "can_display": True,
            "user_provided": True,  # Literals in P-LLM code derive from user intent
        },
    )


def unwrap(cap_val: CapabilityValue | Any) -> Any:
    """Unwrap a CapabilityValue to get the raw value."""
    if isinstance(cap_val, CapabilityValue):
        return cap_val.value
    return cap_val
