"""CaMeL: CApabilities for MachinE Learning security architecture.

This module implements the CaMeL (CApabilities for MachinE Learning) architecture
to protect Nanobot against prompt injection attacks. The key components are:

1. Capability System (capabilities.py):
   - CapabilityValue: Wraps values with trust metadata
   - TrustLevel: TRUSTED, UNTRUSTED, DERIVED

2. Policy Engine (policies.py):
   - PolicyEngine: Validates tool invocations against security policies
   - PolicyViolation: Exception raised when policy is violated

3. Dual-LLM System:
   - P-LLM (p_llm.py): Privileged LLM that only sees user queries, generates code
   - Q-LLM (q_llm.py): Quarantined LLM that processes untrusted data, no tool access

4. Secure Interpreter (interpreter.py):
   - CamelInterpreter: AST-based interpreter with capability tracking

5. CaMeL Agent Loop (loop.py):
   - CamelAgentLoop: Secure agent loop replacing the standard AgentLoop
"""

from nanobot.camel.capabilities import (
    CapabilityValue,
    TrustLevel,
    wrap_trusted,
    wrap_untrusted,
    wrap_literal,
    unwrap,
    propagate_taint,
)
from nanobot.camel.policies import PolicyEngine, PolicyViolation

__all__ = [
    # Capabilities
    "CapabilityValue",
    "TrustLevel",
    "wrap_trusted",
    "wrap_untrusted",
    "wrap_literal",
    "unwrap",
    "propagate_taint",
    # Policies
    "PolicyEngine",
    "PolicyViolation",
]
