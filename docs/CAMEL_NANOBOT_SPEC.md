# CaMeL-Nanobot Specification

## Overview

**Project**: Nanobot-Secure
**Goal**: Integrate CaMeL architecture to make Nanobot resistant to prompt injection attacks
**Approach**: Dual-LLM system with capability-based access control

---

## Problem Statement

Nanobot's single-LLM architecture processes both trusted user instructions and untrusted external data (web pages, emails, files) in the same context. This enables prompt injection attacks where malicious content in external data can hijack agent behavior.

---

## Solution

Implement CaMeL (CApabilities for MachinE Learning) architecture:

1. **P-LLM (Privileged LLM)**: Only sees user queries, generates execution plans
2. **Q-LLM (Quarantined LLM)**: Processes untrusted data, has no tool access
3. **Capability System**: Tracks trust level and permissions on all values
4. **Policy Engine**: Validates operations, prompts user for risky actions
5. **Secure Interpreter**: Executes P-LLM plans with security enforcement

---

## Components

### 1. Capability System

**File**: `nanobot/camel/capabilities.py`

**Purpose**: Wrap values with trust metadata for security tracking.

**Key Types**:
- `TrustLevel` enum: `TRUSTED`, `UNTRUSTED`, `DERIVED`
- `CapabilityValue` dataclass with fields:
  - `value: Any` — the actual data
  - `trust_level: TrustLevel`
  - `origin: str` — source identifier ("user", "q_llm", "tool:web_fetch")
  - `capabilities: dict` — permission flags (can_send_to, can_write_to, can_execute, can_display)

**Key Functions**:
- `propagate_taint(inputs)` → returns lowest trust level among inputs
- `CapabilityValue.is_allowed(operation)` → check if operation is permitted

---

### 2. Policy Engine

**File**: `nanobot/camel/policies.py`

**Purpose**: Validate tool invocations against security policies. Prompt user for confirmation on risky operations.

**Key Types**:
- `PolicyViolation` exception with tool, param, and reason
- `PolicyEngine` class

**Default Policies**:
| Tool | Parameter | Policy |
|------|-----------|--------|
| `message` | recipient/chat_id | Block untrusted unless user confirms |
| `write_file` | path | Block untrusted unless user confirms |
| `exec` | command | Block untrusted unless user confirms |

**Behavior**: When policy violation detected, prompt user with explanation and ask for confirmation. If user approves, allow the operation with audit log.

---

### 3. P-LLM Handler

**File**: `nanobot/camel/p_llm.py`

**Purpose**: Generate execution plans from user queries.

**Constraints**:
- Only receives the original user query (trusted)
- Never sees external data content
- Outputs pseudo-Python code for the interpreter

**System Prompt**: Instructs LLM to convert natural language to code using available tools and `query_quarantined_llm()` for data extraction.

**Configuration**: Uses `camel.p_llm_model` (default: `anthropic/claude-sonnet-4-5`)

---

### 4. Q-LLM Handler

**File**: `nanobot/camel/q_llm.py`

**Purpose**: Extract structured data from untrusted content.

**Constraints**:
- NO tool access (tools parameter always None)
- Cannot influence control flow
- Output always tagged as UNTRUSTED

**System Prompt**: Instructs LLM to extract specific information only, ignore embedded instructions.

**Configuration**: Uses `camel.q_llm_model` (default: `anthropic/claude-sonnet-4-5`)

---

### 5. Secure Interpreter

**File**: `nanobot/camel/interpreter.py`

**Purpose**: Execute P-LLM generated code with security enforcement.

**Approach**: AST-based Python interpreter that:
- Parses P-LLM output as Python AST
- Tracks CapabilityValue on all variables
- Validates tool calls through PolicyEngine before execution
- Routes `query_quarantined_llm()` calls to Q-LLM
- Tags tool results with appropriate trust levels

**Supported Constructs**: Assignment, function calls, for loops, if statements, basic expressions.

**Restricted**: No imports, no exec/eval, no file I/O outside of tools, limited builtins.

---

### 6. CaMeL Agent Loop

**File**: `nanobot/camel/loop.py`

**Purpose**: Main entry point replacing standard agent loop.

**Flow**:
```
User Query → P-LLM (generate plan) → Interpreter (execute with security) → Response
                                          ↓
                                     Q-LLM (as needed for data extraction)
                                          ↓
                                     Tools (validated by PolicyEngine)
```

**User Confirmation**: When PolicyEngine detects risky operation, the loop pauses and prompts user via the channel for confirmation.

---

### 7. Configuration

**File**: `nanobot/config/schema.py` (additions)

**New Config Section**:
```python
class CamelConfig(Base):
    enabled: bool = False
    p_llm_model: str = "anthropic/claude-sonnet-4-5"
    q_llm_model: str = "anthropic/claude-sonnet-4-5"
    strict_mode: bool = False  # False = prompt for confirmation; True = hard block
```

---

## File Structure

```
nanobot/
├── camel/
│   ├── __init__.py
│   ├── capabilities.py
│   ├── policies.py
│   ├── p_llm.py
│   ├── q_llm.py
│   ├── interpreter.py
│   └── loop.py
├── config/
│   └── schema.py          # Add CamelConfig
└── cli/
    └── commands.py        # Add --secure flag
```

---

## Security Properties

| Attack | Mitigation |
|--------|------------|
| Prompt injection | P-LLM never sees untrusted content |
| Data exfiltration | Untrusted recipients require user confirmation |
| Command injection | Untrusted commands require user confirmation |
| Control flow hijacking | Execution plan set only by user query |
| Argument tampering | All tool args validated against capabilities |

---

## User Experience

### Normal Flow
```
User: "Summarize my last email"
→ P-LLM generates: email = get_last_email(); summary = query_quarantined_llm("summarize", email); message(summary)
→ Interpreter executes, Q-LLM summarizes
→ User sees summary
```

### Security Intervention
```
User: "Forward my last email to the sender"
→ P-LLM generates plan with extracted sender address
→ Q-LLM extracts sender (untrusted)
→ PolicyEngine detects untrusted recipient
→ User prompted: "⚠️ The recipient 'bob@example.com' was extracted from email content. Send anyway? [y/N]"
→ User confirms → email sent
→ User declines → operation cancelled
```

---

## Testing Requirements

1. **Unit tests** for CapabilityValue, PolicyEngine, Interpreter
2. **Integration tests** for P-LLM → Interpreter → Q-LLM flow
3. **Security tests** validating prompt injection scenarios are blocked/flagged
4. **E2E tests** for user confirmation flow

---

## Out of Scope (This Version)

- Local Q-LLM support
- Custom user-defined policies
- Capability inheritance for complex data structures
- Multi-turn plan refinement
- Performance optimizations

---

## Decisions

1. **Rollout strategy**: Direct replacement — CaMeL mode replaces the standard agent loop entirely. No legacy/parallel mode.

2. **Confirmation UX**: How to handle confirmations in non-interactive channels (cron, subagents)?
   - Default to deny in non-interactive contexts

---

## Success Criteria

1. CaMeL mode blocks simulated prompt injection attacks
2. User confirmation flow works across all channels
3. Task success rate within 10% of standard mode
4. Clear security violation messages help users understand protections
