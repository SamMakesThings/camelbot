# Nanobot Architecture: Comprehensive Analysis

## Overview

**Nanobot** is an ultra-lightweight personal AI assistant framework (~4,000 core lines of code). It provides a multi-channel conversational AI agent with tool execution, persistent memory, and extensible skills.

**Key Characteristics:**
- Minimal footprint with maximum functionality
- Multi-platform support (Telegram, Discord, WhatsApp, Slack, etc.)
- Tool-based execution with MCP support
- Persistent conversation memory
- Extensible skill system

---

## Project Structure

```
/code/
├── nanobot/                    # Main Python package
│   ├── agent/                  # Core agent system (~30k lines)
│   │   ├── loop.py             # Central agent orchestration (22k)
│   │   ├── context.py          # Prompt building (6.5k)
│   │   ├── memory.py           # Persistent memory (5.7k)
│   │   ├── skills.py           # Skills management (8.3k)
│   │   ├── subagent.py         # Background tasks (9.6k)
│   │   └── tools/              # Tool implementations
│   │       ├── base.py         # Tool interface
│   │       ├── registry.py     # Tool registration
│   │       ├── filesystem.py   # File operations
│   │       ├── shell.py        # Command execution
│   │       ├── web.py          # Web search/fetch
│   │       ├── message.py      # Channel messaging
│   │       ├── spawn.py        # Subagent spawning
│   │       ├── cron.py         # Scheduled tasks
│   │       └── mcp.py          # MCP integration
│   ├── channels/               # Platform integrations (~10k lines)
│   │   ├── base.py             # Channel interface
│   │   ├── telegram.py
│   │   ├── discord.py
│   │   ├── whatsapp.py
│   │   ├── slack.py
│   │   ├── feishu.py
│   │   ├── dingtalk.py
│   │   ├── matrix.py
│   │   ├── mochat.py
│   │   ├── qq.py
│   │   └── email.py
│   ├── cli/                    # Command-line interface
│   │   └── commands.py         # CLI commands (38k)
│   ├── config/                 # Configuration
│   │   └── schema.py           # Pydantic schemas (2.3k)
│   ├── session/                # Conversation management
│   │   └── manager.py          # Session persistence
│   ├── providers/              # LLM backends
│   │   └── litellm.py          # LiteLLM provider
│   ├── bus/                    # Message routing
│   │   ├── queue.py            # Message bus
│   │   └── events.py           # Event types
│   ├── cron/                   # Scheduled tasks
│   │   └── service.py          # Cron service
│   ├── heartbeat/              # Periodic execution
│   │   └── service.py          # Heartbeat service
│   └── skills/                 # Bundled skills
├── bridge/                     # Node.js WhatsApp bridge
├── tests/                      # Test suite
├── pyproject.toml              # Dependencies
├── README.md                   # Documentation
└── SECURITY.md                 # Security guidelines
```

---

## Core Components

### 1. Agent Loop (`nanobot/agent/loop.py`)

The central orchestrator that processes messages and executes tools.

```python
class AgentLoop:
    """Main agent orchestration loop"""

    def __init__(
        self,
        bus: MessageBus,
        provider: LLMProvider,
        workspace: Path,
        model: str,
        max_iterations: int = 40,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        memory_window: int = 100,
        mcp_servers: dict = None,
        channels_config: ChannelsConfig = None,
    ): ...

    async def run(self):
        """Main message processing loop"""
        while True:
            msg = await self.bus.consume_inbound()
            session = self.sessions.get_or_create(msg.session_key)
            response = await self._run_agent_loop(session, msg)
            await self.bus.publish_outbound(response)

    async def _run_agent_loop(
        self,
        initial_messages: list[dict]
    ) -> tuple[str, list, list]:
        """
        Iterative tool execution loop:
        1. Call LLM with messages
        2. If tool calls returned, execute them
        3. Add results to messages
        4. Repeat until no more tool calls or max_iterations
        5. Return final response
        """
```

**Key Parameters:**
- `max_iterations=40`: Prevents infinite tool loops
- `temperature=0.1`: Deterministic responses
- `memory_window=100`: Triggers consolidation when exceeded

**Execution Flow:**
```
Message → Build Context → LLM Call → Tool Execution (loop) → Response
                              ↑              ↓
                              └──── Tool Results ────┘
```

### 2. Context Builder (`nanobot/agent/context.py`)

Assembles the system prompt from multiple sources.

```python
class ContextBuilder:
    """Builds the full context for LLM calls"""

    def build_system_prompt(self) -> str:
        """
        Assembles prompt from:
        1. Identity block (OS, workspace, Python version)
        2. Bootstrap files (AGENTS.md, SOUL.md, USER.md, TOOLS.md, IDENTITY.md)
        3. Memory context (MEMORY.md)
        4. Always-on skills
        5. Skills summary (XML listing)
        6. Runtime context (time, channel, chat_id)
        """

    def build_messages(
        self,
        history: list[dict],
        current_message: str,
        media: list[str],
        channel: str,
        chat_id: str,
    ) -> list[dict]:
        """
        Builds message list:
        - System prompt
        - Conversation history
        - Runtime context injection
        - Current message with media (base64 images)
        """
```

**Bootstrap Files (from workspace):**
| File | Purpose |
|------|---------|
| `AGENTS.md` | Agent behavior configuration |
| `SOUL.md` | Personality and values |
| `USER.md` | User preferences |
| `TOOLS.md` | Tool usage guidelines |
| `IDENTITY.md` | Agent identity |

### 3. Memory System (`nanobot/agent/memory.py`)

Two-file persistent memory architecture.

```python
class MemoryStore:
    """
    Two-layer memory:
    - MEMORY.md: Long-term consolidated facts
    - HISTORY.md: Timestamped searchable log
    """

    async def consolidate(
        self,
        session: Session,
        force: bool = False
    ):
        """
        Triggered when messages exceed memory_window:
        1. Extract old messages from session
        2. Call LLM to consolidate into summary
        3. Update MEMORY.md with new facts
        4. Append to HISTORY.md with timestamps
        5. Preserve append-only message list (cache efficiency)
        """

    def get_memory_context(self) -> str:
        """Returns contents of MEMORY.md for system prompt"""
```

**Consolidation Process:**
```
Session messages > memory_window
         ↓
Extract old messages (before threshold)
         ↓
LLM: "Summarize these into facts + history entry"
         ↓
Tool call: save_memory(memory_update, history_entry)
         ↓
Append to HISTORY.md: [YYYY-MM-DD HH:MM] entry
Update MEMORY.md: consolidated facts
```

### 4. Tool System (`nanobot/agent/tools/`)

Registry-based dynamic tool management.

#### Base Interface (`base.py`)

```python
class Tool(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Tool identifier"""

    @property
    @abstractmethod
    def description(self) -> str:
        """Help text for LLM"""

    @property
    @abstractmethod
    def parameters(self) -> dict:
        """JSON Schema for parameters"""

    @abstractmethod
    async def execute(self, **kwargs) -> str:
        """Execute the tool"""

    def validate_params(self, params: dict) -> list[str]:
        """Validate parameters against schema"""

    def to_schema(self) -> dict:
        """Convert to OpenAI function calling format"""
```

#### Tool Registry (`registry.py`)

```python
class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a tool by name"""

    def unregister(self, name: str) -> None:
        """Remove a tool"""

    def get(self, name: str) -> Tool | None:
        """Get tool by name"""

    def get_definitions(self) -> list[dict]:
        """Get all tool schemas for LLM"""

    async def execute(self, name: str, params: dict) -> str:
        """Execute a tool with validation"""
```

#### Built-in Tools

| Tool | File | Purpose |
|------|------|---------|
| `read_file` | filesystem.py | Read file contents |
| `write_file` | filesystem.py | Create/overwrite files |
| `edit_file` | filesystem.py | Diff-based file editing |
| `list_dir` | filesystem.py | List directory contents |
| `exec` | shell.py | Execute shell commands |
| `web_search` | web.py | Brave API search |
| `web_fetch` | web.py | Fetch and parse URLs |
| `message` | message.py | Send to channels |
| `spawn` | spawn.py | Background subagents |
| `cron` | cron.py | Schedule tasks |

### 5. Session Management (`nanobot/session/manager.py`)

```python
class Session:
    """Manages conversation state"""

    def __init__(self, key: str, workspace: Path):
        self.key = key  # channel:chat_id
        self.messages: list[dict] = []
        self.last_consolidated: int = 0

    def add_message(
        self,
        role: str,
        content: str,
        tool_calls: list = None,
        tool_call_id: str = None
    ):
        """Append message to session"""

    def get_history(self, max_messages: int = 500) -> list[dict]:
        """
        Get messages for context:
        - From last_consolidated onwards
        - Aligned to user turn (no orphaned tool_results)
        """

    def save(self):
        """Persist to JSONL file"""

    @classmethod
    def load(cls, key: str, workspace: Path) -> "Session":
        """Load from JSONL file"""
```

**Storage:** `~/.nanobot/workspace/sessions/{channel}_{chat_id}.jsonl`

### 6. Message Bus (`nanobot/bus/`)

Async message routing between channels and agent.

```python
# events.py
@dataclass
class InboundMessage:
    channel: str        # "telegram", "discord", etc.
    sender_id: str      # User identifier
    chat_id: str        # Chat/thread ID
    content: str        # Message text
    timestamp: datetime
    media: list[str]    # File paths or URLs
    metadata: dict      # Channel-specific data
    session_key_override: str | None  # For threads

@dataclass
class OutboundMessage:
    channel: str
    chat_id: str
    content: str
    reply_to: str | None
    media: list[str]
    metadata: dict

# queue.py
class MessageBus:
    inbound: asyncio.Queue[InboundMessage]
    outbound: asyncio.Queue[OutboundMessage]

    async def publish_inbound(self, msg: InboundMessage): ...
    async def consume_inbound(self) -> InboundMessage: ...
    async def publish_outbound(self, msg: OutboundMessage): ...
    async def consume_outbound(self) -> OutboundMessage: ...
```

### 7. Channel System (`nanobot/channels/`)

Platform integrations for receiving and sending messages.

```python
# base.py
class BaseChannel(ABC):
    def __init__(self, config: dict, bus: MessageBus):
        self.config = config
        self.bus = bus

    @abstractmethod
    async def start(self):
        """Start listening for messages"""

    @abstractmethod
    async def send(self, msg: OutboundMessage):
        """Send a message"""

    def is_allowed(self, sender_id: str) -> bool:
        """Check if sender is in allowFrom list"""
        allow_list = self.config.get("allowFrom", [])
        return not allow_list or sender_id in allow_list
```

**Supported Channels:**
- Telegram
- Discord
- WhatsApp (via Node.js bridge)
- Slack
- Feishu (Lark)
- DingTalk
- Matrix
- Mochat
- QQ
- Email (IMAP/SMTP)

### 8. Provider System (`nanobot/providers/`)

LLM backend abstraction using LiteLLM.

```python
class LLMProvider:
    """LLM provider interface"""

    async def chat_completion(
        self,
        messages: list[dict],
        tools: list[dict] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> dict:
        """Call LLM with messages and optional tools"""

class LiteLLMProvider(LLMProvider):
    """LiteLLM-based provider supporting multiple backends"""

    def __init__(self, model: str, api_key: str, api_base: str = None):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base

    async def chat_completion(self, ...):
        """Route to appropriate backend via LiteLLM"""
```

**Supported Providers:**
- OpenAI
- Anthropic
- OpenRouter
- DeepSeek
- Groq
- Azure OpenAI
- Local models

### 9. Skills System (`nanobot/agent/skills.py`)

Progressive skill loading with requirements checking.

```python
class SkillsLoader:
    """Load and manage agent skills"""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.skills_dir = workspace / "skills"

    def load_skills(self) -> list[Skill]:
        """
        Load skills from:
        - Workspace: ~/.nanobot/workspace/skills/{name}/SKILL.md
        - Built-in: Bundled package skills
        """

    def check_requirements(self, skill: Skill) -> bool:
        """
        Check availability:
        - Binary dependencies (apt/brew)
        - Environment variables
        - Optional features
        """

    def get_always_on(self) -> list[Skill]:
        """Skills marked always=true, loaded into system prompt"""

    def get_skill_summary(self) -> str:
        """XML summary of available skills for context"""
```

**Skill Structure:**
```markdown
---
name: web-researcher
description: Research topics on the web
always: false
requires:
  - env: BRAVE_API_KEY
---

# Web Researcher Skill

Instructions for using web research capabilities...
```

---

## Configuration (`nanobot/config/schema.py`)

Pydantic-based configuration with nested schemas.

```python
class Config(BaseModel):
    agents: AgentsConfig
    providers: ProvidersConfig
    channels: ChannelsConfig
    tools: ToolsConfig

class AgentsConfig(BaseModel):
    defaults: AgentDefaults

class AgentDefaults(BaseModel):
    model: str = "anthropic/claude-opus-4-5"
    provider: str | None = None
    temperature: float = 0.1
    max_tokens: int = 4096
    max_iterations: int = 40
    reasoning_effort: Literal["low", "medium", "high"] | None = None
    memory_window: int = 100

class ToolsConfig(BaseModel):
    restrictToWorkspace: bool = False  # Sandbox file access
    exec: ExecConfig = ExecConfig()
    mcpServers: dict = {}

class ExecConfig(BaseModel):
    timeout: int = 60
    path_append: str | None = None
```

**Config Location:** `~/.nanobot/config.json`

---

## Execution Flows

### Gateway Mode (Multi-Channel Server)

```
┌─────────────────────────────────────────────────────────────────┐
│                      GATEWAY START                               │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Channel Start │    │ Channel Start │    │ Channel Start │
│  (Telegram)   │    │  (Discord)    │    │  (Slack)      │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ↓
                    ┌─────────────────┐
                    │   MessageBus    │
                    │  (InboundQueue) │
                    └────────┬────────┘
                              ↓
                    ┌─────────────────┐
                    │   AgentLoop     │
                    │  (Main Loop)    │
                    └────────┬────────┘
                              ↓
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│    Session    │    │    Context    │    │   Provider    │
│   Manager     │    │    Builder    │    │  (LiteLLM)    │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
                              ↓
                    ┌─────────────────┐
                    │  Tool Registry  │
                    │   (Execute)     │
                    └────────┬────────┘
                              ↓
                    ┌─────────────────┐
                    │   MessageBus    │
                    │ (OutboundQueue) │
                    └────────┬────────┘
                              ↓
                    Route to Channel
```

### Single Message Processing

```
InboundMessage received
        ↓
Get/Create Session (channel:chat_id)
        ↓
Build System Prompt
├── Identity block
├── Bootstrap files (AGENTS.md, SOUL.md, etc.)
├── Memory context (MEMORY.md)
├── Always-on skills
├── Skills summary (XML)
└── Runtime context
        ↓
Build Messages
├── System prompt
├── History (from session)
├── Runtime injection (time, channel)
└── Current message + media
        ↓
LLM Call (with tool definitions)
        ↓
┌─── Tool calls returned? ───┐
│                            │
↓ Yes                        ↓ No
Execute tools                Return content
Add results to messages             ↓
Loop back to LLM Call        Save to session
                             Consolidate if needed
                             Publish OutboundMessage
```

---

## Security Mechanisms

### Current Protections

| Mechanism | Implementation | Location |
|-----------|---------------|----------|
| Path Traversal | Allowed directory enforcement | filesystem.py |
| Dangerous Commands | Pattern blocking | shell.py |
| Parameter Validation | JSON Schema | tools/base.py |
| Output Truncation | 500 char limit | tools/ |
| Access Control | allowFrom lists | channels/base.py |
| Execution Limits | 40 iterations, 60s timeout | loop.py, shell.py |
| Workspace Sandbox | restrictToWorkspace option | config, filesystem.py |

### Shell Security (`shell.py`)

Blocked patterns:
```python
DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",      # Recursive deletion
    r"mkfs\.",             # Disk formatting
    r"diskpart",           # Windows disk management
    r"dd\s+if=",           # Raw disk writes
    r">/dev/sd",           # Device writes
    r"shutdown",           # System control
    r"reboot",
    r"poweroff",
    r":\(\)\s*\{\s*:\s*;\s*\}",  # Fork bombs
]
```

### Known Limitations (from SECURITY.md)

- ⚠️ No rate limiting
- ⚠️ API keys stored in plain text
- ⚠️ No session expiry
- ⚠️ Limited command filtering
- ⚠️ Limited audit trail
- ⚠️ **No prompt injection protection**

---

## Entry Points

### CLI Commands

```bash
# Initialize workspace
nanobot onboard

# Interactive chat
nanobot agent

# Single message
nanobot agent -m "Hello"

# Start gateway server
nanobot gateway

# Show status
nanobot status

# Manage cron jobs
nanobot cron list
nanobot cron add "0 9 * * *" "Good morning summary"
nanobot cron remove <job_id>

# Provider OAuth
nanobot provider login openai-codex

# Channel management
nanobot channels status
nanobot channels login  # WhatsApp QR
```

### Programmatic Usage

```python
from nanobot.agent.loop import AgentLoop
from nanobot.bus.queue import MessageBus
from nanobot.providers.litellm import LiteLLMProvider

bus = MessageBus()
provider = LiteLLMProvider(
    model="anthropic/claude-opus-4-5",
    api_key="sk-..."
)

agent = AgentLoop(
    bus=bus,
    provider=provider,
    workspace=Path("~/.nanobot/workspace"),
    model="anthropic/claude-opus-4-5",
)

# Process a single message
response = await agent.process_message(
    content="Hello, world!",
    channel="cli",
    chat_id="test",
)
```

---

## Architecture Summary

| Layer | Component | Responsibility |
|-------|-----------|----------------|
| **Interface** | CLI, Channels | User interaction |
| **Routing** | MessageBus | Message flow |
| **Orchestration** | AgentLoop | Main control loop |
| **Context** | ContextBuilder | Prompt assembly |
| **Persistence** | Session, Memory | State management |
| **Execution** | ToolRegistry, Tools | Capability execution |
| **Backend** | LLMProvider | LLM integration |
| **Configuration** | Config | Settings management |
| **Scheduling** | CronService, Heartbeat | Automated tasks |
| **Extension** | Skills, MCP | Capability expansion |

---

## Key Characteristics for CaMeL Integration

### Current State (Relevant to CaMeL)

1. **Single LLM Architecture**: One LLM handles both:
   - User instruction interpretation
   - Untrusted data processing (web pages, emails, files)
   - Tool execution decisions

2. **No Data Flow Tracking**: Tools execute without provenance tracking

3. **No Capability System**: All tools available equally to the agent

4. **No Control Flow Separation**: LLM determines both what to do AND processes data

5. **Extensible Tool System**: Clean registry-based design amenable to security wrapping

6. **Session-Based State**: Message history maintained per conversation

### Integration Opportunities

1. **Tool Registry**: Wrap with capability validation
2. **Context Builder**: Separate P-LLM and Q-LLM contexts
3. **Message Processing**: Insert interpreter between LLM and tools
4. **Session State**: Track capability metadata alongside messages
5. **Provider Layer**: Route to P-LLM vs Q-LLM based on context
