# Clawper 🦅

**Autonomous & Unattended CTF Wrapper for Claude Code**

Clawper is an autonomous wrapper built on top of **Claude Code** (`claude` CLI / agents) designed to independently solve Capture The Flag (CTF) challenges, Hack The Box (HTB) machines, Pro Labs, TryHackMe boxes, and penetration testing scenarios without requiring human intervention.

---

## 🚀 Key Features

- **Relentless Autonomous Loop**: Never stops or gives up until all configured success conditions are verified. If the agent claims it is done prematurely, gets stuck, errors out, or requests confirmation, Clawper evaluates ground-truth conditions, generates an adaptive tactical nudge, and drives the agent forward.
- **Configurable Success Conditions**:
  - **Flag Detection**: Automatic extraction and verification using built-in patterns (HTB MD5 format, `HTB{...}`, `THM{...}`, `flag{...}`, `CTF{...}`) or custom regex patterns.
  - **User & Root Separation**: Distinction between user-level and root-level flags.
  - **Root Verification**: Proof of `root` / `SYSTEM` privilege escalation via output signature matching (`uid=0(root)`, `NT AUTHORITY\SYSTEM`), proof files, or verification commands.
  - **Required Files & Loot**: Ensures critical artifacts, hashes, or proof files are retrieved in the workspace.
  - **Custom Verification Scripts**: Hook in custom validation scripts with expected exit codes.
- **Intelligent Prompting & Tactical Nudges**:
  - Phase-aware prompts (Reconnaissance → Service Enumeration → Initial Access → Privilege Escalation → Flag Capture).
  - Anti-giving-up and anti-stalling safeguards: detects lack of progress across iterations and injects pivoting directives.
- **Workspace & State Persistence**:
  - Organized directory structure (`recon/`, `exploits/`, `loot/`, `flags/`, `notes/`, `logs/`).
  - Persistent state saving and seamless session resumption across process restarts.
  - Automated Markdown CTF writeup (`WRITEUP.md`) and machine-readable JSON execution reports (`report.json`).
- **Flexible Agent Drivers**:
  - **Claude Code CLI Driver**: Direct integration with `claude -p "<prompt>" --dangerously-skip-permissions` with session resumption.
  - **Mock Agent Driver**: Scriptable and deterministic driver for tests, CI, and simulations.
  - **Command Agent Driver**: Custom external agent CLI runner.

---

## 📦 Installation

```bash
git clone https://github.com/h4n0sh1/Clawper.git
cd Clawper
pip install -e .
```

---

## ⚡ Quick Start

### 1. Simple Command Line Execution

Target an IP with 2 required flags (User + Root) and root privilege verification:

```bash
clawper run --target 10.10.11.200 --box-name "Sau" --flags 2 --require-root
```

### 2. Custom Mission Prompt & Flag Pattern

```bash
clawper run \
  --target 10.10.11.50 \
  --prompt "Exploit the web application, escalate to root, and capture all flags." \
  --flag-pattern "HTB\{[a-zA-Z0-9_\-]+\}" \
  --flags 2 \
  --workspace ./htb_sau_run
```

### 3. Using Configuration Files

Generate a template configuration:

```bash
clawper init -o clawper.yaml
```

Run using the configuration file:

```bash
clawper run --config clawper.yaml
```

---

## 🛠️ Configuration Example (`clawper.yaml`)

```yaml
prompt: "Root the target box, obtain all flags (user and root), and document your steps."
target:
  ip: "10.10.11.150"
  box_name: "ExampleBox"
  platform: "htb"
  credentials:
    admin: "password123"
  hints:
    - "Web application on port 8080 contains a file upload vulnerability"

flags:
  required_count: 2
  require_user_flag: true
  require_root_flag: true
  patterns:
    - "[a-f0-9]{32}"
    - "HTB\\{[a-zA-Z0-9_\\-\\.\\!@#\\$%\\^&\\*]+\\}"

root:
  enabled: true
  verification_method: "output_check"
  root_signatures:
    - "uid=0(root)"
    - "NT AUTHORITY\\SYSTEM"

agent:
  driver_type: "claude_code"
  binary_path: "claude"
  cli_flags:
    - "--dangerously-skip-permissions"
  timeout_per_run: 600

execution:
  max_iterations: 0      # 0 = Unlimited (never stop until solved)
  loop_delay: 2.0
  writeup_path: "WRITEUP.md"
  auto_nudge: true

workspace_dir: "./clawper_workspace"
```

---

## 📊 Inspecting Sessions & Reports

Check the status and captured flags of any workspace:

```bash
clawper status --workspace ./clawper_workspace
```

Generate / view the CTF writeup:

```bash
clawper report --workspace ./clawper_workspace
```

---

## 🧪 Testing

Run unit and integration test suite:

```bash
pytest -v
```

---

## 📜 License

MIT License.
