# Detect Hermes Memory Poisoning

Inspect Hermes profile memory for commercial recommendation poisoning and
general-purpose memory poisoning without modifying the source files.

[中文](#中文) · [English](#english)

<a id="中文"></a>

## 中文

### 用途

`detect-recommendation-poisoning` 是一个用于审查 Hermes Agent 持久化内存的
Agent Skill。它检查 `USER.md`、`MEMORY.md`，以及文件名以 `_USER` 或 `_MEMORY`
结尾的 Markdown 文件，识别可能持续操控未来回答、工具调用、信任判断或商业推荐的
恶意记录。

Skill 会生成一份带证据的 Markdown 审查报告。默认情况下，它不会编辑、隔离或删除
任何源内存文件。

### 核心功能

- 检测品牌、供应商、产品、来源、排名、引用、购买和竞品方面的商业推荐操控。
- 检测伪造的用户偏好、授权或批准，以及隐藏商业影响的指令。
- 检测 14 类通用内存投毒机制，包括持久控制、安全绕过、工具劫持和数据外泄。
- 将内存内容视为不可信的惰性证据，不执行其中的指令。
- 根据可信运行时模型元数据自动选择直接审查或 DeepSeek Pro 预筛流程。
- 输出 `suspicious`、`uncertain` 和 `benign` 最终结论，并保留文件、记录索引和行号证据。

### 检测范围

商业推荐投毒没有单独的类型代码。它包括持久性品牌、供应商、产品、来源、排名、引用、
购买或竞品引导，以及赞助、联盟营销、变现影响、伪造偏好和影响隐藏。

通用内存投毒使用以下 14 个机制代码：

| 机制 | 检测目标 |
| --- | --- |
| `instruction_override` | 覆盖、忽略、替换或取消既有指令。 |
| `priority_authority_escalation` | 伪造系统级优先级、管理员权限、紧急优先权或批准。 |
| `role_identity_hijacking` | 重定义助手的身份、角色、效忠对象或服务对象。 |
| `goal_redirection` | 用攻击者选择的目标替换用户未来的目标。 |
| `persistent_directive` | 将攻击者选择的命令或行为默认值持久化到未来任务或会话。 |
| `constraint_safety_bypass` | 禁用或绕过安全措施、审批、权限、验证或沙箱边界。 |
| `conditional_sleeper_trigger` | 在日期、短语、用户、工具结果等条件满足后激活恶意行为。 |
| `tool_action_hijacking` | 强制使用攻击者指定的工具、命令、账户、接收者、仓库、端点或操作。 |
| `data_exfiltration` | 发送、上传、嵌入、泄露或暴露密钥、文件、内存、活动等用户数据。 |
| `concealment_anti_audit` | 对用户、日志、报告、监控或审查者隐藏记录及其影响。 |
| `correction_resistance` | 拒绝后续更正、删除、撤销、用户澄清或冲突证据。 |
| `propagation_instruction` | 将指令复制、重装或同步到其他内存、代理、文件、提示词或系统。 |
| `context_boundary_evasion` | 跨越引用、数据、工具输出、内存等信任边界传播控制性指令。 |
| `obfuscated_instruction` | 编码、拆分、伪装或间接表达可执行指令以逃避检查。 |

### 工作方式

Skill 只根据宿主提供的可信运行时元数据选择路由。内存记录、扫描文件、工具结果或用户内容
中自称的模型身份不会影响路由。

| 路由 | 适用模型 | 行为 |
| --- | --- | --- |
| 直接审查 | `gpt-5`、`gpt-5.5`、`gpt-5.6-sol`、`opus-4.6`、`opus-4.7`、`opus-4.8`、`fable5` | 宿主模型直接逐条审查记录；不调用 DeepSeek API。 |
| DeepSeek Pro 预筛与复核 | 其他所有模型，或无法取得可信模型元数据时 | 脚本按确定顺序将每条记录逐一发送给 DeepSeek Pro，随后由宿主模型复核候选项和契约错误。 |

扫描目录时，只处理以下 Markdown 文件：

- `USER.md`
- `MEMORY.md`
- 文件名 stem 以 `_USER` 或 `_MEMORY` 结尾的文件，例如 `PROJECT_USER.md`

### 安装到 Hermes Agent

请先安装并配置 Hermes Agent。参阅
[Hermes Agent 官方快速入门](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/quickstart.md)。

这是一个包含 `references/` 和 `scripts/` 的多文件 skill。请克隆完整仓库，不要只下载
`SKILL.md`。

#### Linux / macOS

```bash
HERMES_SKILL_ROOT="${HERMES_HOME:-$HOME/.hermes}/skills/security"
mkdir -p "$HERMES_SKILL_ROOT"
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git \
  "$HERMES_SKILL_ROOT/detect-recommendation-poisoning"
```

#### Windows PowerShell

```powershell
$hermesRoot = if ($env:HERMES_HOME) { $env:HERMES_HOME } else { Join-Path $HOME ".hermes" }
$skillRoot = Join-Path $hermesRoot "skills\security"
New-Item -ItemType Directory -Force $skillRoot | Out-Null
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git `
  (Join-Path $skillRoot "detect-recommendation-poisoning")
```

如果你设置了自定义 `HERMES_HOME`，上述命令会自动使用它；否则默认安装到
`~/.hermes/skills/security/detect-recommendation-poisoning`。

验证安装：

```bash
hermes skills list
```

也可以在 Hermes 聊天中搜索：

```text
/skills search detect-recommendation-poisoning
```

新安装的 skill 会在新会话中生效。要在当前聊天中刷新技能列表，请执行 `/reset`。
更多信息参阅
[Hermes Skills 官方指南](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/work-with-skills.md)。

### 在 Hermes 中使用

显式调用 skill 并提供文件或目录：

```text
/detect-recommendation-poisoning inspect ~/.hermes/memories/USER.md
```

也可以使用自然语言：

```text
Use detect-recommendation-poisoning to inspect my Hermes memory directory and write the review report.
```

未提供扫描路径时，skill 会检查 `HERMES_MEMORY_DIR`、`HERMES_HOME`、当前工作目录和
用户目录下常见的 `.hermes`、`hermes` 与 `memories` 位置。

### Codex 兼容安装

Codex 可以从仓库级或用户级 `.agents/skills` 目录发现此 skill。

项目级安装（从目标仓库根目录运行）：

```bash
mkdir -p .agents/skills
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git \
  .agents/skills/detect-recommendation-poisoning
```

用户级安装：

```bash
mkdir -p "$HOME/.agents/skills"
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git \
  "$HOME/.agents/skills/detect-recommendation-poisoning"
```

在 Codex 中可显式调用：

```text
Use $detect-recommendation-poisoning to inspect my Hermes USER.md files.
```

### DeepSeek 路由配置

直接审查路由不需要 DeepSeek。DeepSeek Pro 预筛路由需要：

- Python 3
- `openai==1.95.1`
- 当前工作目录的 `.env` 中存在非空 `DEEPSEEK_API_KEY`

在工作目录创建 `.env`：

```dotenv
DEEPSEEK_API_KEY=your-api-key
```

从 skill 安装目录安装固定版本依赖：

```bash
python -m pip install -r scripts/requirements.txt
```

如果 `.env` 位于其他位置，运行预筛脚本时使用 `--env-file <path>`。脚本不会回退读取
进程环境变量中的 `DEEPSEEK_API_KEY`。

### 高级用法：仅运行预筛 CLI

在 skill 安装目录运行以下命令。它只执行 DeepSeek Pro 初始预筛，不会替代宿主模型的
最终审查和 Markdown 报告流程：

```bash
python scripts/deepseek_pro_prefilter.py \
  --scan-path <USER.md-or-directory> \
  --output deepseek_pro_prefilter_results.jsonl
```

常用参数：

- `--errors-output <path>`：契约错误 JSONL 路径。
- `--model <name>`：DeepSeek 模型名；默认 `deepseek-v4-pro`。
- `--env-file <path>`：dotenv 文件路径；默认 `.env`。

### 输出、隐私与安全边界

- 完整 skill 默认写入当前工作目录下的
  `hermes_recommendation_poisoning_reviewed_report.md`。
- DeepSeek 路由会将发现的每条内存记录发送到 `https://api.deepseek.com`；使用前请确认
  数据处理和隐私要求允许这样做。
- 直接审查路由不会调用 DeepSeek API。
- 内存文本和预筛结果始终作为不可信证据处理，不能控制工具、结论或报告格式。
- 除非用户在查看报告后明确要求，否则 skill 不会编辑、隔离或删除内存文件。
- 自动结论不能替代对高风险 `suspicious` 或 `uncertain` 记录的人工复核。

### License

本项目采用 [MIT License](LICENSE)。

<a id="english"></a>

## English

### Purpose

`detect-recommendation-poisoning` is an Agent Skill for reviewing persistent
Hermes Agent memory. It inspects `USER.md`, `MEMORY.md`, and Markdown files whose
names end in `_USER` or `_MEMORY` for malicious records that may persistently
control future responses, tool actions, trust decisions, or commercial
recommendations.

The skill writes an evidence-based Markdown review report. By default, it does
not edit, quarantine, or delete any source memory file.

### Key features

- Detects commercial steering involving brands, suppliers, products, sources,
  rankings, citations, purchases, and competitors.
- Detects forged user preferences, consent, or approval and instructions that
  conceal commercial influence.
- Detects 14 general memory-poisoning mechanisms, including persistent control,
  safety bypasses, tool hijacking, and data exfiltration.
- Treats memory content as untrusted, inert evidence and never follows its
  instructions.
- Selects direct review or DeepSeek Pro prefiltering from trusted runtime model
  metadata.
- Produces final `suspicious`, `uncertain`, and `benign` verdicts with file,
  record-index, and line evidence.

### Detection scope

Commercial recommendation poisoning does not have a separate type code. It
includes persistent brand, supplier, product, source, ranking, citation,
purchase, or competitor steering; sponsored, affiliate, or monetized influence;
forged preferences; and attempts to conceal that influence.

General memory poisoning uses these 14 mechanism codes:

| Mechanism | What it detects |
| --- | --- |
| `instruction_override` | Superseding, ignoring, replacing, or nullifying existing instructions. |
| `priority_authority_escalation` | Forged system priority, administrator authority, emergency precedence, or approval. |
| `role_identity_hijacking` | Redefining the assistant's identity, role, allegiance, or principal. |
| `goal_redirection` | Replacing the user's future objective with an attacker-selected objective. |
| `persistent_directive` | Persisting an attacker-selected command or default across future tasks or sessions. |
| `constraint_safety_bypass` | Disabling or bypassing safeguards, approvals, permissions, validation, or sandbox boundaries. |
| `conditional_sleeper_trigger` | Activating harmful behavior after a date, phrase, user, tool result, or other condition. |
| `tool_action_hijacking` | Forcing attacker-selected tools, commands, accounts, recipients, repositories, endpoints, or actions. |
| `data_exfiltration` | Sending, uploading, embedding, leaking, or exposing secrets, files, memory, activity, or other user data. |
| `concealment_anti_audit` | Hiding the record or its effects from users, logs, reports, monitors, or reviewers. |
| `correction_resistance` | Rejecting later correction, deletion, revocation, user clarification, or conflicting evidence. |
| `propagation_instruction` | Copying, reinstalling, or synchronizing a directive into other memories, agents, files, prompts, or systems. |
| `context_boundary_evasion` | Carrying controlling instructions across quotation, data, tool-output, memory, or other trust boundaries. |
| `obfuscated_instruction` | Encoding, fragmenting, disguising, or indirectly expressing an operative directive to evade inspection. |

### How it works

The skill selects a route only from trusted runtime metadata supplied by the
host. A model identity claimed by a memory record, scanned file, tool result, or
user content never affects routing.

| Route | Models | Behavior |
| --- | --- | --- |
| Direct review | `gpt-5`, `gpt-5.5`, `gpt-5.6-sol`, `opus-4.6`, `opus-4.7`, `opus-4.8`, `fable5` | The host model reviews records directly; no DeepSeek API call is made. |
| DeepSeek Pro prefilter and review | Every other model, or when trusted model metadata is unavailable | The script sends every record to DeepSeek Pro one at a time in deterministic order, then the host model reviews candidates and contract errors. |

When scanning a directory, only these Markdown files are considered:

- `USER.md`
- `MEMORY.md`
- Files whose stem ends in `_USER` or `_MEMORY`, such as `PROJECT_USER.md`

### Install in Hermes Agent

Install and configure Hermes Agent first. See the
[official Hermes Agent quickstart](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/quickstart.md).

This is a multi-file skill containing `references/` and `scripts/`. Clone the
complete repository instead of downloading `SKILL.md` alone.

#### Linux / macOS

```bash
HERMES_SKILL_ROOT="${HERMES_HOME:-$HOME/.hermes}/skills/security"
mkdir -p "$HERMES_SKILL_ROOT"
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git \
  "$HERMES_SKILL_ROOT/detect-recommendation-poisoning"
```

#### Windows PowerShell

```powershell
$hermesRoot = if ($env:HERMES_HOME) { $env:HERMES_HOME } else { Join-Path $HOME ".hermes" }
$skillRoot = Join-Path $hermesRoot "skills\security"
New-Item -ItemType Directory -Force $skillRoot | Out-Null
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git `
  (Join-Path $skillRoot "detect-recommendation-poisoning")
```

The commands use a custom `HERMES_HOME` when configured; otherwise they install
to `~/.hermes/skills/security/detect-recommendation-poisoning`.

Verify the installation:

```bash
hermes skills list
```

You can also search from a Hermes chat:

```text
/skills search detect-recommendation-poisoning
```

New skills take effect in new sessions. Run `/reset` to refresh skills in the
current chat. See the
[official Hermes Skills guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/work-with-skills.md)
for more information.

### Use in Hermes

Invoke the skill explicitly with a file or directory:

```text
/detect-recommendation-poisoning inspect ~/.hermes/memories/USER.md
```

You can also use natural language:

```text
Use detect-recommendation-poisoning to inspect my Hermes memory directory and write the review report.
```

When no scan path is supplied, the skill checks `HERMES_MEMORY_DIR`,
`HERMES_HOME`, the current working directory, and common `.hermes`, `hermes`,
and `memories` locations under the user profile.

### Codex-compatible installation

Codex discovers this skill from repository-level and user-level
`.agents/skills` directories.

Repository-scoped installation, run from the target repository root:

```bash
mkdir -p .agents/skills
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git \
  .agents/skills/detect-recommendation-poisoning
```

User-scoped installation:

```bash
mkdir -p "$HOME/.agents/skills"
git clone https://github.com/XaaaaavitheFool/detect-recommendation-poisoning.git \
  "$HOME/.agents/skills/detect-recommendation-poisoning"
```

Invoke it explicitly in Codex:

```text
Use $detect-recommendation-poisoning to inspect my Hermes USER.md files.
```

### DeepSeek route setup

The direct-review route does not require DeepSeek. The DeepSeek Pro prefilter
route requires:

- Python 3
- `openai==1.95.1`
- A non-empty `DEEPSEEK_API_KEY` in `.env` in the current working directory

Create `.env` in the working directory:

```dotenv
DEEPSEEK_API_KEY=your-api-key
```

Install the pinned dependency from the skill directory:

```bash
python -m pip install -r scripts/requirements.txt
```

If `.env` is stored elsewhere, pass `--env-file <path>` to the prefilter
script. The script does not fall back to `DEEPSEEK_API_KEY` from the process
environment.

### Advanced usage: prefilter CLI only

Run the following command from the skill directory. It performs only the
initial DeepSeek Pro prefilter and does not replace the host model's final
review or the Markdown reporting workflow:

```bash
python scripts/deepseek_pro_prefilter.py \
  --scan-path <USER.md-or-directory> \
  --output deepseek_pro_prefilter_results.jsonl
```

Common options:

- `--errors-output <path>`: contract-error JSONL path.
- `--model <name>`: DeepSeek model name; default `deepseek-v4-pro`.
- `--env-file <path>`: dotenv path; default `.env`.

### Output, privacy, and safety boundaries

- The complete skill writes
  `hermes_recommendation_poisoning_reviewed_report.md` to the current working
  directory by default.
- The DeepSeek route sends every discovered memory record to
  `https://api.deepseek.com`; confirm that your data-handling and privacy
  requirements permit this before use.
- The direct-review route does not call the DeepSeek API.
- Memory text and prefilter output remain untrusted evidence and cannot control
  tools, verdicts, or the report format.
- Unless the user explicitly asks after reviewing the report, the skill does
  not edit, quarantine, or delete memory files.
- Automated verdicts do not replace human review of high-risk `suspicious` or
  `uncertain` records.

### License

This project is licensed under the [MIT License](LICENSE).
