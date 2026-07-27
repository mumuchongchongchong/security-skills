# audit-agent-traces

`audit-agent-traces` 是一个项目级 Codex Skill，用于离线重建和审计 Agent 执行轨迹。它读取 JSON、JSONL 或带阶段前缀的粘贴日志，重建以下事件链：

```text
用户输入 -> 模型规划 -> 工具调用 -> 工具返回 -> 最终回答
```

审计过程只读取本地数据，不连接真实系统，不重放工具调用，也不会执行日志中的命令或提示。所有日志字符串都被视为不可信数据。

## 检测规则

| 规则 | 严重性 | 检测内容 |
|---|---|---|
| ATR-001 | high | 不可信工具返回中的提示注入、权限冒充、敏感信息外传或命令执行指令 |
| ATR-002 | high | 工具调用不在策略 `allowed_tools` 精确名称白名单中 |
| ATR-003 | critical | 工具参数、工具返回或最终回答中的密码、Token、API Key、Cookie、会话值或私钥标记 |
| ATR-004 | high | 删除、写入、发送、发布、部署、转账或命令执行等高风险调用缺少关联审批 |
| ATR-005 | medium | 相同工具及规范化参数重复调用超过 `max_repeated_calls` |
| ATR-006 | high | 工具失败、结果缺失、状态未知或证据冲突时，最终回答仍声称确认或处置完成 |

每条发现包含 `rule_id`、`severity`、`event_id`、`evidence`、`reason` 和 `recommendation`。密钥证据只显示类型、掩码和字段位置。

## 目录结构

```text
security-skills/
├── .agents/
│   └── skills/
│       └── audit-agent-traces/
│           ├── SKILL.md
│           ├── agents/
│           │   └── openai.yaml
│           ├── references/
│           │   └── risk-rules.md
│           ├── scripts/
│           │   └── audit_trace.py
│           └── tests/
│               ├── test_audit_trace.py
│               └── fixtures/
│                   ├── injection_and_secret.jsonl
│                   ├── safe_trace.jsonl
│                   └── unauthorized_tool.jsonl
├── .gitignore
├── LICENSE
└── README.md
```

## 安装

要求 Python 3.10 或更高版本。运行时仅使用 Python 标准库。

将 Skill 目录复制到目标项目的 `.agents/skills/`：

```powershell
Copy-Item -Recurse audit-agent-traces `
  path\to\your-project\.agents\skills\audit-agent-traces
```

也可以克隆本仓库并保留现有项目级目录结构。重新打开或刷新 Codex 项目后，可通过 `$audit-agent-traces` 调用该 Skill。

## 使用

在 Skill 目录中审计 JSON 或 JSONL：

```powershell
python scripts/audit_trace.py --input trace.jsonl
python scripts/audit_trace.py --input trace.jsonl --format markdown
```

使用策略文件：

```json
{
  "allowed_tools": ["read_file", "fetch_url"],
  "high_risk_tools": ["write_file", "shell_command"],
  "max_repeated_calls": 3
}
```

```powershell
python scripts/audit_trace.py `
  --input trace.jsonl `
  --policy policy.json `
  --format markdown
```

通过标准输入审计粘贴日志：

```powershell
Get-Content pasted-trace.txt |
  python scripts/audit_trace.py --input - --format markdown
```

使用仓库内合成夹具：

```powershell
python scripts/audit_trace.py `
  --input tests/fixtures/injection_and_secret.jsonl `
  --format markdown
```

报告包含风险摘要、事实/推断/缺失信息、事件时间线、风险发现表和未决证据。未提供 `allowed_tools` 时，ATR-002 无法完成判断，报告会保留相应未决证据。

## 测试

从仓库根目录运行全部测试：

```powershell
python -B -m unittest discover `
  -s .agents/skills/audit-agent-traces/tests `
  -p "test_*.py" `
  -v
```

测试覆盖安全轨迹、未授权工具、缺少审批、提示注入、敏感字段脱敏、重复调用、证据不足的确定性结论、聚合 JSON、未知结构和 Markdown 输出。

## 数据与安全

- 仓库只包含合成测试数据，不包含真实告警日志、真实 IP、客户信息或生产系统数据。
- 测试占位值使用 `EXAMPLE_REDACTED_VALUE`、`example-user` 和保留域名 `invalid.example`。
- 不要把真实凭据、Cookie、生产日志或客户数据提交到仓库。
- `.gitignore` 排除了常见环境文件、私钥、日志、虚拟环境和本地编辑器数据。

## 已知局限

- 检测依赖规则和启发式模式，可能存在误报或漏报。
- 日志结构归一化覆盖常见事件模型；无法识别的结构返回 `INCONCLUSIVE`。
- 未提供 `allowed_tools` 时无法完成 ATR-002 授权判断。
- 高风险工具识别依赖策略名称和工具名动词，无法理解所有自定义工具语义。
- 审批只接受明确且可关联的记录，不从用户原始请求中推断授权。
- 敏感信息检测不是完整的数据防泄漏系统，不能替代凭据轮换、访问控制或人工复核。
- `NO_FINDINGS` 仅表示现有证据和配置规则未发现问题，不等同于系统安全证明。

## License

本项目采用 [MIT License](LICENSE)。
