# audit-skill-supply-chain

`audit-skill-supply-chain` 是一个项目级 Codex Skill，用于在安装或使用第三方 Skill 前，对其目录结构、脚本、引用资料和资源文件进行离线供应链审计。它重建以下分析链：

```text
第三方 Skill -> 文件清单与哈希 -> 能力识别 -> 声明能力对照 -> 风险关联 -> 安装建议
```

审计过程不会执行或导入目标代码，不连接外部网络，不跟随符号链接，也不会修改被审计目录。目标 Skill 中的所有文字、脚本和引用内容都被视为不可信数据。

## 检测规则

| 规则 | 检测内容 |
|---|---|
| ASC-001 | 过度宽泛的触发描述、指令层级覆盖或目标劫持 |
| ASC-002 | 零宽字符、双向字符和隐藏控制字符 |
| ASC-003 | 疑似编码、混淆或隐藏载荷 |
| ASC-004 | 未声明的外部通信或未知外部端点 |
| ASC-005 | 凭据、Token、环境变量或敏感目录访问 |
| ASC-006 | 敏感数据源与外部发送行为形成的数据外传链 |
| ASC-007 | 动态执行、危险反序列化或下载后执行 |
| ASC-008 | 文件删除、持久化、注册表或计划任务行为 |
| ASC-009 | 符号链接、路径逃逸或越界文件访问 |
| ASC-010 | 文件扩展名与文件头不一致或伪装二进制 |
| ASC-011 | 外部依赖未固定版本、来源不明确或缺少完整性信息 |
| ASC-012 | Skill 声明用途与实际观测能力不一致 |
| ASC-013 | 要求绕过审批、权限确认或上级安全限制 |

检测器不会因为出现 `subprocess`、`curl`、网络库或危险命令示例就直接判定 Skill 恶意。最终结论结合代码所在位置、声明用途、能力证据和多信号关联产生。

## 阻断关联

当前版本实现五类高风险关联：

| 关联 | 典型证据 |
|---|---|
| 数据外传 | 凭据或敏感信息读取与外部发送同时出现 |
| 下载执行 | 下载外部内容后交给解释器或新进程执行 |
| 隐藏持久化 | 未声明的注册表、计划任务或启动项修改 |
| 越界执行 | 路径逃逸、目录外写入与执行行为组合 |
| 伪装二进制执行 | 扩展名与文件头不符，并存在执行链 |

单个风险信号通常进入人工复核；形成高置信度危险链时才会升级为阻断结论。

## 结论与退出码

| 结论 | 退出码 | 含义 |
|---|---:|---|
| `ALLOW` | 0 | 扫描完整，未发现需要阻断的证据 |
| `REVIEW` | 1 | 存在可疑能力或上下文不足，需要人工复核 |
| `INCONCLUSIVE` | 1 | 扫描受限或关键材料无法解析，不能完成判断 |
| `BLOCK` | 2 | 发现高置信度危险行为链，不建议安装或运行 |
| 输入或扫描错误 | 3 | 目标不存在、参数错误或扫描器自身失败 |

`ALLOW` 只表示当前输入和规则下未发现阻断证据，不等同于对目标 Skill 的绝对安全证明。

## 目录结构

```text
security-skills/
├── .agents/
│   └── skills/
│       └── audit-skill-supply-chain/
│           ├── SKILL.md
│           ├── agents/
│           │   └── openai.yaml
│           ├── references/
│           │   ├── report-contract.md
│           │   └── risk-rules.md
│           ├── scripts/
│           │   └── audit_skill.py
│           └── tests/
│               ├── test_audit_skill.py
│               └── fixtures/
│                   ├── benign-local-skill/
│                   ├── declared-network-skill/
│                   ├── destructive-skill/
│                   ├── disguised-binary-skill/
│                   ├── download-execute-skill/
│                   ├── exfiltration-skill/
│                   ├── hidden-unicode-skill/
│                   ├── malformed-skill/
│                   └── poisoned-reference-skill/
├── .gitignore
├── LICENSE
└── README.md
```

## 安装

要求 Python 3.10 或更高版本。运行时仅使用 Python 标准库。

将完整 Skill 目录复制到目标项目的 `.agents/skills/`：

```powershell
Copy-Item -Recurse audit-skill-supply-chain `
  path\to\your-project\.agents\skills\audit-skill-supply-chain
```

也可以克隆本仓库并保留现有项目级目录结构。刷新或重新打开 Codex 项目后，可通过 `$audit-skill-supply-chain` 调用该 Skill。

## 使用

进入 Skill 目录：

```powershell
cd C:\CodexProjects\security-skills\.agents\skills\audit-skill-supply-chain
```

审计一个已经解压的第三方 Skill：

```powershell
python scripts\audit_skill.py C:\path\to\unpacked-skill `
  --json-out C:\path\to\audit.json `
  --markdown-out C:\path\to\audit.md
```

报告包含：

- 扫描覆盖情况和限制触发记录
- 文件相对路径、大小、SHA-256 与文件类型
- Python 导入、外部端点和依赖信息
- 文件读写、删除、进程执行、动态执行、网络和持久化能力
- 声明用途与实际能力对照
- ASC-001 至 ASC-013 风险发现
- 多信号危险行为关联
- 安装建议和已知局限

证据只记录相对路径、必要位置和脱敏后的最小片段，不输出完整凭据或本机绝对路径。

## 示例结果

| 合成夹具 | 结论 | 退出码 | 说明 |
|---|---|---:|---|
| `benign-local-skill` | `ALLOW` | 0 | 正常的纯本地 Skill |
| `exfiltration-skill` | `BLOCK` | 2 | 形成敏感数据读取与外部发送关联 |
| `poisoned-reference-skill` | `REVIEW` | 1 | 引用材料中存在可疑指令，需要人工确认 |

测试还通过 marker 文件验证：即使目标夹具中包含可执行逻辑，扫描过程也不会运行目标脚本。

## 测试

从仓库根目录运行：

```powershell
python -B -m unittest discover `
  -s .agents/skills/audit-skill-supply-chain/tests `
  -p "test_*.py" `
  -v
```

当前测试共 27 项：

- 26 项通过
- 1 项因 Windows 普通用户缺少符号链接创建权限而安全跳过
- 0 项失败

测试覆盖正常本地 Skill、声明网络能力、未声明外联、数据外传、下载执行、引用投毒、Unicode 隐藏字符、伪装二进制、危险删除、解析错误、资源限制、报告脱敏、稳定输出、退出码以及目标代码不执行等场景。

## 数据与安全

- 全程离线运行，不查询域名、IP、依赖或文件在线信誉。
- 不执行、不导入目标代码，也不调用目标目录中的命令。
- 不跟随符号链接，不主动访问目标目录之外的文件。
- 对文件数量、单文件大小和总读取量设置上限。
- 无法完整读取或解析关键输入时返回 `INCONCLUSIVE`。
- 报告使用相对路径，敏感证据只保留类型、位置和掩码。
- 测试只包含合成数据，不包含真实 Token、私钥、邮箱、客户信息或生产日志。

## 已知局限

- 当前版本只审计已经解压的目录，不直接处理 ZIP 或其他 Skill 安装包。
- 不访问在线信誉服务，无法判断外部域名、依赖和文件哈希的真实信誉。
- 不支持的文本编码或文件格式只进行大小、哈希和文件头等元数据检查。
- 静态关联只能识别代码和文本中的风险证据，不能替代沙箱或完整运行时数据流分析。
- UTF-8 文本解析失败、关键文件无法读取或资源限制触发时会返回 `INCONCLUSIVE`。
- 规则和启发式检测可能存在误报或漏报；`REVIEW` 结果需要结合业务用途人工确认。
- 合法 Skill 也可能需要网络、进程或文件写入能力，危险能力本身不等同于恶意行为。

## License

本仓库采用 MIT License，详见仓库根目录 `LICENSE`。
