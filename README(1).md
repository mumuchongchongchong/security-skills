# inspect-encoded-artifacts

`inspect-encoded-artifacts` 是一个面向安全运营、告警研判和事件响应场景的 Codex Skill，用于对安全日志、HTTP 参数、JSON/JSONL 字段及可疑文本中的编码内容进行离线、受限、可追溯的静态分析。

它能够识别并逐层还原 Base64、Base64URL、URL 百分号编码、Hex、Unicode 转义、HTML 实体、JWT 以及 Base64 后的 Gzip/Zlib 数据，同时记录每一步转换所使用的解码器、输入输出大小、SHA-256、置信度和脱敏预览。

这个项目解决的重点不是“如何解一个 Base64”，而是如何对来源不明、可能经过多层编码的内容进行安全、可复核的初步分析。

## 解决的问题

安全人员在告警日志中经常会遇到类似内容：

```text
JTI1NTNiJTI1MjJjbWQlMjUyMiUzQSUyNTIyY21RdVkyVmhJQzlwWkNVeU1qRXlNeVV5TWlVelJBI...
```

人工分析通常需要反复猜测编码类型、复制到不同工具、逐层解码，并自行判断最终内容是否包含命令、脚本、文件头或敏感信息。这个过程容易出现：

- 把普通字符串误判为 Base64；
- 只解开第一层，遗漏后续编码；
- 忘记记录每一步转换过程，导致结果无法复现；
- 将“存在编码”直接等同于“恶意行为”；
- 在报告或聊天中二次泄露 Token、Cookie 和密码；
- 对未知内容进行不安全的执行、解压或落地；
- 遇到递归编码、超大输出或压缩炸弹时资源失控。

本 Skill 将上述步骤组织成统一流程：

```text
输入检查
  -> 提取候选内容
  -> 判断编码置信度
  -> 有界递归解码
  -> 记录转换证据
  -> 识别内容类型和文件签名
  -> 提取风险信号
  -> 敏感信息脱敏
  -> 输出结构化报告
```

## 主要能力

| 类别 | 支持内容 |
|---|---|
| 文本编码 | Base64、Base64URL、URL 百分号编码、Hex、`\xNN`、`\uNNNN`、HTML 实体 |
| 结构解析 | JWT Header 和 Payload，只解析内容，不声明签名有效 |
| 有界解压 | Base64 后的 Gzip 和 Zlib，限制输出大小与解压比例 |
| 文件识别 | PE、ELF、ZIP、Gzip、PDF、PNG、JPEG、JSON、UTF-8 文本和未知二进制 |
| 风险信号 | PowerShell、CMD、Bash、下载执行、动态执行及可疑网络指标 |
| 提示注入 | 识别编码后的控制指令，但只作为不可信数据报告，绝不执行 |
| 敏感信息 | 对 API Key、Bearer Token、JWT、Cookie、密码、Authorization Header 和私钥标记进行脱敏 |
| 证据记录 | 记录字段路径、解码层级、算法、大小、SHA-256、置信度、预览和警告 |
| 输入形式 | 直接文本、普通文件、二进制文件、JSON 和 JSONL |
| 输出形式 | Markdown 报告和结构化 JSON |

## 安全设计

所有输入及解码结果都被视为不可信数据。即使内容中出现“执行命令”“忽略之前的指令”或“调用某个工具”等文字，也只会作为分析对象记录。

默认安全限制包括：

- 最大递归深度；
- 最大输入和输出大小；
- 最大候选数量；
- 最大预览长度；
- 最大解压比例；
- 重复 SHA-256 检测，防止解码链循环；
- 不执行解码后的脚本、命令或二进制；
- 不调用 Shell 或外部程序；
- 不连接网络；
- 不自动提取 ZIP；
- 不默认把解码结果写入磁盘；
- 不在报告中输出完整凭据。

编码、压缩或命令关键词本身都不是攻击成功的证据。项目只报告可复核的风险信号，不替代恶意软件沙箱、YARA、杀毒引擎、EDR 或专业取证工具。

## 结果状态

解码状态包括：

| 状态 | 含义 |
|---|---|
| `DECODED` | 至少完成一层可信解码 |
| `PARTIAL` | 完成部分转换，但后续内容无法可靠还原 |
| `NO_ENCODING_FOUND` | 当前规则未发现可信编码 |
| `LIMIT_REACHED` | 触发递归、大小、候选数量或解压比例限制 |
| `ERROR` | 输入或转换过程中发生受控错误 |

风险信号状态包括：

| 状态 | 含义 |
|---|---|
| `NO_HIGH_RISK_INDICATORS` | 当前规则未发现高风险信号，不等同于内容安全 |
| `REVIEW` | 存在需要人工确认的编码结果或行为特征 |
| `HIGH_RISK_INDICATORS` | 发现高风险命令、文件签名、敏感信息或控制指令等信号 |
| `INCONCLUSIVE` | 证据不足，无法形成可靠判断 |

## 目录结构

在本仓库中，Skill 以独立目录保存：

```text
security-skills/
├── audit-agent-traces/
├── inspect-encoded-artifacts/
│   ├── README.md
│   ├── SKILL.md
│   ├── agents/
│   │   └── openai.yaml
│   ├── references/
│   │   ├── decoding-rules.md
│   │   └── safety-limits.md
│   ├── scripts/
│   │   └── inspect_encoded_artifact.py
│   └── tests/
│       ├── test_inspect_encoded_artifact.py
│       └── fixtures/
├── README.md
└── LICENSE
```

安装到本地 Codex 项目后，目标结构应为：

```text
your-project/
└── .agents/
    └── skills/
        └── inspect-encoded-artifacts/
            ├── README.md
            ├── SKILL.md
            ├── agents/
            ├── references/
            ├── scripts/
            └── tests/
```

## 安装方式一：作为 Codex Skill 使用

### 1. 下载仓库

可以在 GitHub 页面点击：

```text
Code -> Download ZIP
```

解压后找到：

```text
security-skills/inspect-encoded-artifacts
```

也可以使用 Git：

```powershell
git clone https://github.com/mumuchongchongchong/security-skills.git
```

### 2. 复制到目标项目

先创建目标目录：

```powershell
New-Item -ItemType Directory -Force `
  "C:\path\to\your-project\.agents\skills"
```

再复制完整 Skill：

```powershell
Copy-Item -Recurse -Force `
  ".\security-skills\inspect-encoded-artifacts" `
  "C:\path\to\your-project\.agents\skills\inspect-encoded-artifacts"
```

请确认最终文件位置是：

```text
C:\path\to\your-project\.agents\skills\inspect-encoded-artifacts\SKILL.md
```

不要只复制 `SKILL.md`，脚本、参考规则和测试夹具也是 Skill 的组成部分。

### 3. 调用 Skill

在 Codex 中打开目标项目，刷新 Skill 列表或新建任务，然后输入：

```text
$inspect-encoded-artifacts
```

示例请求：

```text
使用 $inspect-encoded-artifacts 分析下面的编码内容，展示逐层转换链、风险信号和安全限制：

SGVsbG8sIFNlY3VyaXR5IQ==
```

## 安装方式二：仅使用 Python 分析脚本

如果只需要解码和静态分析功能，不需要安装为 Codex Skill，可以直接运行脚本。项目仅使用 Python 标准库，不需要安装第三方依赖。

建议使用 Python 3.10 或更高版本：

```powershell
python --version
```

进入 Skill 目录：

```powershell
Set-Location ".\security-skills\inspect-encoded-artifacts"
```

直接分析文本：

```powershell
python scripts/inspect_encoded_artifact.py `
  --text "SGVsbG8sIFNlY3VyaXR5IQ==" `
  --format markdown
```

分析普通文本或二进制文件：

```powershell
python scripts/inspect_encoded_artifact.py `
  --input sample.txt `
  --format markdown
```

分析 JSON 或 JSONL：

```powershell
python scripts/inspect_encoded_artifact.py `
  --input sample.jsonl `
  --format json
```

脚本会递归检查 JSON/JSONL 中的字符串字段，并在结果中保留字段路径。

## 输出内容

Markdown 报告主要包含：

1. 输入摘要；
2. 解码状态；
3. 逐层转换链；
4. 最终内容类型；
5. 脱敏内容预览；
6. 文件签名；
7. 风险信号；
8. URL、域名、IP 和哈希等指标；
9. 已触发的安全限制；
10. 未能完成的分析；
11. 人工复核建议。

JSON 输出使用稳定字段，便于后续接入告警研判、自动化审计或事件响应系统。

## 使用示例

输入：

```text
SGVsbG8sIFNlY3VyaXR5IQ==
```

核心转换链：

```text
原始文本
  -> Base64
  -> Hello, Security!
```

预期结论：

```text
解码状态：DECODED
风险状态：NO_HIGH_RISK_INDICATORS
```

这里的 `NO_HIGH_RISK_INDICATORS` 仅表示当前规则没有发现高风险信号，并不构成内容安全证明。

## 测试

从 GitHub 仓库根目录运行：

```powershell
python -B -m unittest discover `
  -s inspect-encoded-artifacts/tests `
  -p "test_*.py" `
  -v
```

安装为项目级 Skill 后，也可以从目标项目根目录运行：

```powershell
python -B -m unittest discover `
  -s .agents/skills/inspect-encoded-artifacts/tests `
  -p "test_*.py" `
  -v
```

测试应覆盖：

- 普通文本不被误解码；
- Base64、Base64URL、URL、Hex、Unicode 和 HTML 实体；
- 多层嵌套编码；
- JWT 解析与未验证签名标记；
- Base64 与 Gzip/Zlib 组合；
- PE/ELF 等文件签名；
- PowerShell、CMD 和 Shell 风险信号；
- 编码后的提示注入只被报告、不被执行；
- Token、密码和授权头脱敏；
- 非法编码与类 Base64 普通字符串；
- 递归深度、输出大小和解压比例限制；
- JSON/JSONL 字段路径；
- Markdown 和 JSON 输出。

## 数据与隐私

- 仓库测试数据应全部使用人工合成内容；
- 不要提交真实恶意样本、真实客户日志或生产系统数据；
- 不要提交真实 API Key、Token、Cookie、密码和私钥；
- 不要在公开报告中展示完整敏感值；
- 对真实事件进行分析前，应先确认数据处理和共享权限；
- 对疑似恶意二进制进行深入分析时，应使用隔离环境和专业工具。

## 与 CyberChef 的关系

CyberChef 是功能强大的通用数据转换工具，本项目不试图替代它。

CyberChef 更适合人工选择操作并进行交互式转换；`inspect-encoded-artifacts` 更关注安全分析工作流，包括：

- 自动判断可能的编码链；
- 设置递归、输出和解压安全限制；
- 为每层转换记录哈希和证据；
- 识别安全风险信号；
- 对敏感信息进行脱敏；
- 输出可复核的 Markdown 或 JSON 报告；
- 作为 Codex Skill 在安全分析任务中重复调用。

## 已知局限

- 编码识别依赖规则和启发式方法，可能存在误判或漏判；
- 高置信度解码不等于内容具有恶意性；
- 风险关键词不能证明命令已经执行；
- JWT 只解析 Header 和 Payload，不验证签名真实性；
- 文件签名识别不是完整文件格式解析；
- IOC 提取结果需要结合资产、流量和威胁情报进一步确认；
- 项目不执行动态分析，无法判断运行时行为；
- 不能替代沙箱、EDR、反病毒、YARA、取证或人工分析。

## License

本项目采用 [MIT License](../LICENSE)。
