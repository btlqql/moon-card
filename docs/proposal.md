# MoonCard项目申报书

账号：**btlqql**；项目：MoonCard；版本：**0.3.0**；日期：2026-10-30；团队：单人；主要语言：MoonBit；许可：Apache-2.0。

## 一、项目名称与摘要

**MoonCard：支持APDU过程恢复、应用状态跟踪与EMV数据约束核对的离线交易审计库。**

项目面向终端开发、卡片交互脚本调试和交易日志回归。输入是按方向记录的命令APDU与响应APDU，或单独的TLV、APDU数据；核心先解析字节与协议对象，再处理61xx取响应、6Cxx修正长度重试等多次交互，将它们还原为逻辑命令与最终响应，随后核对应用选择、GPO、AFL记录读取、PDOL／CDOL长度及GENERATE AC顺序。

输出包括可复用的结构化会话报告，以及含步骤、问题代码与原因的文本结果。项目同时保留交易日志文本／JSON／CSV输出、卡片字段提取与掩码等基础能力。协议解析、过程恢复和会话判断均由MoonBit实现；Node只承担CLI的本地文件读取。

## 二、应用背景与具体使用场景

单条APDU可以被正确解码，并不表示整段脚本符合前后步骤约束。例如，SELECT返回的PDOL会约束后续GPO输入，GPO返回的AFL会约束应读取的记录，记录中的CDOL1又会约束GENERATE AC输入。仅展示标签或状态字，无法直接回答“这个命令为什么在此时失败”“是否沿用了上一次选择的应用状态”等问题。

本项目围绕三个已经能够演示的任务组织功能：

1. **终端应用选择回归。** 开发者修改应用选择或响应恢复逻辑后，导出APDU日志，检查PPSE候选、部分AID选择、最终DF Name及过程字恢复是否一致。正常的61xx／6Cxx交互不会被直接当成最终业务失败。
2. **交易脚本排错。** 根据前序响应自动建立PDOL、AFL与CDOL约束，定位GPO数据长度不符、READ RECORD越界、漏读记录、错误命令顺序和应用重选后残留旧数据。
3. **测试流水线日志筛查。** 将已录制日志交给`session`命令；明确失败时返回退出码1，并附原因；不完整捕获输出`review`，避免把只有SELECT成功的片段写成完整交易通过。调用者可以读取结构化API结果，实现自己的复核策略。

这些是工具能够处理的开发任务，不代表已有真实商户部署或终端认证经历。外部软件测试日志与本项目构造的完整交易样例在验证记录中分别标注。

## 三、已实现的功能与处理流程

处理链为：**方向日志解析 → APDU解码 → 61xx／6Cxx过程恢复 → 响应TLV解析 → 应用上下文更新 → 跨步骤约束检查 → 结构化报告与CLI退出状态**。

| 层次 | 当前实现 | 对外结果 |
|---|---|---|
| 数据对象 | BER-TLV递归解析、编码、标签查找、路径查询及扁平化 | `Tlv`、标签树和字段值 |
| APDU | 短／扩展APDU解析与编码，响应数据与状态字拆分 | `Apdu`、`ApduResponse` |
| 过程恢复 | 61xx GET RESPONSE、6Cxx修正Le重试、多段数据合并与链完整性检查 | 归一化的逻辑交互 |
| 应用选择 | PPSE候选、部分AID、响应84 DF Name、重选状态清理 | 候选列表、最终选中AID |
| 数据约束 | PDOL／CDOL严格解析、GPO输入长度、AFL范围和记录完整性 | 带代码及原因的审计发现 |
| 交易辅助 | AIP／AFL解析、PAN／有效期／持卡人提取、Luhn及PAN掩码 | 交易摘要及日志报告 |
| 使用入口 | 纯库接口与CLI；基础交易日志支持文本／JSON／CSV | 可嵌入调用与可复现命令 |

会话审计本身提供结构化类型和文本渲染；JSON／CSV是基础交易日志报告的输出能力，不将其混写为所有会话审计字段都已有同格式导出。

## 四、核心技术机制

### 1. 从物理交互恢复逻辑命令

`resolve_apdu_procedures`处理一个命令需要多轮响应才能完成的情况。对于61xx，检查随后是否为匹配CLA、参数与Le的GET RESPONSE，累计各段响应数据后再解析TLV；对于6Cxx，要求下一条命令保持CLA、INS、P1、P2和数据不变，只按状态字修正Le。

错误重试、缺少后继命令或过长的恢复链会进入错误结果，不直接跳过。恢复链限定最多16次交互，以避免异常日志导致无界处理。审计步骤号对应归一化后的逻辑交互，不声称与原始文件物理行号逐一相同。

### 2. 应用选择与上下文生命周期

从PPSE响应的4F标签收集候选应用，随后核对SELECT请求与响应84 DF Name。部分AID选择允许返回的完整AID以请求AID为前缀；最终选中的AID使用响应中的完整名称。存在PPSE候选时，再检查该完整AID是否在候选集中。

成功重新选择应用会清除旧AIP、AFL、已读记录、PDOL／CDOL长度和完成状态。失败状态字不会安装新响应中的AFL或推进正常交易状态，避免后续判断建立在一次失败的GPO之上。

### 3. DOL字段约束

`parse_dol`按EMV数据对象列表的标签／一字节字段长度解释PDOL与CDOL，拒绝截断标签、缺少长度等畸形结构。这里的长度是后续命令中该字段占用的字节数，不能直接按普通TLV值长度处理。

SELECT中的PDOL总长度约束GPO命令83模板的数据长度；应用记录中的CDOL1总长度约束GENERATE AC数据长度。错误分别形成`INVALID_PDOL`、`INVALID_CDOL`、`PDOL_LENGTH_MISMATCH`或`CDOL_LENGTH_MISMATCH`，不把不完整DOL静默解释为较短列表。

### 4. AFL驱动的记录核对

GPO响应支持77与80模板，解析AIP和AFL。READ RECORD的SFI与记录号必须落在AFL声明范围内；发出GENERATE AC前，还会检查AFL要求的记录是否全部出现。前者定位越界访问，后者定位只读部分记录就继续交易。

PAN与有效期按当前应用的记录集合汇总，不要求每条记录都重复携带同一字段。应用重新选择后不会继续使用此前记录中提取的约束。

### 5. 可复核的判定语义

发现明确规则违例时输出`fail`；存在缺少完整交易、候选不足或其他需人工判断的情况时输出`review`；只有当前实现规则未发现违例时输出`pass`。空日志、无法解析的输入、缺失响应和孤立步骤分别处理，不将“没有报文可检查”等同于成功。

主要工程实现位于`transaction.mbt`、`procedures.mbt`和`session.mbt`。基础编解码与卡片字段函数可以独立复用，会话层则依赖前后文作出判断。

## 五、相对已有能力的实质增量

基础BER-TLV、APDU长度编解码、固定命令构造和卡片字段提取都属于可以复用的底层能力。本项目不以协议名或标签数量作为独立价值证明，新增工作集中在多轮交互恢复、应用上下文、数据依赖和跨步骤约束。

| 单条解码能够回答 | 本项目进一步回答 |
|---|---|
| 响应状态字是61xx或6Cxx | 后续取响应／重试是否正确，最终逻辑响应是什么 |
| SELECT数据中有某个AID | 部分AID是否匹配最终DF Name，是否属于候选应用 |
| GPO返回了AFL | 实际读取是否越界、要求的记录是否已读完整 |
| 记录里存在8C CDOL1 | GENERATE AC的数据长度是否满足前序定义 |
| 每个命令本身都能解析 | 是否沿用了旧应用状态、是否在缺少必要步骤时继续 |

ISO 8583／ISO 20022类网络报文工具处理收单或金融网络消息，职责与本项目的卡端交互日志不同；这一层次差异不构成“全生态不存在同类”的保证。项目也不主张发明APDU或EMV算法。

## 六、完整案例与预期输出

### 案例一：外部读卡器软件的过程字恢复

采用`devnied/EMV-NFC-Paycard-Enrollment`固定提交`a59820d4e979b17c1d1721fe2b03219d52ebcb35`中的`wrapperTestSW_61`与`wrapperTestSW_6C`，保留Apache-2.0许可和来源。日志直接使用`send:`／`resp:`格式。

两份日志均请求部分AID `A000000003`，分别经GET RESPONSE或修正Le重试，返回完整AID `A0000000031010`。当前分析选出完整AID，不产生错误的`STATUS_ERROR`或`AID_MISMATCH`；由于捕获只到SELECT，最终判为`review`，包含`INCOMPLETE_TRANSACTION`。

### 案例二：完整合成交易与漏读记录

`happy.log`覆盖PPSE→SELECT→GPO→READ RECORD→GENERATE AC，在当前规则下输出`pass`。`unread-afl.log`将AFL改为要求两条记录，而日志仍只读取一条，输出`AFL_RECORD_MISSING`并退出1。

### 案例三：数据约束与失败状态

| 输入变化 | 检查结果 |
|---|---|
| CDOL1要求27字节，GENERATE AC只有26字节 | `CDOL_LENGTH_MISMATCH` |
| SELECT中的PDOL要求数据，GPO仍带空83模板 | `PDOL_LENGTH_MISMATCH` |
| GPO返回6A82，即使前面携带类似AFL的数据 | `STATUS_ERROR`，不安装AFL |
| SELECT后直接GENERATE AC | 报告缺少GPO、记录等前序条件 |
| 重选应用后沿用上一应用的记录 | 旧上下文已清理，无法据此通过 |

复现入口如下，文件路径相对于仓库根目录：

```sh
moon run cmd/main --target js -- session examples/external/wrapperTestSW_61.log
moon run cmd/main --target js -- session examples/external/wrapperTestSW_6C.log
moon run cmd/main --target js -- session examples/sessions/happy.log
moon run cmd/main --target js -- session examples/sessions/unread-afl.log
```

## 七、公开接口、工程验证与安装

主要接口包括`parse_transaction_log`、`resolve_apdu_procedures`、`analyze_session`和`render_session`；审计结果使用`SessionReport`／`SessionIssue`，保留判定、应用、AFL、记录与问题列表。调用者也可单独使用`parse_tlv`、`parse_apdu`、`parse_dol`和命令构造接口。

当前核心测试为**39项**，覆盖基础编解码、交易报告、过程字恢复、部分AID、DOL错误、状态生命周期及记录约束。代码基线在Windows本地JS、wasm、wasm-gc上完成check／build／test；对应公共CI在JS、wasm、wasm-gc、native四后端通过。跨目标执行不累计成不同测试用例。

独立消费工程从MoonCakes安装`btlqql/moon_card@0.3.0`，能够通过公共API完成过程恢复与应用选择检查；与另外两个包共同执行3项公开API用例。注册表安装的`procedures.mbt`、`session.mbt`和`transaction.mbt`分别与本地源码SHA-256一致。这里不把消费工程的3项共同用例写成本包新增3项测试。

```sh
moon test --target js
moon test --target wasm
moon test --target wasm-gc
moon add btlqql/moon_card@0.3.0
```

## 八、当前适用范围与边界

目标是录制日志的离线开发检查，重点覆盖接触式风格的SELECT／GPO／AFL／记录／GENERATE AC流程；不能据此推断任意非接触内核或全部EMV交易都正确。

项目不执行ARQC／MAC、PIN block、密钥管理或证书验签，不实现完整EMV风险管理、CDA、Level 3认证，也不连接PC/SC、NFC、HID读卡器。`pass`只针对已实现检查，不能替代银行授权、密码学证明或认证结论。`review`退出码为0，自动化调用者仍须读取报告内容。

交易摘要对提取到的PAN使用掩码；原始日志与库接口数据仍由调用者管理，不声称实现了任意日志的全面脱敏。外部软件夹具和合成交易均非本项目实测的真实终端交易；未提供生产部署、大日志性能、模糊测试或硬件兼容性证明。

## 九、公开交付与验证证据

- [公开仓库](https://github.com/btlqql/moon-card)；[GitHub Release v0.3.0](https://github.com/btlqql/moon-card/releases/tag/v0.3.0)。
- 公共模块：[btlqql/moon_card@0.3.0](https://mooncakes.io/docs/btlqql/moon_card@0.3.0)，发布返回`Server status: 200 OK`，已完成全新工程注册表安装验证。
- 已验证核心代码基线：`70aa8d1e7d6e6482d1913a96c7afbb35b2589344`；[该基线四后端CI](https://github.com/btlqql/moon-card/actions/runs/41064285400)。后续申报文档更新不另算功能实现。
- [外部样例、固定来源及许可](https://github.com/btlqql/moon-card/blob/main/examples/external/SOURCES.md)；[核心与验证说明](https://github.com/btlqql/moon-card/blob/main/docs/final-review-20261030.md)。

本项目使用AI辅助开发；参赛者对技术选择、实现理解和结果质量负责。本材料陈述已实现、已验证和已发布的工作，不以说明书的篇幅或自动测试结果冒充比赛审核通过回执。
