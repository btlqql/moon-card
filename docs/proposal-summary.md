# MoonCard：卡片与终端交易脚本的离线审计库

账号：btlqql｜单人项目｜版本：0.3.0｜主要语言：MoonBit｜许可：Apache-2.0

## 解决的问题

终端程序或测试脚本改动后，逐条解码APDU仍难判断应用是否选对、失败响应是否被错误继续、GPO与读记录是否满足前序约束。MoonCard把录制日志还原为逻辑交互，面向终端开发者的回归排错与测试流水线筛查。

## 核心实现

MoonBit实现BER-TLV、短／扩展APDU和有状态会话分析。新增61xx取响应合并、6Cxx修正Le重试、部分AID选择及失败恢复检查；严格解析PDOL／CDOL，核对GPO数据长度、AFL记录范围与完整性、应用重选状态及GENERATE AC长度。输出步骤、问题代码、原因和pass／review／fail。

## 可复现任务

直接读取外部EMV读卡器项目的两份Apache-2.0测试日志，分别完成61xx、6Cxx恢复并选出A0000000031010。捕获在SELECT后结束，因此准确输出review而非伪造完整交易通过。自制完整交易输出pass，漏读AFL记录输出AFL_RECORD_MISSING及退出码1。样例和来源固定提交随代码提供。

## 相对已有能力的增量

重点是跨APDU交互约束和失败过程的状态判断，超出TLV编解码、固定命令封装或字段统计；与收单侧ISO 8583／ISO 20022网络报文的职责不同。核心API可供其他MoonBit程序调用，CLI用于同一流程的复现。

## 验证与范围

39项测试通过；公开CI完成JS、wasm、wasm-gc、native的check／build／test；独立消费工程通过。外部日志为上游软件测试夹具，完整交易为合成样例。不是EMV内核，不验证ARQC／PIN／证书，不连接读卡器；pass仅表示已实现规则未发现问题。

## 项目信息

源码：https://github.com/btlqql/moon-card；固定提交：70aa8d1e7d6e。AI辅助开发，参赛者对目标、技术路径和质量负责。

验证记录：https://github.com/btlqql/moon-card/actions/runs/41064285400

公共包：https://mooncakes.io/docs/btlqql/moon_card@0.3.0（独立工程注册表安装验证通过）

正式发布：[GitHub Release v0.3.0](https://github.com/btlqql/moon-card/releases/tag/v0.3.0)
