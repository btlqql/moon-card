# MoonCard 0.3.0

面向终端交易脚本的离线日志分析：PPSE/AID、GPO/AFL、跨记录数据和CDOL长度检查。失败状态不会推进交易，应用重选会清除旧状态，AFL未读完整会报告失败。

2026-10-30修订。Apache-2.0。核心为纯MoonBit库，Node只承担CLI文件读取。

新增ISO 7816过程字解析：61xx GET RESPONSE多段合并、6Cxx修正Le重试；支持外部项目的send:/resp:日志与部分AID选择。SELECT中的PDOL和记录中的CDOL使用严格DOL解析，约束GPO与GENERATE AC输入长度。失败恢复链、缺失响应和非法DOL不会静默通过。

## 运行

需要MoonBit工具链与Node.js。核心库不依赖Node，CLI使用Node读取文件。

```sh
moon test --target js
moon run cmd/main --target js -- session examples/sessions/happy.log
moon run cmd/main --target js -- session examples/external/wrapperTestSW_61.log
moon run cmd/main --target js -- session examples/external/wrapperTestSW_6C.log
```

session命令发现fail时返回1；review输出供人工复核，退出码为0。

## 当前能力与验证

新版功能和复现任务见[本轮复核](docs/final-review-20261030.md)。Windows本地完成JS、wasm、wasm-gc的check/build/test及独立消费工程。外部样例来源、固定提交和Apache许可证见[样例来源](examples/external/SOURCES.md)。部分捕获输出review表示需要人工复核，不能当作完整交易通过。

不是EMV内核或认证工具；不处理密码学，不连接真实读卡器。示例为构造日志，pass仅表示已实现检查未发现错误。
