# MoonCard

离线支付卡报文工具包：解析 ISO 7816 APDU、EMV BER-TLV 和真实交易日志。

- 仓库：https://github.com/btlqql/moon-card
- 版本：0.1.0
- 许可证：Apache-2.0

## 为什么单独做这一层

MoonCakes 上已有支付相关模块，但不在这一层：

- [Han-Wentao/mooniso8583](https://mooncakes.io/docs/Han-Wentao/mooniso8583) 处理 ISO 8583 收单网络报文。
- [cstoooo/mooniso_lite](https://mooncakes.io/docs/cstoooo/mooniso_lite) 与 [moonpay_flow](https://mooncakes.io/docs/cstoooo/moonpay_flow) 处理 ISO 20022 支付报文与生命周期。
- [lindividual/der](https://mooncakes.io/docs/lindividual/der) 处理 ASN.1 DER（证书/密钥），不是 EMV 的 BER-TLV 标签空间。

MoonCard 处理的是**卡片与终端之间**的 APDU 和 EMV 数据对象：SELECT、GPO、READ RECORD、GENERATE AC、BER-TLV、PAN/有效期/持卡人、状态字与 NRC 风格的失败原因。

面向的任务：拿到一段终端或 Level 3 认证的 APDU 日志，回答“这一步选了什么应用、GPO 返回了什么、读到了哪张卡、哪一步失败、失败状态字是什么”。

2026-10-24 在 MoonCakes 搜索 `emv`、`apdu`、`smartcard`、`iso7816` 未发现同层实现；搜索未命中不等于绝对不存在，私有实现和不同命名仍是盲区。

## 快速开始

要求 MoonBit 工具链（本版本在 `moon 0.1.20260904` 验证）。CLI 以 JS 为目标，文件读取只使用 Node 内置模块。

```bash
moon test
moon run cmd/main --target js -- log examples/transaction.log
```

输出（截断）：

```text
steps: 6 errors: 0
1 >> 00 A4 04 00 0E 32 50 ... 00  SELECT
2 << 6F 09 84 07 ... 90 00  success (9000)
  tags: 6F(FCI Template) 84(Dedicated File Name)
...
6 << 70 15 5A 08 ... 90 00  success (9000)
  tags: 70(Record Template) 5A(Primary Account Number) ...
PAN: 411111******1111 (luhn ok)
expiry: 2025-12
cardholder: JO
```

## CLI

```text
mooncard tlv <hex>                     parse BER-TLV
mooncard response <hex>                parse APDU response + TLV
mooncard apdu <hex>                    parse a command APDU
mooncard select <aid-hex>              build SELECT by AID
mooncard gpo <pdol-data-hex>           build GET PROCESSING OPTIONS
mooncard read-record <record> <sfi>    build READ RECORD (decimal)
mooncard gen-ac <p1> <cdol-data-hex>   build GENERATE AC
mooncard log <transaction.log>         render a recorded APDU log
mooncard luhn <pan>                    check the Luhn digit
mooncard track2 <text>                 parse track 2 equivalent data
```

示例：

```bash
moon run cmd/main --target js -- tlv "6F 09 84 07 A0 00 00 00 03 10 10"
moon run cmd/main --target js -- select A0000000031010
moon run cmd/main --target js -- gpo ""
moon run cmd/main --target js -- read-record 1 3
moon run cmd/main --target js -- response "6F 09 84 07 A0 00 00 00 03 10 10 90 00"
```

## 交易日志格式

每行一条方向加十六进制：

```text
>> 00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00
<< 6F 09 84 07 A0 00 00 00 03 10 10 90 00
```

`>>` / `C:` 表示命令，`<<` / `R:` 表示响应，`#` 开头为注释。响应最后两字节按状态字处理，前面的数据尝试按 BER-TLV 解析；解析失败时保留原始数据，不丢弃步骤。

## 测试

`moon test` 共 10 项：

- TLV 嵌套解析、标签查找、构造模板编码往返、截断/非法长度。
- APDU 短格式 case 1/2/3/4 往返、Le=256、响应拆分。
- 状态字说明（成功、文件不存在、PIN 重试次数）。
- GPO 的 77 与旧 80 两种模板。
- 记录中的 PAN、有效期、持卡人；Luhn；掩码；有效期格式。
- Track 2 解析。
- 交易日志的命令/响应/卡片信息提取；畸形输入记录。

GitHub Actions 在 wasm、wasm-gc、js、native 四个后端执行 check/build/test。

## 明确不做

- 不实现任何密码学：不做 MAC、ARQC、应用密文校验、PIN block 生成、密钥管理或证书验签。
- 不是 EMV 内核：不做终端风险管理、卡片行为决策、CDA、脚本处理或 Level 3 认证流程。
- 不做卡片个人化、发卡、收单主机或 ISO 8583/ISO 20022 网络报文。
- 不连接读卡器，不含 PC/SC、NFC 或 HID 驱动。
- 只支持短 APDU；扩展 APDU、逻辑通道和命令链未实现。

## 安全

报告只显示掩码后的 PAN，不输出密钥、PIN block 或完整磁道数据。工具默认本地处理日志；示例中的卡号是测试号，不对应真实账户。

## 后续

优先补：扩展 APDU、命令链、更多 EMV 标签与长度格式、TLV 模板的结构化视图、日志中请求/响应配对、JSON 输出。每项都要有真实日志样本和失败样例，再谈发布。
