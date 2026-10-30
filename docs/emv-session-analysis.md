> 历史说明：本页记录2026-10-25版本；2026-10-30的实现、验证及边界以[当前修订说明](review-20261030.md)为准。

# APDU/EMV 会话语义分析（2026-10-25）

`session.mbt` 不是 TLV/APDU 编解码器，也不是固定命令封装。它按真实交易顺序消费一段 APDU 日志，维护应用选择、GPO、AFL 记录读取和 GENERATE AC 的状态，并对每一步做可核对的判断。

## 状态机

```text
PPSE
  → SELECT AID（候选匹配、DF name 校验）
  → GPO（AIP/AFL 提取）
  → READ RECORD（AFL 范围校验、记录标签校验）
  → GENERATE AC（CDOL1 长度校验、顺序校验）
```

## 判断项

| 代码 | 级别 | 判断 |
|---|---|---|
| `MISSING_RESPONSE` | fail | 命令后没有响应 |
| `STATUS_ERROR` | fail | SW ≠ 9000，附状态字说明 |
| `PPSE_NO_CANDIDATES` | review | PPSE 响应没有 4F ADF Name |
| `MISSING_DF_NAME` | fail | SELECT 响应没有 84 |
| `AID_MISMATCH` | fail | 请求的 AID 与卡片返回的 84 不一致 |
| `AID_NOT_IN_CANDIDATES` | review | 选中的 AID 不在 PPSE 候选中 |
| `GPO_TEMPLATE` | fail | GPO 响应不是 77/80 |
| `GPO_NO_AFL` | fail | GPO 的 AFL 为空 |
| `RECORD_NOT_IN_AFL` | fail | READ RECORD 的 SFI/记录号不在 AFL 范围 |
| `RECORD_TEMPLATE` | fail | READ RECORD 响应没有可用 TLV |
| `MISSING_PAN` | fail | 记录既没有 5A 也没有 57 |
| `MISSING_EXPIRY` | review | 记录没有 5F24 |
| `GENERATE_AC_BEFORE_GPO` | fail | 未做 GPO 就 GENERATE AC |
| `GENERATE_AC_BEFORE_RECORD` | fail | 未读任何记录就 GENERATE AC |
| `MISSING_CDOL` | review | 未看到 8C CDOL1 |
| `CDOL_LENGTH_MISMATCH` | fail | GENERATE AC 数据长度与 CDOL1 字段总长不一致 |

## 具体日志与结果

`examples/sessions/` 有 7 份日志。节选：

**happy.log**：PPSE → SELECT VISA → GPO(77/82/94) → READ RECORD(70/5A/5F24/5F20/8C) → GENERATE AC(27 字节)。

```text
verdict: pass
candidates: A0000000031010
selected AID: A0000000031010
AIP: 1980
AFL: 1
records read: 1
```

**wrong-order.log**：SELECT 后直接 GENERATE AC。

```text
verdict: fail
issue step=5 fail GENERATE_AC_BEFORE_GPO: GENERATE AC before GPO
issue step=5 fail GENERATE_AC_BEFORE_RECORD: GENERATE AC before any READ RECORD
issue step=5 review MISSING_CDOL: no 8C CDOL1 was seen before GENERATE AC
```

**missing-pan.log**：记录只有 5F24/5F20/8C，没有 5A/57。

```text
verdict: fail
issue step=7 fail MISSING_PAN: record has neither 5A nor 57
```

**afl-mismatch.log**：GPO 的 AFL 只有 SFI1，却请求 SFI2 的 record 1。

```text
verdict: fail
issue step=7 fail RECORD_NOT_IN_AFL: READ RECORD sfi=2 record=1 is outside AFL
```

**cdol-mismatch.log**：CDOL1 要求 27 字节，GENERATE AC 只带 26 字节。

```text
verdict: fail
issue step=9 fail CDOL_LENGTH_MISMATCH: CDOL1 expects 27 bytes but command has 26
```

**status-error.log**：GPO 返回 `6A 82`。

```text
verdict: fail
issue step=5 fail STATUS_ERROR: SW=6A82 file or application not found
```

**two-candidates.log**：PPSE 返回 VISA 和 Mastercard，选择第二个。

```text
verdict: pass
candidates: A0000000031010,A0000000041010
selected AID: A0000000041010
```

## 相对于“编解码 + 固定命令封装”新增的判断

- 从 PPSE 的 4F 提取候选 AID，并与后续 SELECT 的 AID 做归属检查。
- 校验 SELECT 请求 AID 与响应 84 DF Name 一致。
- 维护阶段状态，拒绝“未 GPO 就 GENERATE AC”“未读记录就 GENERATE AC”。
- 用 GPO 返回的 AFL 反查 READ RECORD 的 SFI/记录号是否合法。
- 检查记录是否包含 PAN/有效期；从 8C 解析 CDOL1 字段并计算期望数据长度。
- 把状态字失败、模板缺失和顺序错误汇总为 pass/review/fail 判定，带步骤号和原因。

## 边界

- 不实现密码学、ARQC、CDA、PIN、密钥管理或证书验签。
- 不是 EMV 内核：不做终端风险管理、卡片行为决策、脚本处理或完整 Level 3 流程。
- 只分析日志中出现的命令序列，不生成或补全缺失步骤；缺失由 issue 报出。
- 测试日志是作者构造的合法样例，尚未用真实终端日志验证。

## 复现

```bash
moon test
moon run cmd/main --target js -- session examples/sessions/happy.log
moon run cmd/main --target js -- session examples/sessions/wrong-order.log
```

测试文件：`session_test.mbt`（8 项），总计 28 项测试。
