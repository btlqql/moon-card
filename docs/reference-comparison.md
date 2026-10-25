# 外部对照：pyemv 1.5.0

日期：2026-10-24。参考实现安装到 `D:\Codex\tools\pyrefs`，仅用于开发对照，不是 MoonCard 的运行时依赖。

## 方法

```powershell
python -m pip install --target D:\Codex\tools\pyrefs pyemv==1.5.0
$env:MOONBIT_PYREFS = "D:\Codex\tools\pyrefs"
python scripts\reference_compare.py
```

`scripts/reference_compare.py` 用 `pyemv.tlv` 解析 MoonCard 的 FCI、记录和 GPO 样例，并对照编码结果与截断输入的错误处理。

## 结果

| 对照项 | 输入 | pyemv 结果 | MoonCard | 结论 |
|---|---|---|---|---|
| FCI 模板 | `6F 09 84 07 A0 00 00 00 03 10 10` | `6F` 内 `84 = A0000000031010` | 同一标签/值 | 一致 |
| 记录模板 | `70 15 5A 08 ... 5F 24 03 25 12 31 5F 20 02 4A 4F` | `5A=4111111111111111`，`5F24=251231`，`5F20=JO` | 同一标签/值 | 一致 |
| GPO | `77 0A 82 02 19 80 94 04 08 01 01 00` | `82=1980`，`94=08010100` | 同一标签/值 | 一致 |
| 编码 | `{"9C":"01","E0":{"5F2A":"0208"},"9F02":""}` | `9C0101E0055F2A0202089F0200` | 同一十六进制 | 一致 |
| 截断 TLV | `6F 0A 84 07 A0` | 抛 `DecodeError` | 抛 `Truncated` | 都拒绝 |

脚本输出：

```text
[PASS] FCI 6F/84 ...
[PASS] record 70/5A/5F24/5F20 ...
[PASS] GPO 77/82/94 ...
[PASS] encode pyemv example ...
[PASS] truncated TLV rejected
All reference comparisons passed.
```

## 差异与未覆盖

- `pyemv` 解码成嵌套 `dict`，MoonCard 解码成 `Tlv` 树；标签和值一致，只是数据模型不同。
- 没有对照密码学：ARQC、MAC、PIN block、证书验签都不在 MoonCard 范围。
- 没有对照扩展 APDU、逻辑通道、命令链和真实终端日志。
- 只覆盖 FCI、记录、GPO 和基础编码；不是完整 EMV 标签矩阵。
- 参考库版本固定为 1.5.0；升级后应重跑脚本。

## 参考库许可证

- `pyemv` 1.5.0：MIT。

只在对照脚本中导入，不进入 MoonCard 的构建或发布产物。
