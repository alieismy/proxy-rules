# 首次导入记录

导入日期：2026-11-10（Asia/Singapore）。

## 范围与内容

本次以原项目目录中的当前工作文件为输入，创建独立公共仓库；不从旧 Git 提交恢复文件，也不迁移旧仓库历史。客户端脚本当前未提交的内容包含在首次导入中，原项目文件保持不变。

仅调整目录与文件名。六份脚本的字节、UTF-8 编码、既有换行及内容均保持原样，`.gitattributes` 对 JavaScript 禁用自动换行转换。源码历史注释中的旧文件名仅用于来源追踪，不是运行时文件依赖。

| 原文件名 | 仓库路径 |
| --- | --- |
| `FlClash覆写脚本_v16优化版.js` | [`clients/flclash/override.js`](../clients/flclash/override.js) |
| `Sparkle覆写脚本_v16优化版.js` | [`clients/sparkle/override.js`](../clients/sparkle/override.js) |
| `Clash Verge Rev覆写脚本_v16优化版.js` | [`clients/clash-verge-rev/override.js`](../clients/clash-verge-rev/override.js) |
| `WiFi Calling优化覆写规则-英国全网版.js` | [`scenarios/wifi-calling/uk.js`](../scenarios/wifi-calling/uk.js) |
| `WiFi Calling优化覆写规则-英国德国版.js` | [`scenarios/wifi-calling/uk-de.js`](../scenarios/wifi-calling/uk-de.js) |
| `WiFi Calling优化覆写规则-英国德国美国统一版.js` | [`scenarios/wifi-calling/uk-de-us.js`](../scenarios/wifi-calling/uk-de-us.js) |

## SHA-256

以下校验值对应本次导入时的原始字节；后续内容更新后，应以相应 Git 提交为准。

```text
4e3fd66a27b381bb79667486fc9fd4ddb6b0693ba5919b8a5a81651d63eff885  clients/flclash/override.js
bdfeaf6e24981b205029d9747bbc48187dab8f141de6a529e4ad08c663073805  clients/sparkle/override.js
b5c26b501f1828f4065c93baa67bc280d6fd94c914dc73393051ede81678b7f3  clients/clash-verge-rev/override.js
a5576ffcc0c844ba714ea896e5f3b3dc00c2e8b74581d86d5d58549aa2faea85  scenarios/wifi-calling/uk.js
9bb5c949eb635a1f8d9d3a8417e3a6268945941ca56e8d14b9a38a864b500c26  scenarios/wifi-calling/uk-de.js
b45ec3c7f86ade5edf9a24a9ad3f038af1e403fab8d7911fc15cf89913c140a9  scenarios/wifi-calling/uk-de-us.js
```

## 验证范围

发布前已通过（Node.js v24.22.1）：源文件与目标文件字节比较、六份 JavaScript 的 Node.js 语法检查、隔离环境中的 `main(config)` 配置生成检查、规则目标与规则集引用检查、统一版默认 OFF 行为检查，以及拟提交文件中的凭据与私人标识扫描。

结果：6 / 6 份脚本字节一致且语法通过；18 / 18 组有效输入配置生成检查通过，6 / 6 组空输入拒绝检查通过；规则目标和规则集引用完整；统一版默认 OFF、两个私人参数数组为空；扫描未发现凭据、带认证参数的 URL 或已识别的私人主机标识。原工作区文件与 Git 状态保持不变。

以上属于导入一致性与本地静态 / 配置生成检查。它们不证明客户端 JS 引擎兼容、Mihomo 核心实际接受配置、外部规则源可达、网络分流正确或 IMS 业务成功。原注释中记录的历史版本、政策、性能和测试结果没有在本次迁移中重新确认。

## 保留边界

- 三个客户端版本与三个 WiFi Calling 版本独立保留，没有合并其差异或升级功能。
- 源码中部分历史 SSH 注释仍描述早期行为；当前三个客户端脚本不再含私人 SSH 地址规则。应以实际规则数组为准。
- 统一版 `PRIVATE_SSH_DIRECT_IPV4S` 与 `VOWIFI_OBSERVED_SOURCE_IPV4S` 保持默认空值。个人定制不应提交到公共仓库。
- 旧备份、历史日志、参考材料、原 Git 历史和个人代理指令未纳入发布。
