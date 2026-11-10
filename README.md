# proxy-rules

个人代理客户端覆写脚本与场景规则集合。目前收录 FlClash、Sparkle、Clash Verge Rev 的 JavaScript 覆写脚本，以及三种 WiFi Calling 场景版本。

本仓库按客户端与使用场景组织，后续可加入 iOS 代理客户端规则及 metacubexd 相关配置。当前仅发布下表所列文件，不代表已经支持其他客户端或平台。

## 脚本入口

| 客户端 / 场景 | 文件 | 文件头标注版本 | Raw 下载 |
| --- | --- | --- | --- |
| FlClash | [override.js](clients/flclash/override.js) | v16.7 | [Raw](https://raw.githubusercontent.com/alieismy/proxy-rules/main/clients/flclash/override.js) |
| Sparkle | [override.js](clients/sparkle/override.js) | v16.7 | [Raw](https://raw.githubusercontent.com/alieismy/proxy-rules/main/clients/sparkle/override.js) |
| Clash Verge Rev | [override.js](clients/clash-verge-rev/override.js) | v16.6 | [Raw](https://raw.githubusercontent.com/alieismy/proxy-rules/main/clients/clash-verge-rev/override.js) |
| WiFi Calling：英国全网版 | [uk.js](scenarios/wifi-calling/uk.js) | v16 | [Raw](https://raw.githubusercontent.com/alieismy/proxy-rules/main/scenarios/wifi-calling/uk.js) |
| WiFi Calling：英国德国版 | [uk-de.js](scenarios/wifi-calling/uk-de.js) | v16 | [Raw](https://raw.githubusercontent.com/alieismy/proxy-rules/main/scenarios/wifi-calling/uk-de.js) |
| WiFi Calling：英国德国美国统一版 | [uk-de-us.js](scenarios/wifi-calling/uk-de-us.js) | v16.8 | [Raw](https://raw.githubusercontent.com/alieismy/proxy-rules/main/scenarios/wifi-calling/uk-de-us.js) |

版本来自原文件头，不能代替 Git 提交标识。上述 Raw 链接随 `main` 更新；需要可复现配置时，把 URL 中的 `main` 替换为已检查的完整提交 SHA。

## 使用方式与边界

1. 先备份客户端当前配置及覆写内容，选择对应客户端的一份脚本。
2. 在客户端提供的 JavaScript 覆写入口导入或粘贴文件；如果该版本支持远程脚本，可使用表中的 Raw 链接。具体入口以正在使用的客户端版本为准。
3. 输入配置需要已有 `proxies` 或 `proxy-providers`。这些脚本提供 `main(config)` 入口，不包含节点订阅或代理凭据。
4. 应用后检查最终生成配置、策略组和核心日志，再验证实际访问。TUN 的启停由客户端控制；脚本同时配置 DNS、TUN 参数、嗅探、策略组和路由规则。
5. 出现异常时停用新覆写，恢复备份并重新加载配置。

**每份都是完整覆写脚本。** 它们会替换 `rules`、`proxy-groups`、`rule-providers` 和 DNS 等字段，不是只追加几条规则。WiFi Calling 版本同样包含通用分流；不要把它与普通客户端版直接串联，也不要假定多个完整脚本能够叠加。

现有客户端脚本保留各自的平台差异及分流策略，包括关闭 IPv6、设置代理节点 UDP 标志等。节点的 `udp: true` 不能证明上游 UDP 可用。WiFi Calling 文件基于 Sparkle / Mihomo，尚未作为 iOS 客户端原生规则适配。

DNS 监听范围也有差异：Clash Verge Rev 版生成 `0.0.0.0:1053`，其余五份生成 `127.0.0.1:1053`。前者请求监听所有 IPv4 接口，实际能否从其他设备访问仍取决于最终配置、核心监听和系统防火墙；导入前应确认这符合所需的 DNS 访问范围。

## WiFi Calling 版本区别

| 文件 | 源码中的默认行为与用途 |
| --- | --- |
| `uk.js` | 加载后即把 UK / Vodafone DE 的 ePDG 送入对应策略组，组首项分别为自动 UK / DE；并注入 Vodafone DE 固定 hosts 和对应 IP 规则。没有统一版的 `OFF` 开关。 |
| `uk-de.js` | UK / Vodafone DE 的 ePDG 同样进入对应策略组，组首项分别为自动 UK / DE；普通 DE 组首项为 `DIRECT`。固定地址回退开关默认 `false`，仅关闭该 hosts / IP 回退，不关闭上述域名分流，也不清除输入配置已有的 hosts。 |
| `uk-de-us.js` | `VOWIFI_ACTIVE_PROFILE` 默认 `OFF`：脚本列出的 ePDG DNS 出口和域名规则使用 `DIRECT`，不生成 UDP 500/4500 接管规则，也不新增固定 ePDG hosts。四个 VoWiFi 手动候选组首项为 `REJECT`。`OFF` 不停用通用覆写，也不清除输入配置已有的 hosts。 |

表中“组首项”是生成配置中的顺序；脚本启用了 `store-selected`，客户端保存的历史选择可能继续生效，应用后须核对实际选择。

三个版本保留原有行为，不能只按文件名中的国家范围互换，也不能按版本号认定统一版包含普通 Sparkle 版的全部更新。统一版文件头注明通用基线为 Sparkle v16.4；当前三个客户端版的自动测速组都显式设置了 `empty-fallback: REJECT`，三个 WiFi Calling 版的自动测速组均未设置该项。统一版的 VoWiFi 手动候选组保护不等于所有策略组都有相同保护。

统一版的 profile、源地址范围与启用步骤见其文件开头注释。WiFi Calling 是否成功仍需要手机流量路径、节点 UDP、运营商条件和 IMS 注册、通话、短信等实际验证。

脚本中的客户端版本、运营商政策、DNS 观测、历史测试结果和故障归因是原文件携带的记录。本次导入没有重新核验这些历史主张，也没有进行客户端部署、核心运行或 WiFi Calling 业务验收。

## 目录与后续扩展

```text
clients/
  flclash/override.js
  sparkle/override.js
  clash-verge-rev/override.js
scenarios/
  wifi-calling/
    uk.js
    uk-de.js
    uk-de-us.js
docs/
  initial-import.md
scripts/
  check.cjs
```

- 客户端专用内容放在 `clients/<client>/`。未来 iOS 客户端也按实际软件和格式分目录，例如 `clients/surge/`、`clients/shadowrocket/`；有内容时再创建。
- 特定业务场景放在 `scenarios/<scenario>/`，注明目标客户端、格式与叠加方式。
- 未来 metacubexd 相关配置可放在 `integrations/metacubexd/`；实际分流文件按所属核心或客户端归档，并说明接入方式，不预设各平台格式互通。
- 文件路径保持稳定，版本变化由 Git 记录，避免每次更新都更换订阅或下载地址。
- 私人节点、订阅、控制器凭据和本机定制保存在忽略的 `local/` 或 `private/` 中；提交前单独检查。

## 导入、来源与验证

[首次导入记录](docs/initial-import.md) 列出原文件名、目标路径、SHA-256 与本次验证范围。六份脚本按当前工作文件逐字节导入，保留原编码、换行和注释；未导入源目录的 Git 历史、备份、日志、参考资料或开发工具状态。

原脚本保留了历史 SSH 管理规则的变更注释；当前三个客户端版本没有这些私人地址的 SSH 直连例外，应以实际规则为准。

安装 Node.js 后，在仓库根目录运行：

```sh
node scripts/check.cjs
```

检查不需要安装 npm 依赖、不访问网络、不读入个人配置，也不写出生成配置。它复查六份脚本的语法、18 组配置生成、6 组空输入拒绝、规则引用，以及上文所列的 DNS 监听和 WiFi Calling 默认行为；本次使用 Node.js v24.22.1 通过。它不检查外部规则可达性，也不能替代客户端引擎、Mihomo 核心及实际网络验收。原文件字节同一性和发布内容的敏感信息检查属于首次导入审计，不由这个配置检查命令证明。

脚本引用的外部规则及图标包括 Loyalsoldier、Sukka、blackmatrix7 和 Clash Verge Rev 等项目；具体 URL 保留在各文件中，规则加载仍依赖这些外部来源。本次未打包外部规则，也未更改其来源。

仓库暂未指定统一的开源许可证；原有第三方来源和许可边界需要分别保留，不能从仓库公开状态推定这些材料已获得统一授权。
