// Sparkle / Mihomo 覆写脚本（v16.1 + UK / Germany VoWiFi 分层优化版）
// 2026-11-10 通用修复同步：8 个自动组空组拒绝；修正 AI Gateway 顺序与通用节点筛选；
// 补齐 VS Code 同步及 AI 域名覆盖。保留本版 VoWiFi 流程、App Store、Oracle 和漏网之鱼策略。
// 核心须支持 empty-fallback（已核对 Mihomo v1.19.31 契约）；空组保护不代表 UDP/IMS 可用。
// 同步 OneDrive 路由/DNS、清理 dns.strategy，仅缩小普通 select 周期检查；电话组周期保持。
// 非 Wi-Fi Calling 基线：Sparkle覆写脚本_v16优化版.js
// 适用：Sparkle-windows-1.26.4-x64 / Mihomo 内核，TUN + 规则模式
//
// VoWiFi 能力边界（核实日期：2026-08-10）：
//   1. 本脚本只优化 ePDG DNS、Mihomo 分流和 UDP 出站条件；不能开通运营商账户能力，
//      不能绕过 SIM、设备 carrier profile、IMS、漫游状态或 IKE 层限制，也不保证注册。
//   2. VOXI/Vodafone UK 等英国运营商不正式支持境外 Wi-Fi Calling；UK 组属于实验路径。
//      CMLink UK 若使用标准 mcc234 ePDG 已由 UK 正则覆盖，不使用宽泛 DOMAIN-KEYWORD。
//   3. 德国 Telekom 和 O2 官方支持境外 WLAN Call，DE 组默认 DIRECT；德国节点仅用于
//      所在地网络阻断 DNS、UDP 500/4500 或 ePDG 时的受控对照。
//   4. Vodafone DE 官方不支持境外使用；其德国/英国出口和 DNS/hosts 仅为实验路径。
//      固定 ePDG 地址默认不注入，必须显式打开开关，并在使用前重新核验。
//   5. HTTPS 健康检查、disable-udp:false 或 proxy.udp=true 都不能证明端到端 UDP 可用；
//      手机流量还必须真实经过本机 TUN/热点/ICS，最终以运行日志和 IMS 业务测试为准。
//
// 安全提示：不要依赖 Wi-Fi Calling 拨打所在地紧急号码；境外通话按归属国规则计费，
// 本地号码可能被计为从英国/德国发起的国际电话。使用前先核对运营商当前资费。
//
// v16 变更说明：
//   [Group-AS] 删除「🇭🇰 自动-HK」，并从「🌍 自动-Global」排除香港节点。
//   [Group-AT] AI 服务合并到「AI」；YouTube 合并到「谷歌服务」；删除 Spotify 组。
//   [Filter-AU] 自动测速组和手动 US 组排除名称含「娱乐节点」的节点。
//   [DNS-AV] 补充核心 AI 域名，并与海外 DNS 策略对齐。
//
// v13.5 变更说明（基于 Mihomo 官方配置语义与本机连通性复核）：
//
//   [Perf-AP] find-process-mode 从 always 改为 strict：
//           仅在规则需要时启用进程匹配，保留现有 PROCESS 规则能力并减少无谓查询。
//
//   [Health-AQ] 统一策略组健康检查参数：
//           抽取 HEALTH_CHECK_URL，所有组统一 timeout: 5000 与 expected-status: 204；
//           删除 Mihomo 默认值 max-failed-times: 5。本机 HTTP/HTTPS 均稳定返回 204，
//           因此继续使用 HTTPS，不套用参考配置中的本机特定 HTTP 回退。
//
//   [Doc-AR] 校正 route-exclude-address 注释：
//           该字段表达 auto-route 下的排除意图，不保证 Windows 多网卡环境一定绕过 TUN
//           或为 DIRECT 自动选择正确物理出口；实际路径仍以最终配置、路由和日志为准。
//
// v13.4.1 变更说明（基于 Sparkle core-2026-6-9.log ESET LiveGrid 告警复核）：
//
//   [Fix-AO] 回退 c.eset.com 精确直连：
//           v13.4 将 c.eset.com 改为 DIRECT 后，ESET LiveGrid 的 c.eset.com:80
//           连续出现 dns resolve failed；同一日志中，改动生效前 c.eset.com:80
//           走 RuleSet(proxy) 可正常连接。恢复由规则集代理处理 c.eset.com。
//           c.eset.com:53535 的低频 UDP 解析告警暂不处理，避免影响 LiveGrid TCP 主链路。
//
// v13.4 变更说明（基于 Sparkle core-2026-6-8.log 日志复核）：
//
//   [Fix-AK] 微信功能域名精确救回：
//           wxa.wxs.qq.com 与 dns.weixin.qq.com.cn 被 Sukka reject_domainset 拦截，
//           分别影响微信小程序资源与微信 DNS 兜底链路；改为精确 DOMAIN 直连。
//           badjs.weixinbridge.com 属于错误上报链路，默认继续交给广告规则拦截，
//           仅在小程序异常且确认需要错误上报时再手动放行。
//
//   [Fix-AL] Microsoft 遥测静默丢弃实验：
//           *.events.data.microsoft.com 全天约 3.18 万条 info 日志，功能上可拦截。
//           改为 REJECT-DROP 以减少客户端重试和日志干扰的可能性；
//           在 log-level: info 下是否显著减少日志行，必须以后续运行日志验证。
//
//   [Fix-AM] ESET c.eset.com 精确直连（已在 v13.4.1 回退）：
//           Windows 11 + ESET Internet Security 19.1.4 下，c.eset.com:53535
//           UDP 反复出现 fake-ip/proxy 解析失败；仅对 c.eset.com 精确直连，
//           不放开整个 eset.com，避免改变 update.eset.com 当前正常的代理更新路径。
//
//   [Ops-AN] 稳定运行期日志级别改为 warning：
//           v13.3 已验证核心规则正常后，关闭每条连接的 info 记录，这是最确定的降噪手段。
//
// v13.3 变更说明（基于 Sparkle core-2026-5-25.log 日志分析）：
//
//   [Fix-AH] onecdn.static.microsoft 走代理：
//           Microsoft 新一代 CDN（.microsoft gTLD），后端 Cloudflare Anycast 104.18.x.x。
//           日志确认 res.public.onecdn.static.microsoft 直连超时 22 次。
//           2026 年 6 月起成为 Microsoft AutoUpdate 唯一下载源，趋势性问题。
//
//   [Fix-AI] challenges.cloudflare.com 走代理：
//           Cloudflare Turnstile 验证挑战唯一宿主域名，日志确认直连超时 181 次（TCP 成功率仅 1.6%）。
//           不可达会导致所有使用 Turnstile 的网站验证失败。
//
//   [Fix-AJ] csp-reporting.cloudflare.com 静默丢弃（REJECT-DROP）：
//           CSP 违规上报属于非功能性遥测，日志确认直连超时 52 次。
//           丢弃不影响页面功能，比走代理更干净。
//
// v13.2 变更说明（基于 v13 深度复核 + Mihomo 文档/源码校正）：
//
//   [Fix-AH] rule-providers 显式通过「节点选择」更新：
//           Mihomo rule-provider 支持 proxy 字段，用于指定规则集下载/更新路径。
//           为 Sukka、Loyalsoldier、blackmatrix7、ACL4SSR 全部 HTTP provider 设置 proxy，
//           避免 raw.githubusercontent.com / jsDelivr / ruleset.skk.moe 在不同网络环境下更新失败。
//
//   [Doc-AI] 修正 Cloudflare 注释表述：
//           cloudflare.dev / cloudflareinsights.com 是独立域名，不属于 cloudflare.com 子域树；
//           保留 v13 的 Cloudflare 控制面走代理、普通 cloudflare.com 数据面直连策略。
//
// v13 变更说明（基于 v2rayN 日志交叉验证 + v12.2/v12.3 评审优化）：
//
//   [Fix-AE] 补全 cloudflareinsights.com 显式走代理：
//           cloudflareinsights.com 是 Cloudflare Web Analytics（RUM）脚本托管的独立域名，
//           不属于 cloudflare.com 子域树。v2rayN 日志确认访问 Dashboard 时必然加载。
//           此前无显式规则，只靠 geosite/GFW 兜底"碰运气"，不可靠。
//           新增 DOMAIN-SUFFIX,cloudflareinsights.com,节点选择 + nameserver-policy。
//
//   [Fix-AF] 补全 cloudflare.dev 显式走代理：
//           ws.support-chat.cloudflare.dev 是 Dashboard 在线客服 WebSocket 通道，
//           cloudflare.dev 是独立域名（不被 DOMAIN-SUFFIX,cloudflare.com 覆盖）。
//           v2rayN 日志确认高频访问。此前无显式规则。
//           新增 DOMAIN-SUFFIX,cloudflare.dev,节点选择 + nameserver-policy。
//
//   [Fix-X'] foreignNameservers 移除 DoT，但不新增 dns.google（优化 v12.2 Fix-X）：
//           v12.2 移除 tls://8.8.8.8:853 是正确的（DoT 853 端口走代理不稳定）。
//           但新增的 https://dns.google/dns-query 与已有的 https://8.8.8.8/dns-query
//           是同一 Google DNS 的两种写法（冗余），且域名形式引入额外的解析依赖。
//           v13 只保留两条 IP 形式 DoH：Cloudflare 1.1.1.1 + Google 8.8.8.8。
//
//   [Fix-Y'] 恢复 DNS 服务器 IP-CIDR 显式走代理规则（回退 v12.2 Fix-Y）：
//           v12.2 移除 8.8.8.8/8.8.4.4/1.1.1.1/1.0.0.1 的 IP-CIDR 规则是不推荐的：
//           Mihomo 内部 DoH 连接最终仍以 IP 形式出站，显式 IP-CIDR 规则可提供更快匹配、
//           更清晰意图、更强韧性（不依赖兜底规则链路）。
//
//   [Fix-AA'] infinitynewtab 改走代理（优化 v12.2 Fix-AA）：
//           v12.2 用 REJECT-DROP 过于激进——扩展的壁纸/静态资源会完全无法加载。
//           改为走"节点选择"代理，既解决国内 DNS 无法解析的问题，又保留资源加载能力。
//
//   [Fix-AG] nameserver-policy Cloudflare 条目清理：
//           v12.3 同时保留 "dash.cloudflare.com" 和 "+.dash.cloudflare.com" 两条，
//           但 Mihomo 的 +. 前缀已覆盖域名本身及所有子域名，前者纯冗余。
//           统一使用 +. 写法，减少条目数。
//
// v12.3 继承的修复（均保留）：
//   [Fix-AC] Cloudflare Dashboard DOMAIN → DOMAIN-SUFFIX（覆盖 platform.dash 等子域）
//   [Fix-AD] sparrow.cloudflare.com 显式走代理
//   [Fix-Z]  IPv6 NCSI REJECT-DROP（ipv6.msftconnecttest/msftncsi）
//   [Fix-W]  TUN route-exclude-address（RFC 1918 全量）
//   [Fix-T]  Cursor 3.0 cursor.com 补充
//   [Fix-U]  keep-alive-idle 120s
//   [Fix-V]  udp-timeout 600s
//   [Fix-Q]  claude.com 显式海外 DNS
//   [Fix-R]  Cursor DOMAIN-SUFFIX 通配
//   [Fix-S]  statsigapi.net → 节点选择
//
// 适用：Sparkle-windows-1.26.4-x64 / Mihomo 内核，TUN + 规则模式
// 出差注意：酒店 Captive Portal 认证时请临时关闭 TUN（保留系统代理），认证完成后重启 TUN。

// ========== DNS ==========
const domesticNameservers = [
  "https://223.5.5.5/dns-query",
  "https://doh.pub/dns-query"
];

const foreignNameservers = [
  "https://1.1.1.1/dns-query",
  "https://8.8.8.8/dns-query"
];

// ========== Wi-Fi Calling / ePDG ==========
const ukWifiCallingGroup = "📞 UK VoWiFi（实验）";
const deWifiCallingGroup = "📞 DE VoWiFi";
const vodafoneDeWifiCallingGroup = "📞 Vodafone-DE VoWiFi（实验）";

// Vodafone DE 公共 DNS 在 2026-08-10 经 Cloudflare/Google DoH 复核为只有 CNAME、
// 未观察到公开 A/AAAA；以下固定地址不是运营商承诺的稳定接口。默认关闭，避免 hosts
// 绕过运营商后续 DNS 变更。
const ENABLE_VODAFONE_DE_EPDG_FALLBACK = false;

// 3GPP ePDG FQDN：epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
// VOXI 由 Vodafone 运营且官方称其网络由 Vodafone/Three 提供；本脚本按 Vodafone UK
// 的 234-15 ePDG 路径处理。若设备日志显示其他 HPLMN/ePDG，应以实测域名为准。
// EE 历史/现用 MNC 可能为 030/033；034 当前公共 DNS 返回 127.0.0.1，故不硬编码。
const ukEpdgDomains = [
  "epdg.epc.mnc010.mcc234.pub.3gppnetwork.org", // O2 / giffgaff 等
  "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org", // Vodafone UK / VOXI / Lebara 等
  "epdg.epc.mnc020.mcc234.pub.3gppnetwork.org", // Three / SMARTY / iD 等
  "epdg.epc.mnc030.mcc234.pub.3gppnetwork.org", // EE；CMLink 等 MVNO 需以实际日志为准
  "epdg.epc.mnc033.mcc234.pub.3gppnetwork.org"  // EE legacy Orange
];

const telekomDeEpdgDomains = [
  "epdg.epc.mnc001.mcc262.pub.3gppnetwork.org"
];

const vodafoneDeEpdgDomain =
  "epdg.epc.mnc002.mcc262.pub.3gppnetwork.org";

const o2DeEpdgDomains = [
  "epdg.epc.mnc003.mcc262.pub.3gppnetwork.org",
  "epdg.epc.mnc007.mcc262.pub.3gppnetwork.org"
];

const deEpdgDomains = [
  ...telekomDeEpdgDomains,
  ...o2DeEpdgDomains
];

// Vodafone DE 对公共递归 DNS 返回 CNAME，但目标主机在境外解析可能无 A/AAAA。
// 这三个地址在 2026-08-10 再次复核为 Vodafone AS3209 的 MNC 262-02 ePDG 候选网关；
// 其中 .170 有社区通过英国出口注册成功的个案，但不是官方稳定契约。启用前必须重新
// 核验地址归属、UDP 500/4500 出口一致性和实际 IKE 响应。
const vodafoneDeEpdgFallbackIps = [
  "139.7.117.168",
  "139.7.117.169",
  "139.7.117.170"
];

function proxiedDns(group) {
  return foreignNameservers.map(server => `${server}#${group}`);
}

const dnsConfig = {
  "enable": true,
  "listen": "127.0.0.1:1053",
  "ipv6": false,
  "prefer-h3": false,
  "respect-rules": true,
  "use-hosts": true,
  "use-system-hosts": false,
  "cache-algorithm": "arc",
  "enhanced-mode": "fake-ip",
  "fake-ip-range": "198.18.0.1/16",
  "fake-ip-filter": [
    "+.lan",
    "+.local",
    "+.home.arpa",
    "+.in-addr.arpa",
    "+.ip6.arpa",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "dns.msftncsi.com",
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "time.windows.com",
    "xbox.*.microsoft.com",
    "+.xboxlive.com",
    "time.*.com",
    "time.*.gov",
    "time.*.edu.cn",
    "ntp.*.com",
    "+.pool.ntp.org",
    "time.nist.gov",
    "stun.*.*",
    "stun.*.*.*",
    "+.stun.*.*",
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "*.battlenet.com.cn",
    "*.battlenet.com",
    "*.blzstatic.cn",
    "*.battle.net",
    "localhost.ptlogin2.qq.com",
    "localhost.sec.qq.com",
    "localhost.work.weixin.qq.com",
    "+.asusrouter.com",

    // ePDG 必须返回真实地址，不能把 IKEv2/IPsec 目的端替换为 fake-ip。
    "+.3gppnetwork.org",
    vodafoneDeEpdgDomain,
    ...deEpdgDomains,
    ...ukEpdgDomains
  ],
  "default-nameserver": ["223.5.5.5", "119.29.29.29"],
  "nameserver": [...foreignNameservers],
  "proxy-server-nameserver": [...domesticNameservers],
  "direct-nameserver": [...domesticNameservers],
  "direct-nameserver-follow-policy": true
};

// ========== Sniffer ==========
const snifferConfig = {
  "enable": true,
  "force-dns-mapping": true,
  "parse-pure-ip": true,
  "sniff": {
    "TLS": {
      "ports": [443, 8443]
    },
    "HTTP": {
      "ports": [80, "8080-8880"],
      "override-destination": true
    },
    "QUIC": {
      "ports": [443, 8443]
    }
  },
  "force-domain": [
    "+.v2ex.com",
    "+.netflix.com",
    "+.nflxvideo.net"
  ],
  "skip-domain": [
    "Mijia Cloud",
    "+.push.apple.com"
  ],
  "skip-src-address": [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "FC00::/7",
    "FE80::/10",
    "::1/128"
  ],
  "skip-dst-address": [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "FC00::/7",
    "FE80::/10",
    "::1/128"
  ]
};

// ========== Rule Providers ==========
// 所有远程规则集均显式走「节点选择」更新，避免规则集刷新依赖直连可达性。
const ruleProviderCommon = {
  "type": "http",
  "format": "yaml",
  "interval": 86400,
  "proxy": "节点选择"
};

const ruleProviderSukka = {
  "type": "http",
  "format": "text",
  "interval": 43200,
  "proxy": "节点选择"
};

const ruleProviders = {
  // --- Sukka 广告拦截四件套 + IP ---
  reject_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/reject.txt",
    path: "./ruleset/sukka/reject_non_ip.txt"
  },
  reject_non_ip_drop: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/reject-drop.txt",
    path: "./ruleset/sukka/reject_non_ip_drop.txt"
  },
  reject_non_ip_no_drop: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/reject-no-drop.txt",
    path: "./ruleset/sukka/reject_non_ip_no_drop.txt"
  },
  reject_domainset: {
    ...ruleProviderSukka,
    behavior: "domain",
    url: "https://ruleset.skk.moe/Clash/domainset/reject.txt",
    path: "./ruleset/sukka/reject_domainset.txt"
  },
  reject_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/ip/reject.txt",
    path: "./ruleset/sukka/reject_ip.txt"
  },

  // --- Sukka 服务 ---
  ai_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/ai.txt",
    path: "./ruleset/sukka/ai_non_ip.txt"
  },
  telegram_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/telegram.txt",
    path: "./ruleset/sukka/telegram_non_ip.txt"
  },
  telegram_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/ip/telegram.txt",
    path: "./ruleset/sukka/telegram_ip.txt"
  },
  apple_cdn: {
    ...ruleProviderSukka,
    behavior: "domain",
    url: "https://ruleset.skk.moe/Clash/domainset/apple_cdn.txt",
    path: "./ruleset/sukka/apple_cdn.txt"
  },
  apple_cn_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/apple_cn.txt",
    path: "./ruleset/sukka/apple_cn_non_ip.txt"
  },
  apple_services: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/apple_services.txt",
    path: "./ruleset/sukka/apple_services.txt"
  },
  microsoft_cdn_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/microsoft_cdn.txt",
    path: "./ruleset/sukka/microsoft_cdn_non_ip.txt"
  },
  microsoft_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/microsoft.txt",
    path: "./ruleset/sukka/microsoft_non_ip.txt"
  },

  // --- Sukka 下载流量 ---
  download_domainset: {
    ...ruleProviderSukka,
    behavior: "domain",
    url: "https://ruleset.skk.moe/Clash/domainset/download.txt",
    path: "./ruleset/sukka/download_domainset.txt"
  },
  download_non_ip: {
    ...ruleProviderSukka,
    behavior: "classical",
    url: "https://ruleset.skk.moe/Clash/non_ip/download.txt",
    path: "./ruleset/sukka/download_non_ip.txt"
  },

  // --- Loyalsoldier 核心规则集 ---
  reject: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
    path: "./ruleset/loyalsoldier/reject.yaml"
  },
  icloud: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt",
    path: "./ruleset/loyalsoldier/icloud.yaml"
  },
  apple: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
    path: "./ruleset/loyalsoldier/apple.yaml"
  },
  google: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
    path: "./ruleset/loyalsoldier/google.yaml"
  },
  proxy: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
    path: "./ruleset/loyalsoldier/proxy.yaml"
  },
  direct: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
    path: "./ruleset/loyalsoldier/direct.yaml"
  },
  private: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
    path: "./ruleset/loyalsoldier/private.yaml"
  },
  gfw: {
    ...ruleProviderCommon,
    behavior: "domain",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
    path: "./ruleset/loyalsoldier/gfw.yaml"
  },
  // tld-not-cn 已删除（v8/Fix-A）：与三重 GFW 高度冗余，且对 .io/.dev/.ai 国内服务有误杀
  cncidr: {
    ...ruleProviderCommon,
    behavior: "ipcidr",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
    path: "./ruleset/loyalsoldier/cncidr.yaml"
  },
  lancidr: {
    ...ruleProviderCommon,
    behavior: "ipcidr",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
    path: "./ruleset/loyalsoldier/lancidr.yaml"
  },
  applications: {
    ...ruleProviderCommon,
    behavior: "classical",
    url: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
    path: "./ruleset/loyalsoldier/applications.yaml"
  },

  // --- blackmatrix7 AI 服务规则集（作为手写规则的兜底补盲，覆盖未来新增的 AI 域名） ---
  bm7_openai: {
    ...ruleProviderCommon,
    behavior: "classical",
    url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml",
    path: "./ruleset/blackmatrix7/OpenAI.yaml"
  },
  bm7_claude: {
    ...ruleProviderCommon,
    behavior: "classical",
    url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml",
    path: "./ruleset/blackmatrix7/Claude.yaml"
  },
  bm7_gemini: {
    ...ruleProviderCommon,
    behavior: "classical",
    url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.yaml",
    path: "./ruleset/blackmatrix7/Gemini.yaml"
  },
  bm7_copilot: {
    ...ruleProviderCommon,
    behavior: "classical",
    url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Copilot/Copilot.yaml",
    path: "./ruleset/blackmatrix7/Copilot.yaml"
  },
  bm7_anthropic: {
    ...ruleProviderCommon,
    behavior: "classical",
    url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Anthropic/Anthropic.yaml",
    path: "./ruleset/blackmatrix7/Anthropic.yaml"
  },

  // --- ACL4SSR GFW 补充（解决 Facebook/Instagram 等掉进漏网之鱼） ---
  "proxy-gfwlist": {
    "type": "http",
    "format": "text",
    "behavior": "classical",
    "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyGFWlist.list",
    "path": "./ruleset/acl4ssr/proxy-gfwlist.list",
    "interval": 86400,
    "proxy": "节点选择"
  }
};

// ========== AI / 开发工具精细域名规则 ==========

// --- 开发工具：VS Code Marketplace / Cursor 安装包与下载 ---
const devToolRules = [
  "DOMAIN,marketplace.visualstudio.com,开发工具",
  "DOMAIN-SUFFIX,gallery.vsassets.io,开发工具",
  "DOMAIN-SUFFIX,gallerycdn.vsassets.io,开发工具",
  "DOMAIN,code.visualstudio.com,开发工具",
  "DOMAIN,update.code.visualstudio.com,开发工具",
  "DOMAIN,vscode.download.prss.microsoft.com,开发工具",
  "DOMAIN,download.visualstudio.microsoft.com,开发工具",
  "DOMAIN,vscode.dev,开发工具",
  "DOMAIN,vscode-sync.trafficmanager.net,开发工具",
  "DOMAIN,cursor-cdn.com,开发工具",
  "DOMAIN,anysphere-binaries.s3.us-east-1.amazonaws.com,开发工具"
];

// --- OpenAI / ChatGPT / Codex ---
const openaiRules = [
  "DOMAIN-SUFFIX,openai.com,AI",
  "DOMAIN-SUFFIX,chatgpt.com,AI",
  "DOMAIN-SUFFIX,oaistatic.com,AI",
  "DOMAIN-SUFFIX,oaiusercontent.com,AI",
  "DOMAIN-SUFFIX,oaistatsig.com,AI"
];

// --- Claude / Claude Code / Claude CLI ---
const claudeRules = [
  "DOMAIN,api.anthropic.com,AI",
  "DOMAIN,platform.claude.com,AI",
  "DOMAIN,downloads.claude.ai,AI",
  "DOMAIN,bridge.claudeusercontent.com,AI",
  "DOMAIN-SUFFIX,anthropic.com,AI",
  "DOMAIN-SUFFIX,claude.ai,AI",
  "DOMAIN-SUFFIX,claude.com,AI",
  "DOMAIN-SUFFIX,claude.app,AI",
  "DOMAIN-SUFFIX,claudemcpcontent.com,AI",
  "DOMAIN-SUFFIX,claudeusercontent.com,AI",
  "DOMAIN-SUFFIX,claudemcpclient.com,AI",
  "DOMAIN,clau.de,AI",
  "DOMAIN,anthropic.auth0.com,AI",
  // [Fix-S] statsigapi.net 改走「节点选择」而非「AI」：
  // statsigapi.net 是 Statsig（第三方 A/B 测试 SaaS）的通用域名，非 Anthropic 独占。
  // 不绑定到 AI 聚合组，避免选中节点拥塞时影响其他使用 Statsig 的应用。
  // 保留走代理（statsigapi.net 被 GFW 干扰，直连不可靠），但改用通用节点选择组。
  "DOMAIN-SUFFIX,statsigapi.net,节点选择"
];

// --- Gemini / Antigravity / Google AI Studio ---
const googleAIRules = [
  "DOMAIN,gemini.google.com,AI",
  "DOMAIN,generativelanguage.googleapis.com,AI",
  "DOMAIN,aistudio.google.com,AI",
  "DOMAIN,ai.google.dev,AI",
  "DOMAIN-SUFFIX,antigravity.google,AI"
];

// --- Cursor IDE ---
// [Fix-R] 从逐条精确 DOMAIN 改为 DOMAIN-SUFFIX 通配覆盖：
// Cursor 历史上已多次新增 API 端点（api2~api5、gcpp 系列等），
// 全部写精确 DOMAIN 需要随每次 Cursor 更新手动维护覆写脚本，极易遗漏。
// 改为 DOMAIN-SUFFIX,cursor.sh 和 DOMAIN-SUFFIX,cursorapi.com
// 可自动覆盖所有现有及未来的子域名，无需再手动添加。
// [Fix-T] Cursor 3.0（2026-04）引入 api.cursor.com 等新接口（Cloud Agents API 等），
// 补充 DOMAIN-SUFFIX,cursor.com 覆盖所有 *.cursor.com 子域名。
// Cursor 安装包与 CDN 已移入「开发工具」，API / 登录 / Cloud Agents 仍归「AI」。
const cursorRules = [
  "DOMAIN-SUFFIX,cursor.sh,AI",
  "DOMAIN-SUFFIX,cursor.com,AI",
  "DOMAIN-SUFFIX,cursorapi.com,AI"
];

// --- AI 聚合服务 ---
const aiMiscRules = [
  "DOMAIN-SUFFIX,perplexity.ai,AI",
  "DOMAIN-SUFFIX,x.ai,AI",
  "DOMAIN,copilot.microsoft.com,AI",
  "DOMAIN-SUFFIX,openrouter.ai,AI",
  "DOMAIN-SUFFIX,mistral.ai,AI",
  "DOMAIN-SUFFIX,cohere.ai,AI",
  "DOMAIN-SUFFIX,cohere.com,AI",
  "DOMAIN-SUFFIX,devin.ai,AI",
  "DOMAIN-SUFFIX,kiro.dev,AI",
  "DOMAIN-SUFFIX,dify.ai,AI",
  "DOMAIN-SUFFIX,duck.ai,AI",
  "DOMAIN-SUFFIX,poe.com,AI",
  "DOMAIN-SUFFIX,windsurf.com,AI",
  "DOMAIN-SUFFIX,huggingface.co,AI",
  "DOMAIN-SUFFIX,huggingface.com,AI"
];

// ========== 通用域名规则 ==========
const customRules = [
  // --- Microsoft（OneDrive/Login 精确救回在 rules 主体第 2 步） ---
  "DOMAIN-SUFFIX,microsoftonline.com,微软服务",
  "DOMAIN-SUFFIX,bing.com,微软服务",
  "DOMAIN-SUFFIX,office.com,微软服务",
  "DOMAIN-SUFFIX,office.net,微软服务",
  "DOMAIN-SUFFIX,office365.com,微软服务",
  "DOMAIN-SUFFIX,live.com,微软服务",

  // --- YouTube（合并到谷歌服务）---
  "DOMAIN-SUFFIX,youtube.com,谷歌服务",
  "DOMAIN-SUFFIX,youtu.be,谷歌服务",
  "DOMAIN-SUFFIX,ytimg.com,谷歌服务",
  "DOMAIN-SUFFIX,googlevideo.com,谷歌服务",
  "DOMAIN,youtubei.googleapis.com,谷歌服务",

  // --- 社交媒体（走节点选择，不设独立组） ---
  "DOMAIN-SUFFIX,facebook.com,节点选择",
  "DOMAIN-SUFFIX,fbcdn.net,节点选择",
  "DOMAIN-SUFFIX,fb.com,节点选择",
  "DOMAIN-SUFFIX,instagram.com,节点选择",
  "DOMAIN-SUFFIX,cdninstagram.com,节点选择",
  "DOMAIN-SUFFIX,twitter.com,节点选择",
  "DOMAIN-SUFFIX,x.com,节点选择",
  "DOMAIN-SUFFIX,twimg.com,节点选择",
  "DOMAIN-SUFFIX,t.co,节点选择",
  "DOMAIN-SUFFIX,reddit.com,节点选择",
  "DOMAIN-SUFFIX,redd.it,节点选择",
  "DOMAIN-SUFFIX,redditstatic.com,节点选择",
  "DOMAIN-SUFFIX,discord.com,节点选择",
  "DOMAIN-SUFFIX,discord.gg,节点选择",
  "DOMAIN-SUFFIX,discordapp.com,节点选择",
  "DOMAIN-SUFFIX,discordapp.net,节点选择",
  "DOMAIN-SUFFIX,whatsapp.com,节点选择",
  "DOMAIN-SUFFIX,whatsapp.net,节点选择",
  "DOMAIN-SUFFIX,line.me,节点选择",
  "DOMAIN-SUFFIX,line-scdn.net,节点选择",
  "DOMAIN-SUFFIX,naver.jp,节点选择",
  "DOMAIN-SUFFIX,pinterest.com,节点选择",
  "DOMAIN-SUFFIX,pinimg.com,节点选择",
  "DOMAIN-SUFFIX,tiktok.com,节点选择",
  "DOMAIN-SUFFIX,tiktokv.com,节点选择",
  "DOMAIN-SUFFIX,tiktokcdn.com,节点选择",

  // --- GitHub ---
  "DOMAIN-SUFFIX,github.com,节点选择",
  "DOMAIN-SUFFIX,github.io,节点选择",
  "DOMAIN-SUFFIX,githubusercontent.com,节点选择",
  "DOMAIN-SUFFIX,githubassets.com,节点选择",
  "DOMAIN-SUFFIX,ghcr.io,节点选择",

  // --- Google 补强 ---
  "DOMAIN-SUFFIX,googleapis.cn,谷歌服务",
  "DOMAIN-SUFFIX,gstatic.com,谷歌服务",
  "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,谷歌服务",

  // --- 国内冷门站直连 ---
  "DOMAIN-SUFFIX,asusrouter.com,全局直连"
];

// ========== 噪音 / 解析失败静默拦截 ==========
// [Fix-Z][Fix-AA v12.2] 这些请求在日志中会反复出现 "dns resolve failed" 或
// "i/o timeout"，但实际功能不重要（IPv6 网络检测、新标签页扩展壁纸等）。
// 用 REJECT-DROP 静默丢弃，避免污染日志、误导排查。
// 注意：必须放在 stabilityAllowRules 之前，否则会被 msftconnecttest/msftncsi 的
// DIRECT 规则提前命中。
const noisyRejectRules = [
  // Windows NCSI IPv6 端点（ipv6:false 时必失败，拦截后系统会 fallback 到 IPv4）
  "DOMAIN,ipv6.msftconnecttest.com,REJECT-DROP",
  "DOMAIN,ipv6.msftncsi.com,REJECT-DROP",
  // [Fix-AL v13.4] Microsoft 遥测：功能上可拦截，REJECT-DROP 的降噪效果需后续日志验证
  "DOMAIN-SUFFIX,events.data.microsoft.com,REJECT-DROP",
  // Chrome/Edge 新标签页扩展（infinitynewtab 等）的海外静态资源
  // 命中 Loyalsoldier direct.txt 后走 DIRECT 必然解析失败
  // [Fix-AA' v13] 改走代理而非 REJECT-DROP，保留扩展壁纸/资源加载能力
  "DOMAIN-SUFFIX,infinitynewtab.com,节点选择"
];

// ========== 高优先级稳定性救回 ==========
// 放在广告拦截之前，用于降低登录、验证码、支付等基础功能被广告规则误伤的概率。
// 仅保留小范围关键域名；出问题时仍可通过「广告拦截」/「广告静默拦截」策略组排查。
const stabilityAllowRules = [
  // Microsoft 登录 / OneDrive / Windows 联网检测
  "DOMAIN-KEYWORD,outlook.office,DIRECT",
  "DOMAIN-SUFFIX,login.microsoftonline.com,DIRECT",
  "DOMAIN-SUFFIX,login.live.com,DIRECT",
  "DOMAIN-SUFFIX,account.live.com,DIRECT",
  "DOMAIN-SUFFIX,onedrive.live.com,节点选择",
  "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",
  "DOMAIN-SUFFIX,msftncsi.com,DIRECT",

  // [Fix-AK v13.4] 微信功能域名精确救回；badjs.weixinbridge.com 默认不救回（错误上报链路）
  "DOMAIN,wxa.wxs.qq.com,DIRECT",
  "DOMAIN,dns.weixin.qq.com.cn,DIRECT",

  // [Fix-AH v13.3] Microsoft 新一代 CDN（.microsoft gTLD，后端 Cloudflare）
  // 日志确认 res.public.onecdn.static.microsoft 解析到 104.18.x.x，直连超时。
  // 该 CDN 端点 2026 年 6 月起成为 Microsoft AutoUpdate 唯一下载源。
  "DOMAIN-SUFFIX,onecdn.static.microsoft,节点选择",

  // Cloudflare 分流（v13 完善）：
  //   控制面（Dashboard / API / 遥测 / 分析 / 客服）走代理 —— Anycast IP
  //   104.16.0.0/12 段在国内被严重 QoS + 间歇 RST，直连不可用。
  //   数据面（普通 CDN 站点）保持直连，复用国内 PoP 缓存。
  //   [Fix-AE] cloudflareinsights.com 是独立域名（不属于 cloudflare.com 子域树），v2rayN 日志确认必须加载。
  //   [Fix-AF] cloudflare.dev 是独立域名（不属于 cloudflare.com 子域树），v2rayN 日志确认高频访问。
  "DOMAIN-SUFFIX,dash.cloudflare.com,节点选择",
  "DOMAIN-SUFFIX,api.cloudflare.com,节点选择",
  "DOMAIN-SUFFIX,sparrow.cloudflare.com,节点选择",
  // [Fix-AI v13.3] Cloudflare Turnstile 验证挑战域名，日志确认 181 次直连超时。
  // 不可达会导致所有使用 Turnstile 的网站验证失败。
  "DOMAIN-SUFFIX,challenges.cloudflare.com,节点选择",
  "DOMAIN-SUFFIX,cloudflareinsights.com,节点选择",
  "DOMAIN-SUFFIX,cloudflare.dev,节点选择",
  // AI Gateway 必须先于 cloudflare.com 通用直连规则匹配。
  "DOMAIN,gateway.ai.cloudflare.com,AI",
  // [Fix-AJ v13.3] CSP 违规上报域名，非功能性遥测，静默丢弃即可。
  "DOMAIN-SUFFIX,csp-reporting.cloudflare.com,REJECT-DROP",
  "DOMAIN-SUFFIX,cloudflare-cn.com,DIRECT",
  "DOMAIN-SUFFIX,cloudflare.com,DIRECT",

  // 验证码 / 风控挑战
  "DOMAIN-SUFFIX,hcaptcha.com,节点选择",
  "DOMAIN-SUFFIX,recaptcha.net,谷歌服务",

  // 支付基础链路
  "DOMAIN-SUFFIX,paypal.com,节点选择",
  "DOMAIN-SUFFIX,paypalobjects.com,节点选择",
  "DOMAIN-SUFFIX,stripe.com,节点选择",
  "DOMAIN-SUFFIX,stripe.network,节点选择"
];

// ========== Wi-Fi Calling 规则 ==========
// 仅分流 ePDG/IMS 数据面，不把运营商官网、门户和普通业务域名整体送入电话出口。
// 规则必须位于广告、GFW、GEOIP 和通用兜底之前。
const wifiCallingRules = [
  // UK 主网及共用其 IMS 的 MVNO（VOXI 按 Vodafone UK 的 234-15 路径处理）。
  // CMLink 等 MVNO 若使用标准 mcc234 ePDG 会被下方正则覆盖；实际 MNC 以日志为准。
  ...ukEpdgDomains.map(
    domain => `DOMAIN,${domain},${ukWifiCallingGroup}`
  ),
  `DOMAIN-REGEX,^epdg\\.epc\\.mnc[0-9]{3}\\.mcc23[45]\\.pub\\.3gppnetwork\\.org$,${ukWifiCallingGroup}`,

  // Vodafone DE：官方不支持境外使用；固定网关规则只在显式启用 hosts 兜底时装配。
  `DOMAIN,${vodafoneDeEpdgDomain},${vodafoneDeWifiCallingGroup}`,
  ...(
    ENABLE_VODAFONE_DE_EPDG_FALLBACK
      ? vodafoneDeEpdgFallbackIps.map(
          ip => `IP-CIDR,${ip}/32,${vodafoneDeWifiCallingGroup},no-resolve`
        )
      : []
  ),

  // Telekom DE / O2 DE 官方支持境外 WLAN Call：DE 组默认 DIRECT，必要时可切德国节点。
  ...deEpdgDomains.map(
    domain => `DOMAIN,${domain},${deWifiCallingGroup}`
  ),
  // Vodafone DE 精确规则位于通用德国规则之前，不会被 DE 组覆盖。
  `DOMAIN-REGEX,^epdg\\.epc\\.mnc[0-9]{3}\\.mcc262\\.pub\\.3gppnetwork\\.org$,${deWifiCallingGroup}`,

  // 其余国家标准 ePDG 保持原生直连。
  "DOMAIN-REGEX,^epdg\\.epc\\.mnc[0-9]{3}\\.mcc[0-9]{3}\\.pub\\.3gppnetwork\\.org$,DIRECT"
];

// ========== 规则总装配 ==========
const rules = [
  // 0A. VoWiFi：最高优先级处理 UK/DE ePDG；Vodafone 固定网关仅在显式启用时装配。
  ...wifiCallingRules,

  // 0. 进程直连（高优先级，TUN 模式下迅雷等下载工具绕过代理）
  "PROCESS-NAME,Thunder.exe,DIRECT",
  "PROCESS-NAME,DownloadSDKServer.exe,DIRECT",
  "PROCESS-NAME,upnp.exe,DIRECT",
  "PROCESS-NAME,APlayer.exe,DIRECT",
  "PROCESS-NAME,DownloadService.exe,DIRECT",
  "PROCESS-NAME,P2PService.exe,DIRECT",
  "PROCESS-PATH-REGEX,(?i)Thunder.*\\.exe$,DIRECT",

  // 1. [Fix-Y' v13] DNS 服务器 IP 显式走代理（恢复 v12 原版，提供更快匹配和更强韧性）
  "IP-CIDR,8.8.8.8/32,节点选择,no-resolve",
  "IP-CIDR,8.8.4.4/32,节点选择,no-resolve",
  "IP-CIDR,1.1.1.1/32,节点选择,no-resolve",
  "IP-CIDR,1.0.0.1/32,节点选择,no-resolve",

  // 2. [Fix-Z][Fix-AA'] 静默丢弃 IPv6 NCSI + 代理新标签页扩展资源
  ...noisyRejectRules,

  // 3. 基础功能救回（MUST 在广告拦截之前）
  ...stabilityAllowRules,

  // 4. Sukka 广告拦截（可在 UI 中临时切 DIRECT 排查误杀）
  // 语义顺序：drop 优先静默丢弃 → domainset 大覆盖面 → non_ip classical → no_drop 明确 REJECT
  "RULE-SET,reject_non_ip_drop,广告静默拦截",
  "RULE-SET,reject_domainset,广告拦截",
  "RULE-SET,reject_non_ip,广告拦截",
  "RULE-SET,reject_non_ip_no_drop,广告拦截",

  // 5. GEOSITE 隐私拦截
  "GEOSITE,WIN-SPY,全局拦截",
  //"GEOSITE,WIN-EXTRA,全局拦截",

  // 6. Loyalsoldier 广告域名
  "RULE-SET,reject,全局拦截",

  // 7. PT / Tracker 直连
  "GEOSITE,CATEGORY-PUBLIC-TRACKER,DIRECT",
  "GEOSITE,CATEGORY-PT,DIRECT",

  // 8. AI / 开发工具精确域名（在 Sukka microsoft/google 规则集之前，避免被泛规则吞）
  ...devToolRules,
  ...openaiRules,
  ...claudeRules,
  ...googleAIRules,
  ...cursorRules,
  ...aiMiscRules,

  // 9. blackmatrix7 AI 规则集兜底（手写规则未覆盖的 AI 域名由此捕获）
  "RULE-SET,bm7_openai,AI",
  "RULE-SET,bm7_claude,AI",
  "RULE-SET,bm7_anthropic,AI",
  "RULE-SET,bm7_gemini,AI",
  "RULE-SET,bm7_copilot,AI",

  // 10. Sukka 服务分流
  "RULE-SET,telegram_non_ip,节点选择",
  "RULE-SET,apple_cdn,全局直连",
  "RULE-SET,apple_cn_non_ip,全局直连",
  "RULE-SET,microsoft_cdn_non_ip,全局直连",
  "RULE-SET,apple_services,苹果服务",
  "RULE-SET,microsoft_non_ip,微软服务",
  "RULE-SET,ai_non_ip,AI",

  // 11. 手写域名补强
  ...customRules,

  // 12. 下载流量走「下载」组（默认走节点选择，可手动切全局直连省流量）
  "RULE-SET,download_domainset,下载",
  "RULE-SET,download_non_ip,下载",

  // 13. 通用规则集
  "RULE-SET,applications,全局直连",
  "RULE-SET,private,全局直连",
  "RULE-SET,icloud,苹果服务",
  "RULE-SET,apple,苹果服务",
  "RULE-SET,google,谷歌服务",

  // 14. 三重 GFW 保障（proxy + gfw + ACL4SSR）
  "RULE-SET,proxy,节点选择",
  "RULE-SET,gfw,节点选择",
  "RULE-SET,proxy-gfwlist,节点选择",
  "RULE-SET,direct,全局直连",

  // 15. 国内域名直连
  "GEOSITE,CN,全局直连",

  // 16. IP 类规则
  "RULE-SET,reject_ip,广告拦截,no-resolve",
  "IP-CIDR,160.79.104.0/21,AI,no-resolve",
  // 注：全局 ipv6:false 时此条不生效；保留是为了未来开启 IPv6 时自动覆盖 Anthropic 的 v6 段
  "IP-CIDR6,2607:6bc0::/32,AI,no-resolve",
  "IP-ASN,399358,AI,no-resolve",
  "RULE-SET,telegram_ip,节点选择,no-resolve",
  "RULE-SET,lancidr,全局直连,no-resolve",
  "RULE-SET,cncidr,全局直连,no-resolve",
  "GEOIP,LAN,全局直连,no-resolve",
  "GEOIP,CN,全局直连,no-resolve",

  // 17. 漏网之鱼（走代理，确保 DNS 不泄漏）
  "MATCH,漏网之鱼"
];

// ========== Proxy Groups ==========
const HEALTH_CHECK_URL = "https://www.gstatic.com/generate_204";

const groupCommonOption = {
  "url": HEALTH_CHECK_URL,
  "timeout": 5000,
  "expected-status": 204,
  "hidden": false
};

const periodicSelectGroupOption = {
  ...groupCommonOption,
  "interval": 300,
  "lazy": true
};

const autoTestGroupOption = {
  ...groupCommonOption,
  "interval": 300,
  "lazy": true,
  "tolerance": 100,
  "empty-fallback": "REJECT"
};

function main(config) {
  const proxyCount = config?.proxies?.length ?? 0;
  const proxyProviderCount =
    typeof config?.["proxy-providers"] === "object"
      ? Object.keys(config["proxy-providers"]).length
      : 0;

  if (proxyCount === 0 && proxyProviderCount === 0) {
    throw new Error("配置文件中未找到任何代理");
  }

  Object.assign(config, {
    mode: "rule",
    "log-level": "warning",
    ipv6: false,
    "find-process-mode": "strict",
    "unified-delay": true,
    "tcp-concurrent": true,
    "keep-alive-interval": 30,
    "keep-alive-idle": 120,
    profile: {
      ...(config.profile || {}),
      "store-selected": true,
      "store-fake-ip": true
    }
  });

  // Vodafone DE 固定 ePDG 地址默认不注入。只有显式打开实验开关时，才在保留用户
  // 其他 hosts 的前提下覆盖这一精确域名；关闭开关不会删除用户原配置中的同名 hosts。
  if (ENABLE_VODAFONE_DE_EPDG_FALLBACK) {
    config.hosts = {
      ...(config.hosts || {}),
      [vodafoneDeEpdgDomain]: vodafoneDeEpdgFallbackIps
    };
  }

  // DNS
  config.dns = { ...dnsConfig };
  config.dns["nameserver-policy"] = {
    // 显式域名与通配域名分开列出，减少对 geosite 兜底的依赖。
    // 注意：不同 Mihomo 版本对 nameserver-policy 中精确 / 通配 / geosite 重叠命中的处理细节
    // 可能存在实现差异；因此这里不依赖隐含顺序，而是对关键服务做显式覆盖。

    // --- 国内直连域名走国内 DNS ---
    "geosite:cn,private": domesticNameservers,
    "geosite:apple,icloud,microsoft": domesticNameservers,
    "+.onedrive.live.com": foreignNameservers,

    // --- 需要海外 DNS 解析的服务（精确域名优先列出）---

    // Cloudflare 控制面走海外 DNS（GFW 有 SNI 干扰，国内 DNS 返回中国 CDN IP 会导致控制面超时）
    // [Fix-AG v13] 统一使用 +. 写法（覆盖域名本身 + 全部子域名），移除冗余的精确条目
    "+.dash.cloudflare.com": foreignNameservers,
    "+.api.cloudflare.com": foreignNameservers,
    "+.sparrow.cloudflare.com": foreignNameservers,
    // [Fix-AI v13.3] Turnstile 验证挑战走海外 DNS（防御性，fake-ip 代理流量实际不触发本地解析）
    "+.challenges.cloudflare.com": foreignNameservers,
    // [Fix-AE] cloudflareinsights.com 是独立域名（Cloudflare Web Analytics / RUM）
    "+.cloudflareinsights.com": foreignNameservers,
    // [Fix-AF] cloudflare.dev 是独立域名（Dashboard 客服 WebSocket 等）
    "+.cloudflare.dev": foreignNameservers,
    // [Fix-AH v13.3] Microsoft 新一代 CDN（.microsoft gTLD，后端 Cloudflare Anycast）
    "+.onecdn.static.microsoft": foreignNameservers,
    // 其余 cloudflare 子域名走国内 DNS（cloudflare 在国内有大量 CDN 节点）
    "+.cloudflare-cn.com": domesticNameservers,
    "+.cloudflare.com": domesticNameservers,

    // AI 服务精确覆盖（覆盖 geosite:microsoft 对部分域名的国内解析）
    "+.openai.com": foreignNameservers,
    "+.chatgpt.com": foreignNameservers,
    "+.oaistatic.com": foreignNameservers,
    "+.oaiusercontent.com": foreignNameservers,
    "+.oaistatsig.com": foreignNameservers,
    "+.anthropic.com": foreignNameservers,
    "+.claude.ai": foreignNameservers,
    // [Fix-Q] 保留 claude.com 的显式海外 DNS 覆盖：
    // 该项在上传的 v10/v11 基线中已存在，并非 v12 新增。
    // 继续显式列出是为了降低 geosite 数据滞后或规则库变动导致的解析不确定性，
    // 对 Claude Code / Claude CLI / 浏览器访问 Claude 均更稳妥。
    "+.claude.com": foreignNameservers,
    "+.claude.app": foreignNameservers,
    "+.claudemcpcontent.com": foreignNameservers,
    "+.claudeusercontent.com": foreignNameservers,
    "+.claudemcpclient.com": foreignNameservers,
    "clau.de": foreignNameservers,
    "anthropic.auth0.com": foreignNameservers,
    // [Fix-S] statsigapi.net 保持海外 DNS 解析（被 GFW 干扰，直连不可靠）
    "+.statsigapi.net": foreignNameservers,
    "gateway.ai.cloudflare.com": foreignNameservers,
    "+.openrouter.ai": foreignNameservers,
    "+.mistral.ai": foreignNameservers,
    "+.cohere.ai": foreignNameservers,
    "+.cohere.com": foreignNameservers,
    "+.devin.ai": foreignNameservers,
    "+.kiro.dev": foreignNameservers,
    "+.dify.ai": foreignNameservers,
    "+.duck.ai": foreignNameservers,
    "+.poe.com": foreignNameservers,
    "+.windsurf.com": foreignNameservers,
    "+.huggingface.co": foreignNameservers,
    "+.huggingface.com": foreignNameservers,

    // [Fix-R] Cursor 域名策略简化为通配写法（与规则改动保持一致）
    "+.cursor.sh": foreignNameservers,
    "+.cursor.com": foreignNameservers,
    "+.cursorapi.com": foreignNameservers,
    "cursor-cdn.com": foreignNameservers,

    // Google AI 服务
    "gemini.google.com": foreignNameservers,
    "ai.google.dev": foreignNameservers,
    "aistudio.google.com": foreignNameservers,
    "+.antigravity.google": foreignNameservers,

    // 开发工具（覆盖 geosite:microsoft 的国内解析）
    "copilot.microsoft.com": foreignNameservers,
    "marketplace.visualstudio.com": foreignNameservers,
    "vscode.download.prss.microsoft.com": foreignNameservers,
    "download.visualstudio.microsoft.com": foreignNameservers,
    "vscode.dev": foreignNameservers,

    // --- Wi-Fi Calling / ePDG ---
    // UK 实验路径通过英国出口查询；德国官方路径默认由 DE 组的 DIRECT 查询，必要时可
    // 手动切德国节点。Vodafone DE 单独进入实验组；固定 hosts 仅在显式开关开启时生效。
    ...Object.fromEntries(
      ukEpdgDomains.map(domain => [
        domain,
        proxiedDns(ukWifiCallingGroup)
      ])
    ),
    "+.mcc234.pub.3gppnetwork.org": proxiedDns(ukWifiCallingGroup),
    "+.mcc235.pub.3gppnetwork.org": proxiedDns(ukWifiCallingGroup),
    ...Object.fromEntries(
      deEpdgDomains.map(domain => [
        domain,
        proxiedDns(deWifiCallingGroup)
      ])
    ),
    [vodafoneDeEpdgDomain]: proxiedDns(vodafoneDeWifiCallingGroup),

    // --- GFW 相关服务走海外 DNS（通配符兜底）---
    "geosite:geolocation-!cn": foreignNameservers,
    "geosite:google,youtube,telegram,gfw": foreignNameservers
  };

  // TUN：启停由 Sparkle UI 控制，脚本仅设置参数
  // [Fix-W][Doc-AR] route-exclude-address：请求 auto-route 排除 RFC 1918 私有地址段，
  // 以减少 LAN 流量被 TUN 捕获造成的冲突。该字段不保证 Windows 多网卡环境一定绕过 TUN，
  // 也不保证 DIRECT 自动选择正确物理出口；实际路径仍以最终配置、系统路由和核心日志为准。
  // 注：sniffer.skip-dst-address 额外包含 100.64/10、127/8、169.254/16 等边界段，
  // 此处仅保留 RFC 1918 三段（loopback 不经 TUN，其余边界段普通家用场景无需排除）。
  config.tun = {
    ...(config.tun || {}),
    "stack": "mixed",
    "auto-route": true,
    "auto-detect-interface": true,
    "dns-hijack": ["any:53", "tcp://any:53"],
    "strict-route": true,
    "udp-timeout": 600,
    "route-exclude-address": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  };

  // Sniffer
  config["sniffer"] = snifferConfig;

  // 节点过滤
  const filterKeywords = "(?:官网|套餐|流量|expiring|剩余|時間|重置|URL|到期|过期|机场|group|sub|订阅|查询|续费|观看|频道|客服|M3U|车费|车友|上车|通知|公告|严禁|测速)";
  // 英文标记允许紧邻编号、中文或分隔符，但不得嵌入其他英文单词。
  // 地区组与「其他」共用识别词，避免 LAX 等机场代码同时落入两类组。
  const regionKeywords = {
    HK: "(?:香港|🇭🇰|(?:^|[^A-Za-z])(?:HK|Hong\\s*Kong)(?=$|[^A-Za-z]))",
    TW: "(?:台湾|臺灣|🇹🇼|(?:^|[^A-Za-z])(?:TW|Taiwan|Taipei|TPE|TSA|KHH)(?=$|[^A-Za-z]))",
    JP: "(?:日本|🇯🇵|(?:^|[^A-Za-z])(?:JP|Japan|NRT|HND|KIX|CTS|FUK)(?=$|[^A-Za-z]))",
    SG: "(?:狮城|新加坡|🇸🇬|(?:^|[^A-Za-z])(?:SG|Singapore|SIN|XSP)(?=$|[^A-Za-z]))",
    US: "(?:美国|🇺🇸|(?:^|[^A-Za-z])(?:US|USA|United\\s*States|America|SJC|JFK|LAX|ORD|SFO|SEA|IAD)(?=$|[^A-Za-z]))",
    DE: "(?:德国|德國|🇩🇪|(?:^|[^A-Za-z])(?:DE|Germany|Deutschland|Frankfurt|FRA)(?=$|[^A-Za-z]))",
    UK: "(?:英国|英國|🇬🇧|(?:^|[^A-Za-z])(?:UK|GB|United\\s*Kingdom|Britain|England|London|LHR|LGW)(?=$|[^A-Za-z]))"
  };
  const regionKeywordsRegex = `(?:${Object.values(regionKeywords).join("|")})`;
  const nodeFilterString = `(?i)^(?!.*${filterKeywords}).*$`;
  const otherFilterString = `(?i)^(?!.*${filterKeywords})(?!.*${regionKeywordsRegex}).*$`;

  // 保留游戏与既有倍率排除；GAME 按标签匹配，避免误排 EUGameHost 等服务商名称。
  const excludeSuffix = "(?!.*(?:游戏|娱乐节点|(?:^|[^A-Za-z])GAME(?=$|[^A-Za-z])|5x|10x))";
  const regionNodeFilter = region =>
    `(?i)^(?!.*${filterKeywords})${excludeSuffix}(?=.*${region}).*$`;
  const REGEX = {
    TW: regionNodeFilter(regionKeywords.TW),
    JP: regionNodeFilter(regionKeywords.JP),
    SG: regionNodeFilter(regionKeywords.SG),
    US: regionNodeFilter(regionKeywords.US),
    DE: regionNodeFilter(regionKeywords.DE),
    UK: regionNodeFilter(regionKeywords.UK)
  };

  const autoRegionGroups = [
    "🌍 自动-Global",
    "🇹🇼 自动-TW",
    "🇯🇵 自动-JP",
    "🇸🇬 自动-SG",
    "🇺🇸 自动-US",
    "🧩 自动-其他"
  ];

  // AI / 开发服务默认跟随手动-US 锚点（稳定优先，防止自动切换）
  const stableAIProxies = [
    "🇺🇸 手动-US",
    "节点选择",
    "🇺🇸 自动-US",
    "🌍 自动-Global",
    "🇯🇵 自动-JP",
    "🇸🇬 自动-SG",
    "🇹🇼 自动-TW",
    "🧩 自动-其他"
  ];

  config["proxy-groups"] = [
    // ---- 主选择组 ----
    {
      ...periodicSelectGroupOption,
      name: "节点选择",
      type: "select",
      proxies: ["🇺🇸 手动-US", "🌍 自动-Global", "🇯🇵 自动-JP", "🇸🇬 自动-SG", "🇺🇸 自动-US", "🇹🇼 自动-TW", "🧩 自动-其他"],
      "include-all": true,
      filter: nodeFilterString,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg"
    },

    // 手动-US：只列出 US 节点，手动挑选最信任的那个
    {
      ...periodicSelectGroupOption,
      name: "🇺🇸 手动-US",
      type: "select",
      proxies: ["🇺🇸 自动-US"],
      "include-all": true,
      filter: REGEX.US,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/us.svg"
    },

    // ---- VoWiFi 专用组 ----
    // UK：多数运营商不正式支持境外使用，首选英国出口只属于实验性兼容路径。
    {
      ...groupCommonOption,
      // 保留本版电话组原有周期检查。
      "interval": 300,
      name: ukWifiCallingGroup,
      type: "select",
      proxies: ["🇬🇧 自动-UK", "节点选择", "DIRECT"],
      "include-all": true,
      "disable-udp": false,
      filter: REGEX.UK,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/network.svg"
    },
    // Telekom DE / O2 DE：官方支持境外 WLAN Call，默认 DIRECT；德国节点用于当地网络
    // 阻断 DNS、UDP 500/4500 或 ePDG 时的受控对照。
    {
      ...groupCommonOption,
      // 保留本版电话组原有周期检查。
      "interval": 300,
      name: deWifiCallingGroup,
      type: "select",
      proxies: ["DIRECT", "🇩🇪 自动-DE", "节点选择"],
      "include-all": true,
      "disable-udp": false,
      filter: REGEX.DE,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/network.svg"
    },
    // Vodafone DE：官方不支持境外使用；德国出口为首选实验路径。保留 UK 自动组用于
    // 复现“固定 ePDG hosts + 英国出口”的社区个案，不能据此推断英国出口普遍可用。
    {
      ...groupCommonOption,
      // 保留本版电话组原有周期检查。
      "interval": 300,
      name: vodafoneDeWifiCallingGroup,
      type: "select",
      proxies: ["🇩🇪 自动-DE", "🇬🇧 自动-UK", "节点选择", "DIRECT"],
      "include-all": true,
      "disable-udp": false,
      filter: REGEX.DE,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/network.svg"
    },

    // ---- AI 服务组 ----
    // AI 聚合组：OpenAI / Claude / Google AI / Cursor API / Copilot / 其他 AI
    {
      ...groupCommonOption,
      name: "AI",
      type: "select",
      proxies: [...stableAIProxies, "全局直连"],
      "include-all": true,
      filter: nodeFilterString,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg"
    },

    // 开发工具：VS Code Marketplace、编辑器更新与 Cursor 安装包/CDN
    {
      ...groupCommonOption,
      name: "开发工具",
      type: "select",
      proxies: ["节点选择", ...autoRegionGroups, "全局直连"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg"
    },

    // ---- 其他服务组 ----
    {
      ...groupCommonOption,
      name: "谷歌服务",
      type: "select",
      proxies: ["节点选择", ...autoRegionGroups, "全局直连"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/google.svg"
    },
    {
      ...groupCommonOption,
      name: "苹果服务",
      type: "select",
      proxies: ["全局直连", "节点选择", ...autoRegionGroups],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/apple.svg"
    },
    {
      ...groupCommonOption,
      name: "微软服务",
      type: "select",
      proxies: ["全局直连", "节点选择", ...autoRegionGroups],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/microsoft.svg"
    },
    // ---- 功能组 ----
    // 静默广告拦截策略组：仅用于 reject_non_ip_drop
    // 默认 REJECT-DROP；需要日志时可切 REJECT，需要排查时可切 DIRECT
    {
      ...groupCommonOption,
      name: "广告静默拦截",
      type: "select",
      proxies: ["REJECT-DROP", "REJECT", "DIRECT"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/bug.svg"
    },
    // 广告拦截策略组：Sukka 常规拦截 + reject_ip 走此组
    // 默认 REJECT；遇到某网站打不开时，可在 Sparkle UI 临时切 DIRECT 排查
    {
      ...groupCommonOption,
      name: "广告拦截",
      type: "select",
      proxies: ["REJECT", "DIRECT", "REJECT-DROP"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/bug.svg"
    },
    {
      ...groupCommonOption,
      name: "全局拦截",
      // 默认 REJECT（非 DROP），便于在 Sparkle 日志中看到被拦截的请求
      type: "select",
      proxies: ["REJECT", "REJECT-DROP", "DIRECT"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/bug.svg"
    },
    {
      ...groupCommonOption,
      name: "漏网之鱼",
      type: "select",
      proxies: ["🇺🇸 手动-US", "节点选择", ...autoRegionGroups, "全局直连"],
      "include-all": true,
      filter: nodeFilterString,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg"
    },
    {
      ...groupCommonOption,
      name: "全局直连",
      type: "select",
      proxies: ["DIRECT", "节点选择"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg"
    },
    // 下载组：默认走节点选择，避免境外 CDN 被直连；需要省流量时手动切全局直连
    {
      ...groupCommonOption,
      name: "下载",
      type: "select",
      proxies: ["节点选择", "全局直连", ...autoRegionGroups],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg"
    },

    // ---- 自动测速组 ----
    {
      ...autoTestGroupOption,
      name: "🌍 自动-Global",
      type: "url-test",
      "include-all": true,
      filter: nodeFilterString,
      "exclude-filter": `(?i)(?:${regionKeywords.HK}|娱乐节点)`,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/auto.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🇹🇼 自动-TW",
      type: "url-test",
      "include-all": true,
      filter: REGEX.TW,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/tw.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🇯🇵 自动-JP",
      type: "url-test",
      "include-all": true,
      filter: REGEX.JP,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/jp.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🇸🇬 自动-SG",
      type: "url-test",
      "include-all": true,
      filter: REGEX.SG,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/sg.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🇺🇸 自动-US",
      type: "url-test",
      "include-all": true,
      filter: REGEX.US,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/us.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🇩🇪 自动-DE",
      type: "url-test",
      "include-all": true,
      filter: REGEX.DE,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/de.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🇬🇧 自动-UK",
      type: "url-test",
      "include-all": true,
      filter: REGEX.UK,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/gb.svg"
    },
    {
      ...autoTestGroupOption,
      name: "🧩 自动-其他",
      type: "url-test",
      "include-all": true,
      filter: otherFilterString,
      "exclude-filter": "娱乐节点",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/all.svg"
    }
  ];

  config["rule-providers"] = ruleProviders;
  config["rules"] = rules;

  if (Array.isArray(config["proxies"])) {
    config["proxies"].forEach(proxy => {
      proxy.udp = true;
    });
  }

  return config;
}