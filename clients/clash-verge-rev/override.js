// Clash Verge Rev 覆写脚本（v16.6 空组保护与节点筛选修正版）
// 历史适配基线（v16.5）：Clash Verge Rev v2.5.2 / Mihomo v1.19.30 / boa_engine JS 引擎
// 运行模式：TUN（由 UI 开关控制）+ 系统代理 + 规则模式
// 基线：从 Sparkle v16 同步平台无关逻辑
// v16.6 变更说明（2026-10-07，同步 Sparkle v16.6 的平台无关修复）：
//   [Group-BH] 六个自动组显式设置 empty-fallback: REJECT，避免空组经 COMPATIBLE 意外直连。
//   [Route-BI] gateway.ai.cloudflare.com 的 AI 规则前移至 cloudflare.com 通用直连规则之前。
//   [Filter-BJ] Global 与其他自动组补充「娱乐节点」排除，保留 Global 的香港排除。
//   [Filter-BK] 地区组统一过滤信息节点；英文地区标记、机场代码和 GAME 标签增加边界，
//               不再以「住宅」单独判断美国，「其他」复用各地区识别词，避免误收和误排。
//   [Scope-BL] DNS、TUN、嗅探、Apple/Oracle 分流与四条 VPS SSH 规则保持原样。
//   核心要求：须支持 empty-fallback；本版已用 Mihomo v1.19.31 验证，v1.19.21 不支持空组保护。
//   验证边界：本版在客户端导入后的实际生效与业务结果须另行核对。
//
// v16.5 变更说明（同步 Sparkle v16.5 的平台无关分流与文档更新）：
//   [Route-BD] apps.apple.com 与 itunes.apple.com 精确匹配「🇺🇸 手动-US」，并配置独立海外 DNS；
//              规则优先于 Apple CDN 直连，其他 Apple/iCloud 分流保持原样。
//   [Route-BE] oracle.com 与 oraclecloud.com 后缀匹配 DIRECT，覆盖其根域名和全部子域名。
//   [Route-BF] 保留第 4 条 VPS TCP/22 直连规则，仍限定目标 IP /32、TCP 和端口 22。
//
// v16.4 变更说明（同步 Sparkle v16.4 的平台无关 SSH 管理路径修复）：
//   [Route-BC] 三台现役 VPS 的 TCP/22 强制 DIRECT，使 SSH 管理路径独立于 Reality 数据平面；
//              不改变 20302、2096、443 或其他端口，也不使用全局 SSH、进程或整机直连。
//
// v16.3 变更说明（同步 Sparkle v16.3 的平台无关健康检查范围优化）：
//   [Health-AZ] interval: 300 仅用于 url-test 自动测速组，以及「节点选择」「手动-US」；
//           两个主要 select 组使用 lazy 周期检查；AI 与其余跟随型 select 组不再重复探测。
//   [Group-BA] 漏网之鱼默认跟随「节点选择」，避免固定锚定「🇺🇸 手动-US」。
//   [Scope-BB] 保留迅雷、BT/PT 与 IDM 下载能力，不新增下载进程拦截或固定 IDM 出口。
//
// v16.2 变更说明（同步 Sparkle v16.2 的平台无关运行修复）：
//   [Fix-AY] onedrive.live.com 从 DIRECT 改为「节点选择」，并显式使用海外 DNS；
//            修复国内 DNS 异常解析后持续直连超时的问题。
//
// v16.1 变更说明：
//   [Cleanup-AW] 删除 Mihomo v1.19.29 不支持的 dns.strategy 字段。
//   [Scope-AX] GEO 数据更新不由覆写脚本接管；固定单节点场景不新增 fallback。
//
// v16：合并 AI 与 Google/YouTube 分组，删除 Spotify 和自动-HK，Global 排除 HK，
//      自动区域组排除「娱乐节点」，并补齐 AI 域名及海外 DNS 策略。
//
// 与 Sparkle 版的适配差异：
//   [Adapt-1] TUN enable 由 Clash Verge Rev UI 控制，脚本仅设置 TUN 参数
//   [Adapt-2] DNS listen 地址改为 0.0.0.0:1053（Clash Verge Rev 社区惯例）
//   [Adapt-3] JS 引擎为 boa_engine（ECMAScript 完整实现，语法完全兼容）
//
// v13.5 变更说明（同步 Sparkle v13.5 的平台无关保守优化）：
//
//   [Perf-AP] find-process-mode 从 always 改为 strict，仅在规则需要时启用进程匹配。
//   [Health-AQ] 抽取 HEALTH_CHECK_URL，统一 timeout: 5000 与 expected-status: 204；
//               删除 Mihomo 默认值 max-failed-times: 5；本机 HTTP/HTTPS 均返回 204，保留 HTTPS。
//   [Doc-AR] 校正 route-exclude-address 注释，不再将配置意图表述为 Windows 路由保证。
//
// v13.3 变更说明（基于 Sparkle core-2026-5-25.log 日志分析）：
//
//   [Fix-AH] onecdn.static.microsoft 走代理：
//           Microsoft 新一代 CDN（.microsoft gTLD），后端 Cloudflare Anycast 104.18.x.x。
//           日志确认直连超时 22 次。2026 年 6 月起成为 Microsoft AutoUpdate 唯一下载源。
//
//   [Fix-AI] challenges.cloudflare.com 走代理：
//           Cloudflare Turnstile 验证挑战唯一宿主域名，日志确认直连超时 181 次。
//           不可达会导致所有使用 Turnstile 的网站验证失败。
//
//   [Fix-AJ] csp-reporting.cloudflare.com 静默丢弃（REJECT-DROP）：
//           CSP 违规上报属于非功能性遥测，日志确认直连超时 52 次。丢弃不影响页面功能。
//
// v13.2 变更说明（基于 v13 深度复核 + Mihomo 文档/源码校正）：
//
//   [Fix-AH-pre] rule-providers 显式通过「节点选择」更新：
//           为全部 HTTP provider 设置 proxy: "节点选择"，避免远程规则集更新失败。
//
//   [Doc-AI] 修正注释表述（独立 TLD → 独立域名；route-exclude-address 注释校正）
//
// v13 变更说明（合并 Sparkle v12.2/v12.3 全部有效修复 + v13 优化）：
//
//   [Fix-X'] foreignNameservers 移除 DoT（tls://8.8.8.8:853），仅保留两条 IP 形式 DoH
//   [Fix-Z]  静默拦截 Windows IPv6 NCSI 检测域名（REJECT-DROP）
//   [Fix-AA'] infinitynewtab 改走代理（保留扩展资源加载能力）
//   [Fix-AC] Cloudflare Dashboard DOMAIN → DOMAIN-SUFFIX（覆盖 platform.dash 等子域）
//   [Fix-AD] sparrow.cloudflare.com 显式走代理
//   [Fix-AE] cloudflareinsights.com 显式走代理（独立域名，不属于 cloudflare.com 子域树，v2rayN 日志确认必须加载）
//   [Fix-AF] cloudflare.dev 显式走代理（独立域名，不属于 cloudflare.com 子域树，Dashboard 客服 WebSocket）
//   [Fix-AG] nameserver-policy Cloudflare 条目统一 +. 写法，移除冗余精确条目
//
// 继承的修复（v12 及更早）：
//   [Fix-W] TUN route-exclude-address（RFC 1918）  [Fix-Q] claude.com 显式海外 DNS
//   [Fix-R] Cursor DOMAIN-SUFFIX 通配              [Fix-S] statsigapi.net → 节点选择
//   [Fix-T] Cursor 3.0 cursor.com                  [Fix-U] keep-alive-idle 120s
//   [Fix-V] udp-timeout 600s
//
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

const dnsConfig = {
  "enable": true,
  "listen": "0.0.0.0:1053",
  "ipv6": false,
  "prefer-h3": false,
  "respect-rules": true,
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
    "+.asusrouter.com"
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

// --- 开发工具：VS Code Marketplace / 下载 / Copilot ---
const devToolRules = [
  "DOMAIN,marketplace.visualstudio.com,开发工具",
  "DOMAIN-SUFFIX,gallery.vsassets.io,开发工具",
  "DOMAIN-SUFFIX,gallerycdn.vsassets.io,开发工具",
  "DOMAIN,code.visualstudio.com,开发工具",
  "DOMAIN,update.code.visualstudio.com,开发工具",
  "DOMAIN,vscode.download.prss.microsoft.com,开发工具",
  "DOMAIN,download.visualstudio.microsoft.com,开发工具",
  "DOMAIN,vscode.dev,开发工具",
  "DOMAIN,cursor-cdn.com,开发工具",
  "DOMAIN,anysphere-binaries.s3.us-east-1.amazonaws.com,开发工具"
];

// --- OpenAI / ChatGPT / Codex ---
const openaiRules = [
  "DOMAIN-SUFFIX,openai.com,AI",
  "DOMAIN-SUFFIX,chatgpt.com,AI",
  "DOMAIN-SUFFIX,oaistatic.com,AI",
  "DOMAIN-SUFFIX,oaiusercontent.com,AI"
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
// anysphere-binaries.s3.us-east-1.amazonaws.com 保留精确 DOMAIN：
// 故意只匹配该 S3 bucket，避免将其他应用的 S3 流量误路由到 Cursor 组。
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
// [Fix-Z] IPv6 NCSI 域名在 ipv6:false 时必然解析失败，用 REJECT-DROP 静默丢弃。
// [Fix-AA'] infinitynewtab 走代理（海外域名国内 DNS 无法解析）。
const noisyRejectRules = [
  "DOMAIN,ipv6.msftconnecttest.com,REJECT-DROP",
  "DOMAIN,ipv6.msftncsi.com,REJECT-DROP",
  "DOMAIN-SUFFIX,infinitynewtab.com,节点选择"
];

// ========== 高优先级稳定性救回 ==========
// 放在广告拦截之前，用于降低登录、验证码、支付等基础功能被广告规则误伤的概率。
// 仅保留小范围关键域名；出问题时仍可通过「广告拦截」/「广告静默拦截」策略组排查。
const stabilityAllowRules = [
  // App Store 网页入口使用美国节点；先于 Apple CDN 规则匹配
  "DOMAIN,itunes.apple.com,🇺🇸 手动-US",
  "DOMAIN,apps.apple.com,🇺🇸 手动-US",

  // Oracle Cloud 控制台及相关域名直连
  "DOMAIN-SUFFIX,oracle.com,DIRECT",
  "DOMAIN-SUFFIX,oraclecloud.com,DIRECT",

  // Microsoft 登录 / OneDrive / Windows 联网检测
  "DOMAIN-KEYWORD,outlook.office,DIRECT",
  "DOMAIN-SUFFIX,login.microsoftonline.com,DIRECT",
  "DOMAIN-SUFFIX,login.live.com,DIRECT",
  "DOMAIN-SUFFIX,account.live.com,DIRECT",
  "DOMAIN-SUFFIX,onedrive.live.com,节点选择",
  "DOMAIN-SUFFIX,msftconnecttest.com,DIRECT",
  "DOMAIN-SUFFIX,msftncsi.com,DIRECT",

  // [Fix-AH v13.3] Microsoft 新一代 CDN（.microsoft gTLD，后端 Cloudflare）
  // 日志确认 res.public.onecdn.static.microsoft 解析到 104.18.x.x，直连超时。
  // 该 CDN 端点 2026 年 6 月起成为 Microsoft AutoUpdate 唯一下载源。
  "DOMAIN-SUFFIX,onecdn.static.microsoft,节点选择",

  // Cloudflare 分流（v13 完善）
  "DOMAIN-SUFFIX,dash.cloudflare.com,节点选择",
  "DOMAIN-SUFFIX,api.cloudflare.com,节点选择",
  "DOMAIN-SUFFIX,sparrow.cloudflare.com,节点选择",
  // [Fix-AI v13.3] Cloudflare Turnstile 验证挑战域名，日志确认 181 次直连超时。
  // 不可达会导致所有使用 Turnstile 的网站验证失败。
  "DOMAIN-SUFFIX,challenges.cloudflare.com,节点选择",
  "DOMAIN-SUFFIX,cloudflareinsights.com,节点选择",
  "DOMAIN-SUFFIX,cloudflare.dev,节点选择",
  // [Route-BI v16.6] AI Gateway 必须先于 cloudflare.com 通用直连规则匹配。
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

// ========== 规则总装配 ==========
const rules = [
  // 0. 进程直连（最高优先级，TUN 模式下迅雷等下载工具绕过代理）
  "PROCESS-NAME,Thunder.exe,DIRECT",
  "PROCESS-NAME,DownloadSDKServer.exe,DIRECT",
  "PROCESS-NAME,upnp.exe,DIRECT",
  "PROCESS-NAME,APlayer.exe,DIRECT",
  "PROCESS-NAME,DownloadService.exe,DIRECT",
  "PROCESS-NAME,P2PService.exe,DIRECT",
  "PROCESS-PATH-REGEX,(?i)Thunder.*\\.exe$,DIRECT",

  // 1. DNS 服务器 IP 显式走代理（减少规则遍历，意图清晰）
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

  // 4. GEOSITE 隐私拦截
  "GEOSITE,WIN-SPY,全局拦截",
  //"GEOSITE,WIN-EXTRA,全局拦截",

  // 5. Loyalsoldier 广告域名
  "RULE-SET,reject,全局拦截",

  // 6. PT / Tracker 直连
  "GEOSITE,CATEGORY-PUBLIC-TRACKER,DIRECT",
  "GEOSITE,CATEGORY-PT,DIRECT",

  // 7. AI / 开发工具精确域名（在 Sukka microsoft/google 规则集之前，避免被泛规则吞）
  ...devToolRules,
  ...openaiRules,
  ...claudeRules,
  ...googleAIRules,
  ...cursorRules,
  ...aiMiscRules,

  // 8. blackmatrix7 AI 规则集兜底（手写规则未覆盖的 AI 域名由此捕获）
  "RULE-SET,bm7_openai,AI",
  "RULE-SET,bm7_claude,AI",
  "RULE-SET,bm7_anthropic,AI",
  "RULE-SET,bm7_gemini,AI",
  "RULE-SET,bm7_copilot,AI",

  // 9. Sukka 服务分流
  "RULE-SET,telegram_non_ip,节点选择",
  "RULE-SET,apple_cdn,全局直连",
  "RULE-SET,apple_cn_non_ip,全局直连",
  "RULE-SET,microsoft_cdn_non_ip,全局直连",
  "RULE-SET,apple_services,苹果服务",
  "RULE-SET,microsoft_non_ip,微软服务",
  "RULE-SET,ai_non_ip,AI",

  // 10. 手写域名补强
  ...customRules,

  // 11. 下载流量走「下载」组（默认走节点选择，可手动切全局直连省流量）
  "RULE-SET,download_domainset,下载",
  "RULE-SET,download_non_ip,下载",

  // 12. 通用规则集
  "RULE-SET,applications,全局直连",
  "RULE-SET,private,全局直连",
  "RULE-SET,icloud,苹果服务",
  "RULE-SET,apple,苹果服务",
  "RULE-SET,google,谷歌服务",

  // 13. 三重 GFW 保障（proxy + gfw + ACL4SSR）
  "RULE-SET,proxy,节点选择",
  "RULE-SET,gfw,节点选择",
  "RULE-SET,proxy-gfwlist,节点选择",
  "RULE-SET,direct,全局直连",

  // 14. 国内域名直连
  "GEOSITE,CN,全局直连",

  // 15. IP 类规则
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

  // 16. 漏网之鱼（走代理，确保 DNS 不泄漏）
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
    "log-level": "info",
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

  // DNS
  config.dns = { ...dnsConfig };
  config.dns["nameserver-policy"] = {
    // 显式域名与通配域名分开列出，减少对 geosite 兜底的依赖。
    // 注意：Mihomo 2026-01 已切换到 OrderedMap，nameserver-policy 现在有序。
    // 国内 geosite 放前面，精确海外域名放中间，海外 geosite 兜底放末尾。

    // --- 国内直连域名走国内 DNS ---
    "geosite:cn,private": domesticNameservers,
    "geosite:apple,icloud,microsoft": domesticNameservers,

    // --- 需要海外 DNS 解析的服务（精确域名优先列出）---
    // App Store 网页入口：覆盖 Apple 通用国内 DNS 策略
    "itunes.apple.com": foreignNameservers,
    "apps.apple.com": foreignNameservers,

    // [Fix-AY v16.2] OneDrive 路由已改走代理，避免继续受 Microsoft 国内 DNS 兜底影响
    "+.onedrive.live.com": foreignNameservers,

    // Cloudflare 控制面走海外 DNS（GFW 有 SNI 干扰）
    "+.dash.cloudflare.com": foreignNameservers,
    "+.api.cloudflare.com": foreignNameservers,
    "+.sparrow.cloudflare.com": foreignNameservers,
    // [Fix-AI v13.3] Turnstile 验证挑战走海外 DNS（防御性，fake-ip 代理流量实际不触发本地解析）
    "+.challenges.cloudflare.com": foreignNameservers,
    "+.cloudflareinsights.com": foreignNameservers,
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
    "+.anthropic.com": foreignNameservers,
    "+.claude.ai": foreignNameservers,
    // [Fix-Q] 保留 claude.com 的显式海外 DNS 覆盖：
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

    // [Fix-R][Fix-T] Cursor 域名策略：通配写法覆盖 cursor.sh / cursor.com / cursorapi.com
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

    // --- GFW 相关服务走海外 DNS（通配符兜底）---
    "geosite:geolocation-!cn": foreignNameservers,
    "geosite:google,youtube,telegram,gfw": foreignNameservers
  };

  // [Adapt-1] TUN：不设置 enable，由 Clash Verge Rev UI 开关控制
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
    US: "(?:美国|🇺🇸|(?:^|[^A-Za-z])(?:US|USA|United\\s*States|America|SJC|JFK|LAX|ORD|SFO|SEA|IAD)(?=$|[^A-Za-z]))"
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
    US: regionNodeFilter(regionKeywords.US)
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
    // 默认 REJECT；遇到某网站打不开时，可在 Clash Verge Rev UI 临时切 DIRECT 排查
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
      // 默认 REJECT（非 DROP），便于在 Clash Verge Rev 日志中看到被拦截的请求
      type: "select",
      proxies: ["REJECT", "REJECT-DROP", "DIRECT"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/bug.svg"
    },
    {
      ...groupCommonOption,
      name: "漏网之鱼",
      type: "select",
      proxies: ["节点选择", ...autoRegionGroups, "全局直连"],
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
