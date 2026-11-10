"use strict";

// 仅执行仓库内已审阅的脚本；node:vm 用于隔离变量，不是恶意代码安全沙箱。
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const files = [
  "clients/flclash/override.js",
  "clients/sparkle/override.js",
  "clients/clash-verge-rev/override.js",
  "scenarios/wifi-calling/uk.js",
  "scenarios/wifi-calling/uk-de.js",
  "scenarios/wifi-calling/uk-de-us.js"
];
// 文档保留地址与虚构节点，仅检查配置生成，不发起连接。
const proxy = { name: "US-Example", type: "socks5", server: "192.0.2.1", port: 1080 };
const providers = { example: { type: "file", path: "./local/example.yaml" } };
const fixtures = [
  { proxies: [proxy], tun: { enable: true } },
  { "proxy-providers": providers, tun: { enable: false } },
  { proxies: [proxy], "proxy-providers": providers }
];
const epdg = "epdg.epc.mnc002.mcc262.pub.3gppnetwork.org";

function evaluate(source, input, expression = "main(input)") {
  const context = vm.createContext({ input: JSON.parse(JSON.stringify(input)) });
  return JSON.parse(vm.runInContext(`${source}\nJSON.stringify(${expression})`, context, {
    timeout: 5000
  }));
}

// 将生成表达式的 (?i) 映射为 JS 标志，检查代表反例；不是 Mihomo 正则引擎验收。
function accepts(group, name) {
  const matches = pattern => new RegExp(pattern.replaceAll("(?i)", ""), "i").test(name);
  return matches(group.filter || ".*") && (!group["exclude-filter"] || !matches(group["exclude-filter"]));
}

for (const file of files) {
  const source = fs.readFileSync(path.join(root, file), "utf8");
  new vm.Script(source, { filename: file });
  assert.throws(() => evaluate(source, {}), /配置文件中未找到任何代理/, file);
  for (const fixture of fixtures) {
    const out = evaluate(source, fixture);
    assert.equal(out.mode, "rule", file);
    assert.equal(out.tun.enable, fixture.tun?.enable, file);
    const groups = out["proxy-groups"];
    const names = groups.map(group => group.name);
    assert.equal(new Set(names).size, names.length, `${file}: duplicate group`);
    const targets = new Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", ...names,
      ...(fixture.proxies || []).map(item => item.name)]);
    for (const group of groups) {
      for (const name of group.proxies || []) {
        assert(targets.has(name), `${file}: unresolved group member ${name}`);
      }
    }
    for (const rule of out.rules) {
      const fields = rule.split(",");
      const target = fields.at(-1) === "no-resolve" ? fields.at(-2) : fields.at(-1);
      assert(targets.has(target), `${file}: unresolved rule target ${target}`);
      if (fields[0] === "RULE-SET") {
        assert(Object.hasOwn(out["rule-providers"], fields[1]), `${file}: missing rule provider`);
      }
    }
    assert.equal(out.dns.listen, file.includes("clash-verge-rev")
      ? "0.0.0.0:1053" : "127.0.0.1:1053", file);
    const autoGroups = groups.filter(group => group.type === "url-test");
    assert.equal(autoGroups.length, file.startsWith("clients/") ? 6 : 8, file);
    for (const group of autoGroups) {
      assert.equal(group["empty-fallback"], "REJECT", file);
    }
    const phoneGroups = groups.filter(group => group.name.startsWith("📞"));
    if (file.endsWith("/uk.js") || file.endsWith("/uk-de.js")) {
      const ukDomain = "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org";
      const ukTarget = phoneGroups[0].name;
      const vodafoneTarget = phoneGroups.at(-1).name;
      for (const [domain, target] of [[ukDomain, ukTarget], [epdg, vodafoneTarget]]) {
        assert(out.rules.includes(`DOMAIN,${domain},${target}`), file);
        assert(out.dns["nameserver-policy"][domain].every(server => server.endsWith(`#${target}`)), file);
      }
    }
    if (file.endsWith("/uk.js")) {
      assert.deepEqual(phoneGroups.map(group => group.proxies[0]), ["🇬🇧 自动-UK", "🇩🇪 自动-DE"], file);
      assert.equal(out.hosts[epdg].length, 3, file);
    } else if (file.endsWith("/uk-de.js")) {
      assert.deepEqual(phoneGroups.map(group => group.proxies[0]), ["🇬🇧 自动-UK", "DIRECT", "🇩🇪 自动-DE"], file);
      assert.equal(out.hosts, undefined, file);
    } else if (file.endsWith("/uk-de-us.js")) {
      assert.deepEqual(phoneGroups.map(group => group.proxies[0]), Array(4).fill("REJECT"), file);
      assert.equal(out.hosts, undefined, file);
      assert.equal(out.rules.filter(rule => /DST-PORT,(500|4500)/.test(rule)).length, 0, file);
      const defaults = evaluate(source, {}, "({profile: VOWIFI_ACTIVE_PROFILE, ssh: PRIVATE_SSH_DIRECT_IPV4S, source: VOWIFI_OBSERVED_SOURCE_IPV4S})");
      assert.deepEqual(defaults, { profile: "OFF", ssh: [], source: [] }, file);
      const rules = evaluate(source, {}, "wifiCallingRules");
      assert(rules.length > 0 && rules.every(rule => rule.endsWith(",DIRECT")), file);
      const dns = out.dns["nameserver-policy"][epdg];
      assert(dns.length > 0 && dns.every(server => server.endsWith("#DIRECT")), file);
    }
  }
  // 默认不注入 hosts 的版本仍保留调用方已有 hosts；OFF 不等于清空配置。
  const input = { ...fixtures[0], hosts: { [epdg]: "192.0.2.2" } };
  if (!file.endsWith("/uk.js")) {
    assert.deepEqual(evaluate(source, input).hosts, input.hosts, file);
  }
  if (file.startsWith("scenarios/")) {
    const out = evaluate(source, fixtures[0]);
    const group = name => out["proxy-groups"].find(item => item.name === name);
    const gateway = "DOMAIN,gateway.ai.cloudflare.com,AI";
    assert.equal(out.rules.filter(rule => rule === gateway).length, 1, file);
    assert(out.rules.indexOf(gateway) < out.rules.indexOf("DOMAIN-SUFFIX,cloudflare.com,DIRECT"), file);
    assert(out.rules.includes("DOMAIN,vscode-sync.trafficmanager.net,开发工具"), file);
    for (const domain of ["oaistatsig.com", "claude.app", "claudemcpcontent.com"]) {
      assert(out.rules.includes(`DOMAIN-SUFFIX,${domain},AI`), file);
      assert.deepEqual(out.dns["nameserver-policy"][`+.${domain}`],
        ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"], file);
    }
    assert(out.rules.includes("DOMAIN-SUFFIX,onedrive.live.com,节点选择"), file);
    assert(!out.rules.includes("DOMAIN-SUFFIX,onedrive.live.com,DIRECT"), file);
    assert(Array.isArray(out.dns["nameserver-policy"]["+.onedrive.live.com"]), file);
    assert(!Object.hasOwn(out.dns, "strategy"), file);
    // 明确排除的分流策略不能借通用同步混入。
    for (const domain of ["apps.apple.com", "itunes.apple.com", "oracle.com", "oraclecloud.com"]) {
      assert(!out.rules.some(rule => rule.split(",")[1] === domain), file);
      for (const key of [domain, `+.${domain}`]) {
        assert(!Object.hasOwn(out.dns["nameserver-policy"], key), file);
      }
    }
    const unified = file.endsWith("/uk-de-us.js");
    assert.equal(group("漏网之鱼").proxies[0], unified ? "节点选择" : "🇺🇸 手动-US", file);
    for (const item of out["proxy-groups"].filter(item => item.type === "select")) {
      const periodic = ["节点选择", "🇺🇸 手动-US"].includes(item.name) ||
        (!unified && item.name.startsWith("📞"));
      assert.equal(item.interval, periodic ? 300 : undefined, `${file}: ${item.name}`);
    }
    for (const [name, node, expected] of [
      ["🇺🇸 自动-US", "JP-住宅-01", false],
      ["🇺🇸 自动-US", "US-剩余流量-100GB", false],
      ["🇺🇸 自动-US", "US-EUGameHost-01", true],
      ["🇺🇸 自动-US", "US-GAME-01", false],
      ["🇺🇸 自动-US", "LAX-01", true],
      ["🧩 自动-其他", "LAX-01", false],
      ["🌍 自动-Global", "US-娱乐节点-01", false],
      ["🌍 自动-Global", "HK01", false],
      ["🧩 自动-其他", "Finland-01", true],
      ["🧩 自动-其他", "Finland-娱乐节点-01", false],
      ["🇩🇪 自动-DE", "FRA01", true],
      ["🇬🇧 自动-UK", "LHR01", true],
      ["🧩 自动-其他", "FRA01", false],
      ["🧩 自动-其他", "LHR01", false],
      ["🇬🇧 自动-UK", "UK-EUGameHost-01", true],
      ["🇬🇧 自动-UK", "UK-剩余流量-01", false]
    ]) assert.equal(accepts(group(name), node), expected, `${file}: ${name} / ${node}`);

    if (unified) {
      const phone = group("📞 UK VoWiFi（手动候选）");
      assert(accepts(phone, "UK-EUGameHost-5x"), file);
      assert(!accepts(phone, "DE-EUGameHost-01"), file);
      assert(!accepts(phone, "UK-剩余流量-01"), file);
      // 覆盖八个活动 profile 的两种源地址范围，保证通用同步不影响端口保护。
      const definitions = evaluate(source, {}, "VOWIFI_PROFILE_DEFINITIONS");
      for (const [profile, definition] of Object.entries(definitions)) {
        if (profile === "OFF") continue;
        for (const scope of ["SOURCE_IPS_REQUIRED", "ALL_TUN_CLIENTS"]) {
          const configured = source
            .replace('const VOWIFI_ACTIVE_PROFILE = "OFF";', `const VOWIFI_ACTIVE_PROFILE = "${profile}";`)
            .replace('const VOWIFI_IKE_SCOPE = "SOURCE_IPS_REQUIRED";', `const VOWIFI_IKE_SCOPE = "${scope}";`)
            .replace(/const VOWIFI_OBSERVED_SOURCE_IPV4S = \[[\s\S]*?\n\];/, 'const VOWIFI_OBSERVED_SOURCE_IPV4S = ["192.0.2.2"];');
          const active = evaluate(configured, fixtures[0]);
          const portRules = active.rules.filter(rule => /DST-PORT,(500|4500)/.test(rule));
          const expected = [500, 4500].flatMap(port => {
            const prefix = `AND,((IN-TYPE,TUN),(NETWORK,UDP),(DST-PORT,${port})` +
              (scope === "SOURCE_IPS_REQUIRED" ? ",(SRC-IP-CIDR,192.0.2.2/32)" : "") + ")";
            return definition.target === "DIRECT" ? [`${prefix},DIRECT`] :
              [`${prefix},${definition.target}`, `${prefix},REJECT`];
          });
          assert.deepEqual(portRules, expected, `${profile}: ${scope}`);
          assert.deepEqual(active.rules.slice(0, expected.length), expected, `${profile}: priority`);
        }
      }
      const missingSource = source.replace('const VOWIFI_ACTIVE_PROFILE = "OFF";',
        'const VOWIFI_ACTIVE_PROFILE = "UK_PROXY";');
      assert.throws(() => evaluate(missingSource, fixtures[0]), /至少需要一个/, file);
    }
  }
  console.log(`PASS ${file}`);
}
console.log("PASS: 6 scripts; 18 config cases; 6 empty-input cases; references, generic fixes, filters and 16 active-profile/scope cases.");
