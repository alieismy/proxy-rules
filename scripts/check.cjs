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
    assert(autoGroups.length > 0, file);
    for (const group of autoGroups) {
      assert.equal(group["empty-fallback"], file.startsWith("clients/") ? "REJECT" : undefined, file);
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
  console.log(`PASS ${file}`);
}
console.log("PASS: 6 scripts; 18 config cases; 6 empty-input cases; references and documented defaults.");
