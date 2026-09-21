import test from 'node:test';
import assert from 'node:assert/strict';
import worker, {
    base64Encode,
    base64Decode,
    parseVless,
    parseVmess,
    parseTrojan,
    parseShadowsocks,
    parseShadowsocksR,
    parseHysteria2,
    parseTuic,
    parseNode,
    nodeToUri,
    formatHostForUri,
    processNodes,
    generateClashConfig,
    proxyToClashYaml,
    generateBase64Config,
    parseClashProxies,
    parseSubConfig,
    loadSubConfig,
    extractRuleProviderName,
    matchRegex,
    parseCustomProxyGroup,
    breakCycles,
    applyGhProxy,
    normalizeTargetUrl,
    getFailoverUrls,
    handleRuleProxyRequest,
    cleanTextRuleList,
    isYamlRulePayload,
    convertRuleListToYaml,
    parseYaml,
    dumpYaml,
    deepMerge,
    applyYamlOverride,
    loadOverrideConfig,
    sanitizeDnsFakeIpFilter,
    getRequestHeadersForUrl
} from '../_worker.js';

test('Extract rule provider name from URL and deduplicate', () => {
    const seen = new Set();
    const name1 = extractRuleProviderName('https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list', 0, seen);
    assert.equal(name1, 'direct');

    const name2 = extractRuleProviderName('https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list', 1, seen);
    assert.equal(name2, 'LocalAreaNetwork');

    const name3 = extractRuleProviderName('https://other.com/path/direct.list', 2, seen);
    assert.equal(name3, 'direct_2'); // deduplicated!

    const name4 = extractRuleProviderName('https://example.com/rules/AWAvenue-Ads-Rule.yaml', 3, seen);
    assert.equal(name4, 'AWAvenue-Ads-Rule');
});

test('Base64 UTF-8 encoding and decoding', () => {
    const original = '你好，世界！Hello World 123! 🚀';
    const encoded = base64Encode(original);
    const decoded = base64Decode(encoded);
    assert.equal(decoded, original);
});

test('Parse VLESS: strict parameter fidelity without forced defaults', () => {
    // 1. Without fp or insecure -> should NOT have clientFingerprint or skipCertVerify
    const vlessSimple = 'vless://uuid123@cf.example.com:443?type=ws&path=%2Fws#Node-Simple';
    const n1 = parseNode(vlessSimple);
    assert.ok(n1);
    assert.equal(n1.clientFingerprint, undefined);
    assert.equal(n1.skipCertVerify, undefined);

    // 2. With fp and reality
    const vlessReality = 'vless://d3b07384-d113-494b-9c8e-3c27ac8418ff@1.2.3.4:443?flow=xtls-rprx-vision&security=reality&sni=yahoo.com&fp=chrome&pbk=fakeKey123&sid=fakeSid456#Reality-Node';
    const n2 = parseNode(vlessReality);
    assert.ok(n2);
    assert.equal(n2.type, 'vless');
    assert.equal(n2.name, 'Reality-Node');
    assert.equal(n2.tls, true);
    assert.equal(n2.realityOpts.publicKey, 'fakeKey123');
    assert.equal(n2.realityOpts.shortId, 'fakeSid456');
    assert.equal(n2.clientFingerprint, 'chrome');
    assert.equal(n2.flow, 'xtls-rprx-vision');
});

test('Parse VMess node: strict parameter fidelity', () => {
    const vmessJson = {
        v: "2",
        ps: "VMess-Test",
        add: "cf.example.com",
        port: "8443",
        id: "03fcc618-b93d-6796-6aed-8a38c975d581",
        net: "ws",
        path: "/linkws",
        tls: "tls"
    };
    const vmessUri = `vmess://${base64Encode(JSON.stringify(vmessJson))}`;
    const node = parseNode(vmessUri);
    assert.ok(node);
    assert.equal(node.type, 'vmess');
    assert.equal(node.name, 'VMess-Test');
    assert.equal(node.server, 'cf.example.com');
    assert.equal(node.port, 8443);
    assert.equal(node.uuid, '03fcc618-b93d-6796-6aed-8a38c975d581');
    assert.equal(node.network, 'ws');
    assert.equal(node.cipher, 'auto'); // Default to auto when scy is omitted
    assert.equal(node.clientFingerprint, undefined); // No forced default

    const yaml = proxyToClashYaml(node);
    assert.ok(yaml.includes('cipher: auto'), 'Clash YAML must have cipher: auto for VMess');
});

test('Parse Trojan node: strict parameter fidelity', () => {
    // 1. Without fp or insecure
    const trojanUri1 = 'trojan://password123@hk.example.com:443?type=ws&path=%2Ftrojanws#Trojan-1';
    const node1 = parseNode(trojanUri1);
    assert.ok(node1);
    assert.equal(node1.clientFingerprint, undefined); // Let client handle default
    assert.equal(node1.skipCertVerify, undefined);

    // 2. Explicit fp and allowInsecure
    const trojanUri2 = 'trojan://password123@hk.example.com:443?fp=firefox&allowInsecure=1#Trojan-2';
    const node2 = parseNode(trojanUri2);
    assert.ok(node2);
    assert.equal(node2.clientFingerprint, 'firefox');
    assert.equal(node2.skipCertVerify, true);
});

test('Parse Shadowsocks SIP002', () => {
    const userInfo = base64Encode('aes-256-gcm:secret123');
    const ssUri = `ss://${userInfo}@1.2.3.4:8388#SS-Node`;
    const node = parseNode(ssUri);
    assert.ok(node);
    assert.equal(node.type, 'ss');
    assert.equal(node.name, 'SS-Node');
    assert.equal(node.server, '1.2.3.4');
    assert.equal(node.port, 8388);
    assert.equal(node.cipher, 'aes-256-gcm');
    assert.equal(node.password, 'secret123');
});

test('Parse Hysteria2 node', () => {
    const hy2Uri = 'hy2://mySecretPwd@hy2.example.com:443?sni=hy2.example.com&insecure=1#Hy2-Node';
    const node = parseNode(hy2Uri);
    assert.ok(node);
    assert.equal(node.type, 'hysteria2');
    assert.equal(node.name, 'Hy2-Node');
    assert.equal(node.server, 'hy2.example.com');
    assert.equal(node.port, 443);
    assert.equal(node.password, 'mySecretPwd');
    assert.equal(node.skipCertVerify, true);
});

test('Process nodes deduplication and renaming', () => {
    const n1 = parseNode('trojan://pwd1@1.2.3.4:443#HK');
    const n2 = parseNode('trojan://pwd1@1.2.3.4:443#HK-Dup');
    const n3 = parseNode('trojan://pwd2@5.6.7.8:443#HK');

    const processed = processNodes([n1, n2, n3]);
    assert.equal(processed.length, 2);
    assert.equal(processed[0].name, 'HK');
    assert.equal(processed[1].name, 'HK 2');
});

test('Parse subconfig INI and generate Clash with rule-providers and regional groups', () => {
    const sampleIni = `
[custom]
ruleset=全球直连,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/direct.list
ruleset=德国节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/de.list
ruleset=香港节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/hk.list
ruleset=节点选择,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/proxy.list
ruleset=全球拦截,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list
ruleset=全球直连,[]GEOIP,CN
ruleset=🐟 漏网之鱼,[]FINAL
`;
    const parsedSubConfig = parseSubConfig(sampleIni);
    assert.equal(parsedSubConfig.rulesets.length, 5); // 只有 5 个真正远程 http 规则集
    assert.equal(parsedSubConfig.directRules.length, 2); // 2 个内置直接规则
    assert.equal(parsedSubConfig.rulesets[0].group, '全球直连');
    assert.equal(parsedSubConfig.rulesets[1].group, '德国节点');

    const nodes = [
        parseNode('trojan://p1@1.1.1.1:443#🇭🇰 香港 01'),
        parseNode('trojan://p2@2.2.2.2:443#🇩🇪 德国 01'),
        parseNode('trojan://p3@3.3.3.3:443#🇺🇸 美国 01')
    ];
    const processed = processNodes(nodes);

    const clashYaml = generateClashConfig(processed, 'TestSub', parsedSubConfig);
    assert.ok(clashYaml.includes('rule-providers:'));
    assert.ok(clashYaml.includes('direct:'));
    assert.ok(clashYaml.includes('path: ./ruleset/direct.list'));
    assert.ok(clashYaml.includes('format: text'));
    assert.ok(clashYaml.includes('RULE-SET,direct,全球直连'));
    assert.ok(clashYaml.includes('de:'));
    assert.ok(clashYaml.includes('path: ./ruleset/de.list'));
    assert.ok(clashYaml.includes('RULE-SET,de,德国节点'));
    assert.ok(clashYaml.includes('hk:'));
    assert.ok(clashYaml.includes('path: ./ruleset/hk.list'));
    assert.ok(clashYaml.includes('RULE-SET,hk,香港节点'));
    assert.ok(clashYaml.includes('proxy:'));
    assert.ok(clashYaml.includes('RULE-SET,proxy,节点选择'));
    assert.ok(clashYaml.includes('BanAD:'));
    assert.ok(clashYaml.includes('RULE-SET,BanAD,全球拦截'));
    assert.ok(clashYaml.includes('name: "香港节点"'));
    assert.ok(clashYaml.includes('name: "德国节点"'));
    assert.ok(clashYaml.includes('🇭🇰 香港 01'));
    assert.ok(clashYaml.includes('🇩🇪 德国 01'));

    // 严苛验证：[]GEOIP 和 []FINAL 绝不能出现在 rule-providers 中
    assert.ok(!clashYaml.includes('__GEOIP'));
    assert.ok(!clashYaml.includes('__FINAL'));
    assert.ok(!clashYaml.includes('url: "[]'));

    // 验证它们正确直接写入 rules 区域
    assert.ok(clashYaml.includes('GEOIP,CN,全球直连,no-resolve'));
    assert.ok(clashYaml.includes('MATCH,🐟 漏网之鱼'));
});

test('Generate Base64 configuration', () => {
    const n1 = parseNode('trojan://pwd1@1.2.3.4:443?sni=example.com#HK-Trojan');
    const processed = processNodes([n1]);

    const b64 = generateBase64Config(processed);
    assert.ok(b64.length > 0);
    const decoded = base64Decode(b64);
    assert.ok(decoded.includes('trojan://'));
    assert.ok(decoded.includes('HK-Trojan'));
});

test('Parse Clash YAML proxies', () => {
    const sampleYaml = `
proxies:
  - name: "Clash-HK-01"
    type: trojan
    server: 1.1.1.1
    port: 443
    password: mypassword
    sni: sni.test.com
  - name: "Clash-US-02"
    type: vmess
    server: 2.2.2.2
    port: 80
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /ws
`;
    const parsedNodes = parseClashProxies(sampleYaml);
    assert.equal(parsedNodes.length, 2);
    assert.equal(parsedNodes[0].name, 'Clash-HK-01');
    assert.equal(parsedNodes[0].type, 'trojan');
    assert.equal(parsedNodes[0].server, '1.1.1.1');
    assert.equal(parsedNodes[1].name, 'Clash-US-02');
    assert.equal(parsedNodes[1].type, 'vmess');
    assert.equal(parsedNodes[1].wsOpts.path, '/ws');
});

test('Worker fetch handler - Clash and Base64 routing', async () => {
    const mockEnv = {
        TOKEN: 'mytesttoken',
        LINK: 'trojan://testpwd@1.2.3.4:443?sni=test.com#HK-01'
    };

    // 1. Unauthorized request -> returns 200 nginx decoy
    const resUnauthorized = await worker.fetch(new Request('https://mysub.workers.dev/wrongtoken', {
        headers: { 'User-Agent': 'Mozilla/5.0' }
    }), mockEnv);
    assert.equal(resUnauthorized.status, 200);
    const htmlText = await resUnauthorized.text();
    assert.ok(htmlText.includes('Welcome to nginx!'));

    // 2. Authorized Clash request via query parameter
    const resClash = await worker.fetch(new Request('https://mysub.workers.dev/?token=mytesttoken&clash', {
        headers: { 'User-Agent': 'ClashVerge/1.3.8' }
    }), mockEnv);
    assert.equal(resClash.status, 200);
    assert.equal(resClash.headers.get('Content-Type'), 'text/yaml; charset=utf-8');
    const clashYaml = await resClash.text();
    assert.ok(clashYaml.includes('proxies:'));
    assert.ok(clashYaml.includes('HK-01'));
    assert.ok(clashYaml.includes('节点选择'));

    // 3. Authorized Base64 request via query parameter
    const resB64 = await worker.fetch(new Request('https://mysub.workers.dev/mytesttoken?b64', {
        headers: { 'User-Agent': 'v2rayN/6.45' }
    }), mockEnv);
    assert.equal(resB64.status, 200);
    assert.equal(resB64.headers.get('Content-Type'), 'text/plain; charset=utf-8');
    const b64Body = await resB64.text();
    const decoded = base64Decode(b64Body);
    assert.ok(decoded.includes('trojan://'));
    assert.ok(decoded.includes('HK-01'));

    // 4. Auto detection by Clash User-Agent
    const resAutoClash = await worker.fetch(new Request('https://mysub.workers.dev/mytesttoken', {
        headers: { 'User-Agent': 'ClashMeta/v1.18.0' }
    }), mockEnv);
    assert.equal(resAutoClash.status, 200);
    assert.equal(resAutoClash.headers.get('Content-Type'), 'text/yaml; charset=utf-8');
});

test('matchRegex helper handles (?i) flag safely without regex syntax error', () => {
    assert.ok(matchRegex('(?i)(港|香港|HK)', '🇭🇰 香港 01'));
    assert.ok(matchRegex('(?i)(港|香港|HK)', 'my-hk-node'));
    assert.ok(!matchRegex('(?i)(港|香港|HK)', 'US-Node-01'));
    assert.ok(matchRegex('.*', 'Any Node Name'));
});

test('parseCustomProxyGroup parses subconverter custom group line properly', () => {
    const line1 = '节点选择`select`[]DIRECT`.*';
    const g1 = parseCustomProxyGroup(line1);
    assert.equal(g1.name, '节点选择');
    assert.equal(g1.type, 'select');
    assert.deepEqual(g1.rules, ['[]DIRECT', '.*']);

    const line2 = 'AI自动测速`url-test`[]美国节点`[]香港节点`http://www.gstatic.com/generate_204`300,,50';
    const g2 = parseCustomProxyGroup(line2);
    assert.equal(g2.name, 'AI自动测速');
    assert.equal(g2.type, 'url-test');
    assert.equal(g2.url, 'http://www.gstatic.com/generate_204');
    assert.equal(g2.interval, 300);
    assert.equal(g2.tolerance, 50);
    assert.deepEqual(g2.rules, ['[]美国节点', '[]香港节点']);
});

test('breakCycles breaks intentional mutual circular loops', () => {
    const circularGroups = [
        { name: '节点选择', proxies: ['香港节点', 'DIRECT', 'node1'] },
        { name: '香港节点', proxies: ['hk1', '节点选择'] }
    ];
    breakCycles(circularGroups);
    // 香港节点 was referenced by 节点选择, and 节点选择 was referenced by 香港节点.
    // breakCycles must break the cycle!
    const selectGroup = circularGroups.find(g => g.name === '节点选择');
    assert.ok(!selectGroup.proxies.includes('香港节点'));
    assert.ok(selectGroup.proxies.includes('DIRECT'));
});

test('generateClashConfig with user my.ini produces ZERO circular loops in ProxyGroups', () => {
    const myIniText = `
[custom]
ruleset=全球直连,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/direct.list
ruleset=德国节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/de.list
ruleset=香港节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/hk.list
ruleset=节点选择,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/proxy.list
ruleset=新加坡节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/sg.list
ruleset=台湾节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/tw.list
ruleset=美国节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/us.list
ruleset=全球拦截,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list
ruleset=应用净化,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list
ruleset=谷歌FCM,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list
ruleset=微软服务,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list
ruleset=电报信息,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Telegram.list
ruleset=OpenAi,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list
ruleset=油管视频,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list
ruleset=奈飞视频,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list
ruleset=国外媒体,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list
ruleset=全球直连,[]GEOIP,LAN
ruleset=全球直连,[]GEOIP,CN
ruleset=漏网之鱼,[]FINAL

custom_proxy_group=节点选择\`select\`[]DIRECT\`.*
custom_proxy_group=AI自动测速\`url-test\`[]美国节点\`[]香港节点\`[]日本节点\`[]新加坡节点\`http://www.gstatic.com/generate_204\`300
custom_proxy_group=OpenAi\`select\`[]AI自动测速\`[]美国节点\`[]日本节点\`[]新加坡节点\`[]节点选择
custom_proxy_group=油管视频\`select\`[]节点选择\`[]香港节点\`[]美国节点\`[]全球直连
custom_proxy_group=奈飞视频\`select\`[]节点选择\`[]香港节点\`[]台湾节点\`[]全球直连
custom_proxy_group=国外媒体\`select\`[]节点选择\`[]香港节点\`[]日本节点\`[]全球直连
custom_proxy_group=电报信息\`select\`[]节点选择\`[]全球直连
custom_proxy_group=微软服务\`select\`[]节点选择\`[]全球直连
custom_proxy_group=谷歌FCM\`select\`[]节点选择\`[]全球直连
custom_proxy_group=全球直连\`select\`[]DIRECT\`[]节点选择
custom_proxy_group=全球拦截\`select\`[]REJECT\`[]全球直连
custom_proxy_group=应用净化\`select\`[]REJECT\`[]全球直连
custom_proxy_group=漏网之鱼\`select\`[]节点选择\`[]香港节点\`[]全球直连
custom_proxy_group=香港节点\`select\`(?i)(港|香港|HK|Hong Kong|🇭🇰|HongKong)
custom_proxy_group=台湾节点\`select\`(?i)(台|台湾|台灣|TW|Tai Wan|🇹🇼|TaiWan|Taiwan)
custom_proxy_group=新加坡节点\`select\`(?i)(新|新加坡|SG|坡|狮城|🇸🇬|Singapore)
custom_proxy_group=韩国节点\`select\`(?i)(韩|韩国|韓國|KR|首尔|春川|🇰🇷|Korea)
custom_proxy_group=日本节点\`select\`(?i)(日|日本|JP|川日|东京|大阪|泉日|埼玉|沪日|深日|🇯🇵|Japan)
custom_proxy_group=德国节点\`select\`(?i)(德|德国|法兰克福|DE|🇩🇪|Germany)
custom_proxy_group=英国节点\`select\`(?i)(英|英国|UK|England|United Kingdom|伦敦|🇬🇧)
custom_proxy_group=美国节点\`select\`(?i)(美|美国|US|纽约|波特兰|达拉斯|俄勒|凤凰城|费利蒙|硅谷|拉斯|洛杉|圣何塞|圣克拉|西雅|芝加|🇺🇸|United States)
`;

    const parsedSub = parseSubConfig(myIniText);
    const mockNodes = [
        parseNode('trojan://p1@1.1.1.1:443#🇭🇰 香港 01'),
        parseNode('trojan://p2@2.2.2.2:443#🇩🇪 德国 01'),
        parseNode('trojan://p3@3.3.3.3:443#🇺🇸 美国 01'),
        parseNode('trojan://p4@4.4.4.4:443#🇹🇼 台湾 01'),
        parseNode('trojan://p5@5.5.5.5:443#🇸🇬 新加坡 01')
    ];
    const processedNodes = processNodes(mockNodes);
    const clashYaml = generateClashConfig(processedNodes, 'MySub', parsedSub);

    // 验证关键策略组正常生成
    assert.ok(clashYaml.includes('name: "OpenAi"'));
    assert.ok(clashYaml.includes('name: "油管视频"'));
    assert.ok(clashYaml.includes('name: "奈飞视频"'));
    assert.ok(clashYaml.includes('name: "节点选择"'));
    assert.ok(clashYaml.includes('name: "香港节点"'));
    assert.ok(clashYaml.includes('name: "漏网之鱼"'));

    // 严格图论环路检测：解析 YAML 中的 proxy-groups 邻接表，断言无任何环路
    const pgSection = clashYaml.split('\nproxy-groups:\n')[1].split(/\n(?:rule-providers|rules):/)[0];
    const groupMatches = [...pgSection.matchAll(/  - name:\s*"([^"]+)"\s*\n\s*type:\s*(\S+)[\s\S]*?proxies:\n([\s\S]*?)(?=\n  - name:|$)/g)];
    const groupNames = new Set(groupMatches.map(m => m[1]));
    const adj = new Map();

    for (const m of groupMatches) {
        const gName = m[1];
        const proxyLines = m[3].split('\n').map(l => l.trim()).filter(l => l.startsWith('-'));
        const proxies = proxyLines.map(l => {
            const raw = l.slice(1).trim();
            try { return JSON.parse(raw); } catch { return raw; }
        });
        adj.set(gName, proxies.filter(p => groupNames.has(p)));
    }

    // DFS 环路检测
    const visited = new Map();
    const detectedCycles = [];
    function dfs(u, path) {
        visited.set(u, 1);
        path.push(u);
        for (const v of adj.get(u) || []) {
            const state = visited.get(v) || 0;
            if (state === 1) {
                const idx = path.indexOf(v);
                detectedCycles.push(path.slice(idx).concat(v));
            } else if (state === 0) {
                dfs(v, path);
            }
        }
        path.pop();
        visited.set(u, 2);
    }

    for (const g of groupNames) {
        if (!visited.has(g)) dfs(g, []);
    }

    assert.equal(detectedCycles.length, 0, `Detected circular loops in proxy-groups: ${JSON.stringify(detectedCycles)}`);
});

test('Web UI rendering and KV configuration persistence', async () => {
    const kvStore = new Map();
    const mockEnv = {
        TOKEN: 'admintoken',
        GUESTTOKEN: 'guesttoken',
        KV: {
            get: async (k) => kvStore.get(k) || null,
            put: async (k, v) => kvStore.set(k, v),
            delete: async (k) => kvStore.delete(k)
        }
    };

    // 1. GET request from browser -> returns modernized HTML dashboard
    const resGet = await worker.fetch(new Request('https://mysub.workers.dev/admintoken', {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36' }
    }), mockEnv);
    assert.equal(resGet.status, 200);
    assert.equal(resGet.headers.get('Content-Type'), 'text/html;charset=utf-8');
    const html = await resGet.text();
    assert.ok(html.includes('汇聚订阅中心'));
    assert.ok(html.includes('admintoken'));
    assert.ok(html.includes('guesttoken'));
    assert.ok(html.includes('SUBCONFIG'));
    assert.ok(html.includes('一键导入'));
    assert.ok(html.includes('去重整理'));

    // 2. POST request to save LINK.txt and CONFIG.txt
    const savePayload = {
        link: 'trojan://pwd1@1.1.1.1:443#Node1\ntrojan://pwd2@2.2.2.2:443#Node2',
        subConfig: 'https://example.com/custom.ini'
    };
    const resPost = await worker.fetch(new Request('https://mysub.workers.dev/admintoken', {
        method: 'POST',
        headers: {
            'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(savePayload)
    }), mockEnv);
    assert.equal(resPost.status, 200);
    assert.equal(await resPost.text(), '保存成功');
    assert.equal(kvStore.get('LINK.txt'), savePayload.link);
    assert.equal(kvStore.get('CONFIG.txt'), savePayload.subConfig);
});

test('applyGhProxy accelerates raw.githubusercontent.com URLs', () => {
    const rawUrl = 'https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list';
    
    // 1. Worker 边缘中继模式 (默认)
    const workerRelay = applyGhProxy(rawUrl, 'worker', 'https://mysub.workers.dev/mytoken/rule');
    assert.equal(workerRelay, 'https://mysub.workers.dev/mytoken/rule?url=' + encodeURIComponent(rawUrl));

    // 2. 第三方镜像模式
    assert.equal(applyGhProxy(rawUrl, 'https://gh-proxy.com'), 'https://gh-proxy.com/https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list');
    assert.equal(applyGhProxy(rawUrl, 'https://ghproxy.net/'), 'https://ghproxy.net/https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list');
    assert.equal(applyGhProxy(rawUrl, 'https://ghfast.top/'), 'https://ghfast.top/https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list');

    // 3. 直连模式 (关闭加速)
    assert.equal(applyGhProxy(rawUrl, 'direct'), rawUrl);
    assert.equal(applyGhProxy(rawUrl, 'false'), rawUrl);
    assert.equal(applyGhProxy(rawUrl, 'off'), rawUrl);

    // 4. 防重复代理 (剥离已存在镜像前缀)
    const alreadyMirrored = 'https://ghproxy.net/https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list';
    assert.equal(normalizeTargetUrl(alreadyMirrored), rawUrl);
});

test('Multi-source failover pool generates prioritized sources', () => {
    const rawUrl = 'https://raw.githubusercontent.com/xiaopowanyi/Base/main/Rules/direct.list';
    const failoverList = getFailoverUrls(rawUrl);

    // 必须首先尝试直连源站
    assert.equal(failoverList[0], rawUrl);
    // 必须包含高可用镜像池，杜绝 ghproxy.net 单点宕机故障
    assert.ok(failoverList.includes('https://gh-proxy.com/' + rawUrl));
    assert.ok(failoverList.includes('https://ghfast.top/' + rawUrl));
    assert.ok(failoverList.includes('https://ghproxy.net/' + rawUrl));
    assert.ok(failoverList.includes('https://raw.gitmirror.com/xiaopowanyi/Base/main/Rules/direct.list'));
});

test('generateClashConfig fixes: DIRECT moved to end of 节点选择, AI自动测速 filters empty groups, rule-providers accelerated', () => {
    const myIniText = `
[custom]
ruleset=全球直连,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/direct.list
ruleset=德国节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/de.list
ruleset=香港节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/hk.list
ruleset=新加坡节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/sg.list
ruleset=美国节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/us.list
ruleset=日本节点,https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/jp.list
ruleset=漏网之鱼,[]FINAL

custom_proxy_group=节点选择\`select\`[]DIRECT\`.*
custom_proxy_group=AI自动测速\`url-test\`[]美国节点\`[]香港节点\`[]日本节点\`[]新加坡节点\`http://www.gstatic.com/generate_204\`300
custom_proxy_group=香港节点\`select\`(?i)(港|香港|HK|Hong Kong|🇭🇰|HongKong)
custom_proxy_group=新加坡节点\`select\`(?i)(新|新加坡|SG|坡|狮城|🇸🇬|Singapore)
custom_proxy_group=日本节点\`select\`(?i)(日|日本|JP|川日|东京|大阪|泉日|埼玉|沪日|深日|🇯🇵|Japan)
custom_proxy_group=德国节点\`select\`(?i)(德|德国|法兰克福|DE|🇩🇪|Germany)
custom_proxy_group=美国节点\`select\`(?i)(美|美国|US|纽约|波特兰|达拉斯|俄勒|凤凰城|费利蒙|硅谷|拉斯|洛杉|圣何塞|圣克拉|西雅|芝加|🇺🇸|United States)
custom_proxy_group=全球直连\`select\`[]DIRECT\`[]节点选择
custom_proxy_group=漏网之鱼\`select\`[]节点选择\`[]全球直连
`;

    const parsedSub = parseSubConfig(myIniText);
    // User has US, DE, SG, HK nodes, but NO Japan node
    const mockNodes = [
        parseNode('trojan://p1@1.1.1.1:443#Silicloud-US-Trojan'),
        parseNode('trojan://p2@2.2.2.2:443#Oracle-DE-Trojan'),
        parseNode('trojan://p3@3.3.3.3:443#Oracle-SG-Trojan'),
        parseNode('trojan://p5@5.5.5.5:443#HuaWei-HK-Trojan')
    ];
    const processedNodes = processNodes(mockNodes);

    // 1. 测试 Worker 边缘中继模式 (默认)
    const clashYamlWorker = generateClashConfig(processedNodes, 'MySub', parsedSub, 'worker', 'https://mysub.workers.dev/mytoken/rule');
    assert.ok(clashYamlWorker.includes('url: "https://mysub.workers.dev/mytoken/rule?url=https%3A%2F%2Fraw.githubusercontent.com%2Fxiaopowanyi%2FBase%2Frefs%2Fheads%2Fmain%2FRules%2Fdirect.list&format=text"'));
    assert.ok(clashYamlWorker.includes('format: text'), '必须为 .list 规则文件自动添加 format: text 声明');
    assert.ok(clashYamlWorker.includes('path: ./ruleset/direct.list'), '规则集路径后缀应自适应为 .list');

    // 2. 测试第三方镜像兼容模式 (例如用户指定 ghproxy.net 或 gh-proxy.com)
    const clashYamlProxyNet = generateClashConfig(processedNodes, 'MySub', parsedSub, 'https://ghproxy.net/');
    assert.ok(clashYamlProxyNet.includes('url: "https://ghproxy.net/https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/direct.list"'));

    // 3. 解析 proxy-groups
    const pgSection = clashYamlWorker.split('\nproxy-groups:\n')[1].split(/\n(?:rule-providers|rules):/)[0];
    const groupMatches = [...pgSection.matchAll(/  - name:\s*"([^"]+)"\s*\n\s*type:\s*(\S+)[\s\S]*?proxies:\n([\s\S]*?)(?=\n  - name:|$)/g)];
    const groups = new Map();

    for (const m of groupMatches) {
        const gName = m[1];
        const proxyLines = m[3].split('\n').map(l => l.trim()).filter(l => l.startsWith('-'));
        const proxies = proxyLines.map(l => {
            const raw = l.slice(1).trim();
            try { return JSON.parse(raw); } catch { return raw; }
        });
        groups.set(gName, { type: m[2], proxies });
    }

    // 验证 问题 1：节点选择 第一项绝不能是 DIRECT，应为 AI自动测速，DIRECT 在最后一位
    const nodeSelect = groups.get('节点选择');
    assert.ok(nodeSelect);
    assert.equal(nodeSelect.proxies[0], 'AI自动测速', '节点选择第一项必须为测速组');
    assert.notEqual(nodeSelect.proxies[0], 'DIRECT', '节点选择第一项绝不能是 DIRECT');
    assert.equal(nodeSelect.proxies[nodeSelect.proxies.length - 1], 'DIRECT', 'DIRECT 应置于末尾备选');

    // 验证 问题 2：AI自动测速 剔除了空分组“日本节点”，只保留具有真实节点的国家分组
    const aiTest = groups.get('AI自动测速');
    assert.ok(aiTest);
    assert.ok(aiTest.proxies.includes('美国节点'));
    assert.ok(aiTest.proxies.includes('香港节点'));
    assert.ok(aiTest.proxies.includes('新加坡节点'));
    assert.ok(!aiTest.proxies.includes('日本节点'), 'AI自动测速必须剔除只有 DIRECT 的空国家分组');
    assert.ok(!aiTest.proxies.includes('DIRECT'), 'AI自动测速中不应包含 DIRECT');
});

test('Rule relay endpoint (/rule) handles authorization, failover and edge caching', async () => {
    const mockEnv = {
        TOKEN: 'mytesttoken',
        GUESTTOKEN: 'myguesttoken'
    };

    // 1. 无效 Token 访问 /rule -> 拦截并返回 decoy
    const resUnauthorized = await worker.fetch(new Request('https://mysub.workers.dev/wrongtoken/rule?url=https://raw.githubusercontent.com/test/rule.list'), mockEnv);
    assert.equal(resUnauthorized.status, 200);
    const htmlText = await resUnauthorized.text();
    assert.ok(htmlText.includes('Welcome to nginx!'));

    // 2. 有效 Token 但缺少 url 参数 -> 400 Bad Request
    const resNoUrl = await worker.fetch(new Request('https://mysub.workers.dev/mytesttoken/rule'), mockEnv);
    assert.equal(resNoUrl.status, 400);

    // 3. 有效 Token 并请求有效规则文件 -> 成功拉取并设置缓存头
    const directUrl = 'https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/Rules/direct.list';
    const resRule = await worker.fetch(new Request(`https://mysub.workers.dev/mytesttoken/rule?url=${encodeURIComponent(directUrl)}`), mockEnv);
    assert.equal(resRule.status, 200);
    assert.equal(resRule.headers.get('Cache-Control'), 'public, max-age=86400');
    const content = await resRule.text();
    assert.ok(content.length > 0);

    // 4. 第二次请求 -> 触发内存或边缘命中 (HIT)
    const resRuleCached = await worker.fetch(new Request(`https://mysub.workers.dev/mytesttoken/rule?url=${encodeURIComponent(directUrl)}`), mockEnv);
    assert.equal(resRuleCached.status, 200);
    assert.equal(resRuleCached.headers.get('X-Cache-Status'), 'HIT-MEMORY');
});

test('Web UI includes GHPROXY settings and persists to KV', async () => {
    const kvStore = new Map();
    const mockEnv = {
        TOKEN: 'mytesttoken',
        KV: {
            get: async (key) => kvStore.get(key) || null,
            put: async (key, val) => kvStore.set(key, val),
            delete: async (key) => kvStore.delete(key)
        }
    };

    // 1. GET 请求管理页面 -> 验证包含 GHPROXY 选择与描述
    const resPage = await worker.fetch(new Request('https://mysub.workers.dev/mytesttoken', {
        headers: { 'User-Agent': 'Mozilla/5.0' }
    }), mockEnv);
    assert.equal(resPage.status, 200);
    const pageHtml = await resPage.text();
    assert.ok(pageHtml.includes('ghProxySelect'), '必须包含规则集加速选择器');
    assert.ok(pageHtml.includes('规则集加速与容灾中继'), '页面必须包含容灾中继卡片');

    // 2. POST 保存 GHPROXY 配置 -> 写入 KV GHPROXY.txt
    const savePayload = {
        link: 'trojan://p@1.1.1.1:443#Test',
        subConfig: 'https://raw.githubusercontent.com/test/my.ini',
        ghProxy: 'worker'
    };
    const resSave = await worker.fetch(new Request('https://mysub.workers.dev/mytesttoken', {
        method: 'POST',
        body: JSON.stringify(savePayload),
        headers: { 'Content-Type': 'application/json' }
    }), mockEnv);
    assert.equal(resSave.status, 200);
    assert.equal(kvStore.get('GHPROXY.txt'), 'worker');
});

test('Rule list adapters: cleanTextRuleList and convertRuleListToYaml', () => {
    const rawList = `
# This is a comment
; Another comment
// C-style comment

DOMAIN-SUFFIX,google.com
DOMAIN-KEYWORD,anthropic # Inline comment
IP-CIDR,127.0.0.0/8,no-resolve
`;

    // 1. cleanTextRuleList for Mihomo format: text
    const textOutput = cleanTextRuleList(rawList);
    assert.ok(!textOutput.includes('#'));
    assert.ok(!textOutput.includes(';'));
    assert.ok(textOutput.includes('DOMAIN-SUFFIX,google.com'));
    assert.ok(textOutput.includes('DOMAIN-KEYWORD,anthropic'));
    assert.ok(textOutput.includes('IP-CIDR,127.0.0.0/8,no-resolve'));

    // 2. convertRuleListToYaml for Classic Clash format: yaml (guaranteed payload: field)
    const yamlOutput = convertRuleListToYaml(rawList);
    assert.ok(isYamlRulePayload(yamlOutput), 'YAML 结果必须具有 payload 头部');
    assert.ok(yamlOutput.includes('payload:\n'));
    assert.ok(yamlOutput.includes('- "DOMAIN-SUFFIX,google.com"'));
    assert.ok(yamlOutput.includes('- "DOMAIN-KEYWORD,anthropic"'));
    assert.ok(yamlOutput.includes('- "IP-CIDR,127.0.0.0/8,no-resolve"'));
});

test('YAML parser (parseYaml) handles primitives, lists, maps, quotes and comments', () => {
    const yamlStr = `
# Global comment
port: 7890
socks-port: 7891
mode: rule # Inline mode
ipv6: false
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - https://1.1.1.1/dns-query#RULES
  fallback: []
  nameserver-policy:
    "geosite:cn,private": [223.5.5.5, 119.29.29.29]
proxies:
  - name: "Node-1"
    type: trojan
    server: 1.2.3.4
    port: 443
rules:
  - DOMAIN-SUFFIX,google.com,节点选择
  - MATCH,漏网之鱼
`;

    const parsed = parseYaml(yamlStr);
    assert.equal(parsed.port, 7890);
    assert.equal(parsed['socks-port'], 7891);
    assert.equal(parsed.mode, 'rule');
    assert.equal(parsed.ipv6, false);
    assert.equal(parsed['log-level'], 'info');

    assert.ok(parsed.dns);
    assert.equal(parsed.dns.enable, true);
    assert.equal(parsed.dns['enhanced-mode'], 'fake-ip');
    assert.equal(parsed.dns['fake-ip-range'], '198.18.0.1/16');
    assert.deepEqual(parsed.dns.fallback, []);
    assert.equal(parsed.dns.nameserver.length, 3);
    assert.equal(parsed.dns.nameserver[2], 'https://1.1.1.1/dns-query#RULES');

    assert.ok(parsed.dns['nameserver-policy']['geosite:cn,private']);
    assert.equal(parsed.dns['nameserver-policy']['geosite:cn,private'].length, 2);

    assert.equal(parsed.proxies.length, 1);
    assert.equal(parsed.proxies[0].name, 'Node-1');
    assert.equal(parsed.proxies[0].type, 'trojan');
    assert.equal(parsed.proxies[0].server, '1.2.3.4');
    assert.equal(parsed.proxies[0].port, 443);

    assert.equal(parsed.rules.length, 2);
    assert.equal(parsed.rules[0], 'DOMAIN-SUFFIX,google.com,节点选择');
    assert.equal(parsed.rules[1], 'MATCH,漏网之鱼');
});

test('Clash Party deepMerge override semantics (+rules prepend, rules+ append, key! replace, recursive merge)', () => {
    const target = {
        dns: {
            enable: false,
            'enhanced-mode': 'redir-host',
            nameserver: ['114.114.114.114']
        },
        rules: [
            'GEOIP,CN,DIRECT',
            'MATCH,漏网之鱼'
        ],
        tun: {
            enable: false,
            stack: 'gvisor'
        }
    };

    const override = {
        dns: {
            enable: true,
            'enhanced-mode': 'fake-ip',
            fallback: []
        },
        '+rules': [
            'DOMAIN-SUFFIX,linux.do,全球直连',
            'DOMAIN-KEYWORD,openai,节点选择'
        ],
        'tun!': {
            enable: true,
            stack: 'mixed',
            'auto-route': true
        }
    };

    const merged = deepMerge(target, override, true);

    // 1. Recursive merge for dns
    assert.equal(merged.dns.enable, true);
    assert.equal(merged.dns['enhanced-mode'], 'fake-ip');
    assert.deepEqual(merged.dns.nameserver, ['114.114.114.114']);
    assert.deepEqual(merged.dns.fallback, []);

    // 2. Prepend array for +rules
    assert.equal(merged.rules.length, 4);
    assert.equal(merged.rules[0], 'DOMAIN-SUFFIX,linux.do,全球直连');
    assert.equal(merged.rules[1], 'DOMAIN-KEYWORD,openai,节点选择');
    assert.equal(merged.rules[2], 'GEOIP,CN,DIRECT');
    assert.equal(merged.rules[3], 'MATCH,漏网之鱼');

    // 3. Force replacement for tun!
    assert.equal(merged.tun.enable, true);
    assert.equal(merged.tun.stack, 'mixed');
    assert.equal(merged.tun['auto-route'], true);

    // 4. Test rules+ append
    const appendOverride = {
        'rules+': ['FINAL,漏网之鱼,no-resolve']
    };
    deepMerge(merged, appendOverride, true);
    assert.equal(merged.rules.length, 5);
    assert.equal(merged.rules[4], 'FINAL,漏网之鱼,no-resolve');
});

test('dumpYaml generates valid YAML string formatting', () => {
    const obj = {
        port: 7890,
        mode: 'rule',
        ipv6: false,
        dns: {
            enable: true,
            nameserver: [
                '223.5.5.5',
                'https://1.1.1.1/dns-query#RULES'
            ]
        },
        proxies: [
            {
                name: 'Test Node',
                type: 'ss',
                server: '1.2.3.4',
                port: 8388
            }
        ]
    };

    const yamlStr = dumpYaml(obj);
    assert.ok(yamlStr.includes('port: 7890'));
    assert.ok(yamlStr.includes('mode: rule'));
    assert.ok(yamlStr.includes('ipv6: false'));
    assert.ok(yamlStr.includes('dns:'));
    assert.ok(yamlStr.includes('  enable: true'));
    assert.ok(yamlStr.includes('  nameserver:'));
    assert.ok(yamlStr.includes('    - 223.5.5.5'));
    assert.ok(yamlStr.includes('    - "https://1.1.1.1/dns-query#RULES"'));
    assert.ok(yamlStr.includes('proxies:'));
    assert.ok(yamlStr.includes('  - name: Test Node'));
    assert.ok(yamlStr.includes('    type: ss'));
});

test('applyYamlOverride merges base Clash YAML and override YAML seamlessly', () => {
    const baseYaml = `
port: 7890
socks-port: 7891
mode: rule
dns:
  enable: true
  nameserver:
    - 223.5.5.5
rules:
  - GEOIP,CN,DIRECT
  - MATCH,漏网之鱼
`;

    const overrideYaml = `
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fallback: []
tun:
  enable: true
  stack: mixed
+rules:
  - DOMAIN-SUFFIX,linux.do,全球直连
`;

    const result = applyYamlOverride(baseYaml, overrideYaml);
    assert.ok(result.includes('port: 7890'));
    assert.ok(result.includes('enhanced-mode: fake-ip'));
    assert.ok(result.includes('fake-ip-range: 198.18.0.1/16'));
    assert.ok(result.includes('fallback: []'));
    assert.ok(result.includes('tun:'));
    assert.ok(result.includes('  enable: true'));
    assert.ok(result.includes('  stack: mixed'));

    // Check rules order: prepended rule must precede existing rules
    const idxPrepend = result.indexOf('DOMAIN-SUFFIX,linux.do,全球直连');
    const idxCn = result.indexOf('GEOIP,CN,DIRECT');
    const idxMatch = result.indexOf('MATCH,漏网之鱼');
    assert.ok(idxPrepend !== -1, 'Prepend rule must be present');
    assert.ok(idxCn !== -1, 'Original rule must be present');
    assert.ok(idxPrepend < idxCn, 'Prepend rule must come BEFORE original rules');
    assert.ok(idxCn < idxMatch, 'MATCH must follow GEOIP');
});

test('Web UI includes OVERRIDE settings and persists OVERRIDE.txt to KV', async () => {
    const kvStore = new Map();
    const mockEnv = {
        TOKEN: 'mytesttoken',
        KV: {
            get: async (k) => kvStore.get(k) || null,
            put: async (k, v) => kvStore.set(k, v)
        }
    };

    // 1. GET 网页端渲染 -> 包含 OVERRIDE 卡片和预设
    const reqGet = new Request('https://mysub.workers.dev/mytesttoken', {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    });
    const resGet = await worker.fetch(reqGet, mockEnv);
    const pageHtml = await resGet.text();
    assert.ok(pageHtml.includes('Clash YAML 覆写配置 (OVERRIDE)'), '页面必须包含 OVERRIDE 配置卡片');
    assert.ok(pageHtml.includes('overrideInput'), '页面必须包含 overrideInput 输入框');
    assert.ok(pageHtml.includes('applyOverridePreset'), '页面必须包含 applyOverridePreset 预设切换函数');

    // 2. POST 保存 OVERRIDE 配置 -> 写入 KV OVERRIDE.txt
    const savePayload = {
        link: 'trojan://p@1.1.1.1:443#Test',
        subConfig: 'https://raw.githubusercontent.com/test/my.ini',
        ghProxy: 'worker',
        override: 'https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/override.yaml'
    };
    const resSave = await worker.fetch(new Request('https://mysub.workers.dev/mytesttoken', {
        method: 'POST',
        body: JSON.stringify(savePayload),
        headers: { 'Content-Type': 'application/json' }
    }), mockEnv);
    assert.equal(resSave.status, 200);
    assert.equal(kvStore.get('OVERRIDE.txt'), 'https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/override.yaml');
});

test('Worker fetch endpoint handles ?override= query and ?override=none correctly', async () => {
    const mockEnv = {
        TOKEN: 'mytesttoken',
        LINK: 'trojan://password@1.1.1.1:443#HK-Trojan',
        OVERRIDE: 'none' // 禁用全局覆盖以便测试独立参数
    };

    // 1. 请求无覆写 (OVERRIDE=none)
    const reqNoOv = new Request('https://mysub.workers.dev/mytesttoken?clash', {
        headers: { 'User-Agent': 'clash-verge/v1.0' }
    });
    const resNoOv = await worker.fetch(reqNoOv, mockEnv);
    assert.equal(resNoOv.status, 200);
    const yamlNoOv = await resNoOv.text();
    assert.ok(!yamlNoOv.includes('custom-test.com'), '未启用覆写时不包含 override 特有规则');
    assert.ok(!yamlNoOv.includes('stack: mixed'), '未启用覆写时不包含 override 特有 tun 配置');
    assert.ok(!yamlNoOv.includes('fallback: []'), '未启用覆写时不包含 override 特有清空 fallback');

    // 2. 请求带嵌入式或自包含 override (如自定义 DNS 与 TUN)
    const customOverrideText = `
dns:
  fallback: []
tun:
  enable: true
  stack: mixed
+rules:
  - DOMAIN-SUFFIX,custom-test.com,全球直连
`;
    const reqWithOv = new Request(`https://mysub.workers.dev/mytesttoken?clash&override=${encodeURIComponent(customOverrideText)}`, {
        headers: { 'User-Agent': 'clash-verge/v1.0' }
    });
    const resWithOv = await worker.fetch(reqWithOv, mockEnv);
    assert.equal(resWithOv.status, 200);
    const yamlWithOv = await resWithOv.text();
    assert.ok(yamlWithOv.includes('fallback: []'), '生效覆写后包含 fallback: []');
    assert.ok(yamlWithOv.includes('stack: mixed'), '生效覆写后包含 tun stack: mixed');
    assert.ok(yamlWithOv.includes('DOMAIN-SUFFIX,custom-test.com,全球直连'), '生效覆写后包含 +rules 前置规则');
});

test('Parse subconfig handles prefixed rulesets (e.g. clash-classic:https://kelee.one/...)', () => {
    const iniText = `
[custom]
ruleset=OpenAi,clash-classic:https://kelee.one/Tool/Clash/Rule/AI.yaml
ruleset=奈飞视频,clash-classic:https://rule.kelee.one/Clash/Netflix.yaml,3600
ruleset=域名分组,clash-domain:https://example.com/domain.list
ruleset=IP分组,clash-ipcidr:https://example.com/ip.list
ruleset=普通规则,https://raw.githubusercontent.com/test/direct.list
ruleset=全球直连,[]GEOIP,CN
`;

    const parsed = parseSubConfig(iniText);
    assert.equal(parsed.rulesets.length, 5);
    assert.equal(parsed.directRules.length, 1);

    const r0 = parsed.rulesets[0];
    assert.equal(r0.group, 'OpenAi');
    assert.equal(r0.url, 'https://kelee.one/Tool/Clash/Rule/AI.yaml');
    assert.equal(r0.behavior, 'classical');
    assert.equal(r0.interval, 86400);

    const r1 = parsed.rulesets[1];
    assert.equal(r1.group, '奈飞视频');
    assert.equal(r1.url, 'https://rule.kelee.one/Clash/Netflix.yaml');
    assert.equal(r1.behavior, 'classical');
    assert.equal(r1.interval, 3600);

    const r2 = parsed.rulesets[2];
    assert.equal(r2.behavior, 'domain');

    const r3 = parsed.rulesets[3];
    assert.equal(r3.behavior, 'ipcidr');
});

test('Special source kelee.one UA spoofing and automatic worker relay proxying', () => {
    // 1. User-Agent spoofing for kelee.one
    const keleeHeaders = getRequestHeadersForUrl('https://rule.kelee.one/Clash/Proxy.yaml');
    assert.equal(keleeHeaders['User-Agent'], 'Loon/991 CFNetwork/3896.100.1.1.1 Darwin/27.0.0');

    const standardHeaders = getRequestHeadersForUrl('https://raw.githubusercontent.com/test/rule.list');
    assert.ok(standardHeaders['User-Agent'].includes('Clash/Mihomo'));

    // 2. applyGhProxy automatically forces worker relay for kelee.one when workerRuleBase is available
    const workerRuleBase = 'https://mysub.workers.dev/token123/rule';
    const proxiedKelee = applyGhProxy('https://rule.kelee.one/Clash/Netflix.yaml', 'worker', workerRuleBase, 'yaml');
    assert.equal(proxiedKelee, 'https://mysub.workers.dev/token123/rule?url=https%3A%2F%2Frule.kelee.one%2FClash%2FNetflix.yaml&format=yaml');

    // 3. Even with ghProxy=direct, kelee.one MUST route through worker relay to inject required Loon UA
    const proxiedDirectKelee = applyGhProxy('https://rule.kelee.one/Clash/Netflix.yaml', 'direct', workerRuleBase, 'yaml');
    assert.equal(proxiedDirectKelee, 'https://mysub.workers.dev/token123/rule?url=https%3A%2F%2Frule.kelee.one%2FClash%2FNetflix.yaml&format=yaml');
});

test('Worker request isolation: multiple consecutive calls do not accumulate state', async () => {
    const env = {
        TOKEN: 'isolation-token',
        LINK: 'vless://d9f94f97-7521-482a-9e11-e4ab1844b204@1.1.1.1:443?security=tls#Node1',
        LINKSUB: 'vless://d9f94f97-7521-482a-9e11-e4ab1844b204@2.2.2.2:443?security=tls#Node2'
    };

    // First request
    const req1 = new Request('https://example.com/isolation-token?b64');
    const res1 = await worker.fetch(req1, env);
    const text1 = base64Decode(await res1.text());
    const lines1 = text1.trim().split('\n').filter(Boolean);

    // Second request
    const req2 = new Request('https://example.com/isolation-token?b64');
    const res2 = await worker.fetch(req2, env);
    const text2 = base64Decode(await res2.text());
    const lines2 = text2.trim().split('\n').filter(Boolean);

    // Must have identical count and no duplicate accumulation
    assert.equal(lines1.length, 2);
    assert.equal(lines2.length, 2);
});

test('loadSubConfig: direct parsing of inline INI content without network fetching', async () => {
    const inlineIni = `
[custom]
ruleset=🎯 全球直连,https://raw.githubusercontent.com/test/direct.list
custom_proxy_group=🎯 全球直连\`select\`[]DIRECT\`[]PROXY
`;
    const parsed = await loadSubConfig(inlineIni);
    assert.ok(parsed);
    assert.equal(parsed.rulesets.length, 1);
    assert.equal(parsed.rulesets[0].group, '🎯 全球直连');
    assert.equal(parsed.customGroups.length, 1);
});

test('Parse nodes with IPv6 bracketed host (VLESS, Trojan, SS, Hy2, TUIC)', () => {
    // 1. VLESS IPv6
    const vlessIpv6 = 'vless://uuid-123@[2606:4700::1]:443?security=tls#IPv6-Vless';
    const parsedVless = parseVless(vlessIpv6);
    assert.ok(parsedVless);
    assert.equal(parsedVless.server, '2606:4700::1');
    assert.equal(parsedVless.port, 443);

    // 2. Trojan IPv6
    const trojanIpv6 = 'trojan://pass123@[2400:3200::1]:8443?security=tls#IPv6-Trojan';
    const parsedTrojan = parseTrojan(trojanIpv6);
    assert.ok(parsedTrojan);
    assert.equal(parsedTrojan.server, '2400:3200::1');
    assert.equal(parsedTrojan.port, 8443);

    // 3. Shadowsocks IPv6
    const ssUserInfo = base64Encode('aes-256-gcm:mypass');
    const ssIpv6 = `ss://${ssUserInfo}@[2001:db8::2]:8388#IPv6-SS`;
    const parsedSS = parseShadowsocks(ssIpv6);
    assert.ok(parsedSS);
    assert.equal(parsedSS.server, '2001:db8::2');
    assert.equal(parsedSS.port, 8388);

    // 4. Hysteria2 IPv6
    const hy2Ipv6 = 'hysteria2://mypass@[2001:4860:4860::8888]:443#IPv6-Hy2';
    const parsedHy2 = parseHysteria2(hy2Ipv6);
    assert.ok(parsedHy2);
    assert.equal(parsedHy2.server, '2001:4860:4860::8888');
    assert.equal(parsedHy2.port, 443);

    // 5. TUIC IPv6
    const tuicIpv6 = 'tuic://myuuid:mypass@[2606:4700:4700::1111]:8443#IPv6-TUIC';
    const parsedTuic = parseTuic(tuicIpv6);
    assert.ok(parsedTuic);
    assert.equal(parsedTuic.server, '2606:4700:4700::1111');
    assert.equal(parsedTuic.port, 8443);
});

test('nodeToUri supports TUIC, SSR, and IPv6 authority formatting', () => {
    // 1. formatHostForUri
    assert.equal(formatHostForUri('1.1.1.1'), '1.1.1.1');
    assert.equal(formatHostForUri('example.com'), 'example.com');
    assert.equal(formatHostForUri('2606:4700::1'), '[2606:4700::1]');
    assert.equal(formatHostForUri('[2606:4700::1]'), '[2606:4700::1]');

    // 2. nodeToUri for TUIC
    const tuicNode = {
        name: 'My Tuic Node',
        type: 'tuic',
        server: '2606:4700::1',
        port: 8443,
        uuid: 'uuid-abc',
        password: 'pass-def',
        sni: 'tuic.example.com',
        congestionController: 'bbr'
    };
    const tuicUri = nodeToUri(tuicNode);
    assert.ok(tuicUri.startsWith('tuic://uuid-abc:pass-def@[2606:4700::1]:8443'));
    assert.ok(tuicUri.includes('congestion_controller=bbr'));
    assert.ok(tuicUri.includes('#My%20Tuic%20Node'));

    // 3. nodeToUri for SSR
    const ssrNode = {
        name: 'My SSR Node',
        type: 'ssr',
        server: 'ssr.example.com',
        port: 443,
        protocol: 'auth_aes128_md5',
        cipher: 'aes-128-cfb',
        obfs: 'tls1.2_ticket_auth',
        password: 'password123'
    };
    const ssrUri = nodeToUri(ssrNode);
    assert.ok(ssrUri.startsWith('ssr://'));
    const parsedBack = parseShadowsocksR(ssrUri);
    assert.ok(parsedBack);
    assert.equal(parsedBack.server, 'ssr.example.com');
    assert.equal(parsedBack.port, 443);
    assert.equal(parsedBack.cipher, 'aes-128-cfb');
    assert.equal(parsedBack.name, 'My SSR Node');
});

test('ShadowsocksR round-trip preserves bracketed IPv6 host', () => {
    const ssrNode = {
        name: 'IPv6 SSR',
        type: 'ssr',
        server: '2001:db8::1',
        port: 443,
        protocol: 'origin',
        cipher: 'none',
        obfs: 'plain',
        password: 'password123'
    };
    const uri = nodeToUri(ssrNode);
    const parsed = parseShadowsocksR(uri);
    assert.ok(parsed);
    assert.equal(parsed.server, '2001:db8::1');
    assert.equal(parsed.port, 443);
    assert.equal(parsed.password, 'password123');
});

test('loadSubConfig fetches HTTP URLs containing ruleset query parameters', async () => {
    const originalFetch = globalThis.fetch;
    let requestedUrl = '';
    globalThis.fetch = async (requestUrl) => {
        requestedUrl = String(requestUrl);
        return new Response('[custom]\nruleset=🎯 全球直连,https://example.com/direct.list');
    };

    try {
        const parsed = await loadSubConfig('https://example.com/config?ruleset=test');
        assert.equal(requestedUrl, 'https://example.com/config?ruleset=test');
        assert.ok(parsed);
        assert.equal(parsed.rulesets.length, 1);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('sanitizeDnsFakeIpFilter converts rule mode fake-ip-filter to blacklist for Clash Party compatibility', () => {
    const baseYaml = `
port: 7890
dns:
  enable: true
`;
    const overrideYaml = `
dns:
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - DOMAIN-SUFFIX,lan,real-ip
    - DOMAIN-KEYWORD,time,real-ip
    - DOMAIN,localhost.ptlogin2.qq.com,real-ip
    - DOMAIN-SUFFIX,workers.dev,fake-ip
    - MATCH,fake-ip
`;
    const merged = applyYamlOverride(baseYaml, overrideYaml);
    assert.ok(!merged.includes('fake-ip-filter-mode: rule'));
    assert.ok(merged.includes('+.lan'));
    assert.ok(merged.includes('*time*'));
    assert.ok(merged.includes('localhost.ptlogin2.qq.com'));
    assert.ok(!merged.includes('workers.dev'));
});



