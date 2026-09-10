import test from 'node:test';
import assert from 'node:assert/strict';
import worker, {
    base64Encode,
    base64Decode,
    parseVless,
    parseVmess,
    parseTrojan,
    parseShadowsocks,
    parseHysteria2,
    parseNode,
    nodeToUri,
    processNodes,
    generateClashConfig,
    generateBase64Config,
    parseClashProxies,
    parseSubConfig,
    extractRuleProviderName,
    matchRegex,
    parseCustomProxyGroup,
    breakCycles
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
    assert.equal(node.clientFingerprint, undefined); // No forced default
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
    assert.ok(clashYaml.includes('path: ./ruleset/direct.yaml'));
    assert.ok(clashYaml.includes('RULE-SET,direct,全球直连'));
    assert.ok(clashYaml.includes('de:'));
    assert.ok(clashYaml.includes('path: ./ruleset/de.yaml'));
    assert.ok(clashYaml.includes('RULE-SET,de,德国节点'));
    assert.ok(clashYaml.includes('hk:'));
    assert.ok(clashYaml.includes('path: ./ruleset/hk.yaml'));
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
