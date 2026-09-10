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
    extractRuleProviderName
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
`;
    const parsedSubConfig = parseSubConfig(sampleIni);
    assert.equal(parsedSubConfig.rulesets.length, 5);
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
