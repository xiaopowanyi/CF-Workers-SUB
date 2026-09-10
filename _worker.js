/**
 * 自建汇聚订阅 CF-Workers-SUB
 * 原生内置转换引擎（无需外部后端转换服务，安全不泄露节点，无转换超时）
 * 支持 Clash (Mihomo) 与 Base64 订阅生成
 * 节点信息严格按照填写的节点配置生成，不强制添加默认值，由客户端自行处理默认策略
 * 支持通过 环境变量 (SUBCONFIG) 或 前端页面选择/填写保存自定义 .ini 规则配置链接
 */

let mytoken = 'auto';
let guestToken = '';
let BotToken = '';
let ChatID = '';
let TG = 0;
let FileName = 'CF-Workers-SUB';
let SUBUpdateTime = 6;
let total = 99; // TB
let timestamp = 4102329600000; // 2099-12-31

// 默认自建节点与订阅链接
let MainData = `
https://cfxr.eu.org/getSub
`;

// 默认订阅规则配置文件 (支持环境变量 SUBCONFIG 覆盖，或前端管理页面填写保存至 KV)
let subConfig = "https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/my.ini";

// SUBCONFIG 缓存 (URL -> { parsed, time })
const subConfigCache = new Map();

export default {
	async fetch(request, env) {
		const userAgentHeader = request.headers.get('User-Agent') || '';
		const userAgent = userAgentHeader.toLowerCase();
		const url = new URL(request.url);
		const token = url.searchParams.get('token');

		mytoken = env.TOKEN || mytoken;
		BotToken = env.TGTOKEN || BotToken;
		ChatID = env.TGID || ChatID;
		TG = env.TG || TG;
		subConfig = env.SUBCONFIG || subConfig;
		FileName = env.SUBNAME || FileName;
		SUBUpdateTime = env.SUBUPTIME || SUBUpdateTime;
		const envScv = env.SCV === 'true';

		const currentDate = new Date();
		currentDate.setHours(0, 0, 0, 0);
		const timeTemp = Math.ceil(currentDate.getTime() / 1000);
		const fakeToken = await MD5MD5(`${mytoken}${timeTemp}`);
		guestToken = env.GUESTTOKEN || env.GUEST || guestToken;
		if (!guestToken) guestToken = await MD5MD5(mytoken);
		const 访客订阅 = guestToken;

		// 鉴权检查
		const isAuthorized = [mytoken, fakeToken, 访客订阅].includes(token) ||
			url.pathname === ("/" + mytoken) ||
			url.pathname.includes("/" + mytoken + "?") ||
			(url.pathname === "/sub" && [mytoken, fakeToken, 访客订阅].includes(token));

		if (!isAuthorized) {
			if (TG == 1 && url.pathname !== "/" && url.pathname !== "/favicon.ico") {
				await sendMessage(`#异常访问 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`);
			}
			if (env.URL302) return Response.redirect(env.URL302, 302);
			else if (env.URL) return await proxyURL(env.URL, url);
			else return new Response(await nginx(), {
				status: 200,
				headers: { 'Content-Type': 'text/html; charset=UTF-8' }
			});
		}

		// 解析当前生效的 SUBCONFIG (优先级: URL参数 ?config= > KV 中保存的 CONFIG.txt > 环境变量 SUBCONFIG > 默认 subConfig)
		let currentSubConfig = url.searchParams.get('config');
		if (!currentSubConfig && env.KV) {
			currentSubConfig = await env.KV.get('CONFIG.txt');
		}
		if (!currentSubConfig) {
			currentSubConfig = env.SUBCONFIG || subConfig;
		}

		// KV 管理页面与数据加载
		if (env.KV) {
			await 迁移地址列表(env, 'LINK.txt');
			if (userAgent.includes('mozilla') && !url.search && url.pathname !== '/sub') {
				await sendMessage(`#编辑订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`);
				return await renderKVPage(request, env, 'LINK.txt', 访客订阅, currentSubConfig);
			} else {
				MainData = await env.KV.get('LINK.txt') || MainData;
			}
		} else {
			MainData = env.LINK || MainData;
			if (env.LINKSUB) {
				const subs = await parseTextLines(env.LINKSUB);
				MainData = MainData + '\n' + subs.join('\n');
			}
		}

		// 记录访问日志
		await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`);

		// 收集自建节点与远程订阅链接
		const allLines = await parseTextLines(MainData);
		const directNodes = [];
		const remoteSubUrls = [];

		for (const line of allLines) {
			if (line.toLowerCase().startsWith('http://') || line.toLowerCase().startsWith('https://')) {
				remoteSubUrls.push(line);
			} else {
				directNodes.push(line);
			}
		}

		// 拉取远程订阅
		const remoteContents = await fetchSubscriptions(remoteSubUrls);
		let allRawNodeLines = [...directNodes];
		let clashParsedProxies = [];

		for (const content of remoteContents) {
			if (!content) continue;
			if (content.includes('proxies:')) {
				// 远程订阅返回了 Clash YAML 配置
				const parsed = parseClashProxies(content);
				clashParsedProxies.push(...parsed);
			} else if (isValidBase64(content)) {
				// 远程订阅返回了 Base64
				try {
					const decoded = base64Decode(content);
					const lines = await parseTextLines(decoded);
					allRawNodeLines.push(...lines);
				} catch (e) {
					console.error('Base64 decode error on remote sub:', e);
				}
			} else if (content.includes('://')) {
				// 明文链接
				const lines = await parseTextLines(content);
				allRawNodeLines.push(...lines);
			}
		}

		// 解析自建和明文节点 (严格按照节点填写的参数解析，不填充任意默认值)
		const parsedDirectNodes = [];
		for (const rawLine of allRawNodeLines) {
			const node = parseNode(rawLine, envScv);
			if (node) parsedDirectNodes.push(node);
		}

		// 聚合所有节点并去重规范化
		const allNodes = processNodes([...parsedDirectNodes, ...clashParsedProxies]);

		// 判断请求格式：只支持 clash 与 base64
		let outputFormat = 'base64';
		if (url.searchParams.has('clash') || url.searchParams.has('meta') || url.searchParams.has('mihomo')) {
			outputFormat = 'clash';
		} else if (url.searchParams.has('b64') || url.searchParams.has('base64')) {
			outputFormat = 'base64';
		} else if (userAgent.includes('clash') || userAgent.includes('meta') || userAgent.includes('mihomo') || userAgent.includes('stash')) {
			outputFormat = 'clash';
		}

		// 构建响应头
		const responseHeaders = {
			"Profile-Update-Interval": `${SUBUpdateTime}`,
			"Profile-web-page-url": request.url.split('?')[0]
		};

		if (!userAgent.includes('mozilla')) {
			responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(FileName)}`;
		}

		if (outputFormat === 'clash') {
			responseHeaders["Content-Type"] = "text/yaml; charset=utf-8";
			// 根据当前选择或配置的 SUBCONFIG 解析规则与分组
			const subConfigParsed = await loadSubConfig(currentSubConfig);
			const clashYaml = generateClashConfig(allNodes, FileName, subConfigParsed);
			return new Response(clashYaml, { headers: responseHeaders });
		} else {
			responseHeaders["Content-Type"] = "text/plain; charset=utf-8";
			const base64Content = generateBase64Config(allNodes);
			return new Response(base64Content, { headers: responseHeaders });
		}
	}
};

// ==========================================
// 1. Base64 与 UTF-8 编解码
// ==========================================

export function base64Encode(str) {
	if (!str) return '';
	const bytes = new TextEncoder().encode(str);
	const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
	return btoa(binString);
}

export function base64Decode(str) {
	if (!str) return '';
	let clean = str.replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/');
	while (clean.length % 4 !== 0) {
		clean += '=';
	}
	const binString = atob(clean);
	const bytes = Uint8Array.from(binString, (m) => m.charCodeAt(0));
	return new TextDecoder('utf-8').decode(bytes);
}

function isValidBase64(str) {
	const clean = str.replace(/[\r\n\s]/g, '');
	if (!clean || clean.length % 4 !== 0) return false;
	return /^[A-Za-z0-9+/=]+$/.test(clean);
}

function safeDecodeURIComponent(str) {
	try {
		return decodeURIComponent(str);
	} catch {
		return str;
	}
}

// ==========================================
// 2. 统一多协议节点解析器（严格按填写的节点信息解析，不赋默认值）
// ==========================================

export function parseVless(rawUri, envScv = false) {
	const match = rawUri.match(/^vless:\/\/([^@]+)@([^:?#]+):([0-9]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const uuid = match[1];
	const server = match[2];
	const port = parseInt(match[3], 10);
	const searchParams = new URLSearchParams(match[4] ? match[4].slice(1) : '');
	const name = match[5] ? safeDecodeURIComponent(match[5].slice(1)).trim() : `${server}:${port}`;

	const security = (searchParams.get('security') || '').toLowerCase();
	const isTls = security === 'tls' || security === 'reality';
	const isReality = security === 'reality';
	const net = (searchParams.get('type') || '').toLowerCase();
	const sni = searchParams.get('sni') || searchParams.get('peer') || '';
	const fp = searchParams.get('fp') || searchParams.get('client-fingerprint') || '';

	const proxy = {
		name,
		type: 'vless',
		server,
		port,
		uuid,
		rawUri
	};

	// 仅当节点显式指定时才赋值
	if (searchParams.has('udp')) {
		proxy.udp = searchParams.get('udp') === '1' || searchParams.get('udp') === 'true';
	}
	if (isTls) proxy.tls = true;
	if (sni) proxy.sni = sni;
	if (fp) proxy.clientFingerprint = fp;
	if (searchParams.get('allowInsecure') === '1' || searchParams.get('insecure') === '1' || envScv) {
		proxy.skipCertVerify = true;
	}
	if (searchParams.get('flow')) {
		proxy.flow = searchParams.get('flow');
	}

	if (isReality) {
		proxy.realityOpts = {};
		if (searchParams.get('pbk') || searchParams.get('publicKey')) {
			proxy.realityOpts.publicKey = searchParams.get('pbk') || searchParams.get('publicKey');
		}
		if (searchParams.get('sid') || searchParams.get('shortId')) {
			proxy.realityOpts.shortId = searchParams.get('sid') || searchParams.get('shortId');
		}
		if (searchParams.get('spx') || searchParams.get('spiderX')) {
			proxy.realityOpts.spiderX = searchParams.get('spx') || searchParams.get('spiderX');
		}
	}

	if (net && net !== 'tcp') {
		proxy.network = net;
		if (net === 'ws') {
			proxy.wsOpts = {};
			if (searchParams.get('path')) {
				proxy.wsOpts.path = safeDecodeURIComponent(searchParams.get('path'));
			}
			if (searchParams.get('host')) {
				proxy.wsOpts.headers = { Host: searchParams.get('host') };
			}
		} else if (net === 'grpc') {
			const svc = searchParams.get('serviceName') || searchParams.get('service') || searchParams.get('path');
			if (svc) {
				proxy.grpcOpts = { serviceName: svc };
			}
		}
	}

	return proxy;
}

export function parseVmess(rawUri, envScv = false) {
	try {
		const content = rawUri.replace(/^vmess:\/\//i, '').trim();
		const jsonStr = base64Decode(content);
		const item = JSON.parse(jsonStr);

		const isTls = item.tls === 'tls' || item.tls === true || item.tls === '1';
		const net = (item.net || '').toLowerCase();
		const fp = item.fp || '';

		const proxy = {
			name: (item.ps || `${item.add}:${item.port}`).trim(),
			type: 'vmess',
			server: item.add,
			port: parseInt(item.port, 10),
			uuid: item.id,
			rawUri
		};

		if (item.aid !== undefined && item.aid !== null && item.aid !== '') {
			proxy.alterId = parseInt(item.aid, 10);
		}
		if (item.scy) proxy.cipher = item.scy;
		if (item.udp !== undefined) {
			proxy.udp = item.udp === true || item.udp === 'true' || item.udp === '1';
		}
		if (isTls) proxy.tls = true;
		if (item.sni || item.host) proxy.sni = item.sni || item.host;
		if (fp) proxy.clientFingerprint = fp;
		if (envScv || item.skipCertVerify === true) proxy.skipCertVerify = true;

		if (net && net !== 'tcp') {
			proxy.network = net;
			if (net === 'ws') {
				proxy.wsOpts = {};
				if (item.path) proxy.wsOpts.path = item.path;
				if (item.host) proxy.wsOpts.headers = { Host: item.host };
			} else if (net === 'grpc') {
				const svc = item.path || item.serviceName;
				if (svc) proxy.grpcOpts = { serviceName: svc };
			} else if (net === 'h2' || net === 'http') {
				proxy.h2Opts = {};
				if (item.host) proxy.h2Opts.host = [item.host];
				if (item.path) proxy.h2Opts.path = item.path;
			}
		}

		return proxy;
	} catch {
		return null;
	}
}

export function parseTrojan(rawUri, envScv = false) {
	const match = rawUri.match(/^trojan:\/\/([^@]+)@([^:?#]+):([0-9]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const password = match[1];
	const server = match[2];
	const port = parseInt(match[3], 10);
	const searchParams = new URLSearchParams(match[4] ? match[4].slice(1) : '');
	const name = match[5] ? safeDecodeURIComponent(match[5].slice(1)).trim() : `${server}:${port}`;

	const sni = searchParams.get('sni') || searchParams.get('peer') || '';
	const net = (searchParams.get('type') || '').toLowerCase();
	const fp = searchParams.get('fp') || searchParams.get('client-fingerprint') || '';

	const proxy = {
		name,
		type: 'trojan',
		server,
		port,
		password,
		rawUri
	};

	if (searchParams.has('udp')) {
		proxy.udp = searchParams.get('udp') === '1' || searchParams.get('udp') === 'true';
	}
	if (sni) proxy.sni = sni;
	if (fp) proxy.clientFingerprint = fp;
	if (searchParams.get('allowInsecure') === '1' || searchParams.get('insecure') === '1' || envScv) {
		proxy.skipCertVerify = true;
	}

	if (net && net !== 'tcp') {
		proxy.network = net;
		if (net === 'ws') {
			proxy.wsOpts = {};
			if (searchParams.get('path')) {
				proxy.wsOpts.path = safeDecodeURIComponent(searchParams.get('path'));
			}
			if (searchParams.get('host')) {
				proxy.wsOpts.headers = { Host: searchParams.get('host') };
			}
		} else if (net === 'grpc') {
			const svc = searchParams.get('serviceName') || searchParams.get('service') || searchParams.get('path');
			if (svc) proxy.grpcOpts = { serviceName: svc };
		}
	}

	return proxy;
}

export function parseShadowsocks(rawUri) {
	let main = rawUri.replace(/^ss:\/\//i, '').trim();
	let name = '';
	const hashIdx = main.indexOf('#');
	if (hashIdx !== -1) {
		name = safeDecodeURIComponent(main.slice(hashIdx + 1)).trim();
		main = main.slice(0, hashIdx);
	}

	let searchParams = null;
	const qIdx = main.indexOf('?');
	if (qIdx !== -1) {
		searchParams = new URLSearchParams(main.slice(qIdx + 1));
		main = main.slice(0, qIdx);
	}

	let cipher = '', password = '', server = '', port = 0;

	if (main.includes('@')) {
		const atIdx = main.lastIndexOf('@');
		let userInfo = main.slice(0, atIdx);
		const serverPort = main.slice(atIdx + 1);

		try {
			userInfo = base64Decode(userInfo);
		} catch {}

		const colonIdx = userInfo.indexOf(':');
		if (colonIdx !== -1) {
			cipher = userInfo.slice(0, colonIdx);
			password = userInfo.slice(colonIdx + 1);
		}

		const spMatch = serverPort.match(/^([^:]+):([0-9]+)$/);
		if (spMatch) {
			server = spMatch[1];
			port = parseInt(spMatch[2], 10);
		}
	} else {
		try {
			const decoded = base64Decode(main);
			const m = decoded.match(/^([^:]+):([^@]+)@([^:]+):([0-9]+)$/);
			if (m) {
				cipher = m[1];
				password = m[2];
				server = m[3];
				port = parseInt(m[4], 10);
			}
		} catch {}
	}

	if (!server || !port || !cipher) return null;
	if (!name) name = `${server}:${port}`;

	const proxy = {
		name,
		type: 'ss',
		server,
		port,
		cipher,
		password,
		rawUri
	};

	if (searchParams && searchParams.has('udp')) {
		proxy.udp = searchParams.get('udp') === '1' || searchParams.get('udp') === 'true';
	}

	if (searchParams && searchParams.has('plugin')) {
		const pluginStr = safeDecodeURIComponent(searchParams.get('plugin'));
		const parts = pluginStr.split(';');
		proxy.plugin = parts[0];
		proxy.pluginOpts = {};
		for (let i = 1; i < parts.length; i++) {
			const [k, v] = parts[i].split('=');
			if (k) proxy.pluginOpts[k] = v || true;
		}
	}

	return proxy;
}

export function parseShadowsocksR(rawUri) {
	try {
		const content = base64Decode(rawUri.replace(/^ssr:\/\//i, '').trim());
		const parts = content.split('/?');
		const main = parts[0].split(':');
		if (main.length < 6) return null;

		const server = main[0];
		const port = parseInt(main[1], 10);
		const protocol = main[2];
		const cipher = main[3];
		const obfs = main[4];
		const password = base64Decode(main[5]);

		let name = `${server}:${port}`;
		let obfsParam = '';
		let protoParam = '';

		if (parts[1]) {
			const params = new URLSearchParams(parts[1]);
			if (params.get('remarks')) {
				name = base64Decode(params.get('remarks')).trim();
			}
			if (params.get('obfsparam')) {
				obfsParam = base64Decode(params.get('obfsparam'));
			}
			if (params.get('protoparam')) {
				protoParam = base64Decode(params.get('protoparam'));
			}
		}

		return {
			name,
			type: 'ssr',
			server,
			port,
			cipher,
			password,
			protocol,
			protocolParam: protoParam,
			obfs,
			obfsParam,
			rawUri
		};
	} catch {
		return null;
	}
}

export function parseHysteria2(rawUri) {
	const clean = rawUri.replace(/^(hysteria2|hy2):\/\//i, '').trim();
	const match = clean.match(/^([^@]+)@([^:?#]+):([0-9, \-]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const password = match[1];
	const server = match[2];
	const portStr = match[3];
	const port = parseInt(portStr.split(',')[0].split('-')[0], 10);
	const searchParams = new URLSearchParams(match[4] ? match[4].slice(1) : '');
	const name = match[5] ? safeDecodeURIComponent(match[5].slice(1)).trim() : `${server}:${port}`;

	const proxy = {
		name,
		type: 'hysteria2',
		server,
		port,
		password,
		rawUri
	};

	if (searchParams.get('sni')) proxy.sni = searchParams.get('sni');
	if (searchParams.get('insecure') === '1') proxy.skipCertVerify = true;

	if (portStr.includes(',') || portStr.includes('-')) {
		proxy.ports = portStr;
	}

	if (searchParams.get('obfs')) {
		proxy.obfs = searchParams.get('obfs');
		proxy.obfsPassword = searchParams.get('obfs-password') || '';
	}

	return proxy;
}

export function parseTuic(rawUri) {
	const clean = rawUri.replace(/^tuic:\/\//i, '').trim();
	const match = clean.match(/^([^:]+):([^@]+)@([^:?#]+):([0-9]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const uuid = match[1];
	const password = match[2];
	const server = match[3];
	const port = parseInt(match[4], 10);
	const searchParams = new URLSearchParams(match[5] ? match[5].slice(1) : '');
	const name = match[6] ? safeDecodeURIComponent(match[6].slice(1)).trim() : `${server}:${port}`;

	const proxy = {
		name,
		type: 'tuic',
		server,
		port,
		uuid,
		password,
		rawUri
	};

	if (searchParams.get('sni')) proxy.sni = searchParams.get('sni');
	if (searchParams.get('allow_insecure') === '1' || searchParams.get('insecure') === '1') {
		proxy.skipCertVerify = true;
	}
	if (searchParams.get('congestion_controller')) {
		proxy.congestionController = searchParams.get('congestion_controller');
	}
	if (searchParams.get('udp_relay_mode')) {
		proxy.udpRelayMode = searchParams.get('udp_relay_mode');
	}

	return proxy;
}

export function parseNode(line, envScv = false) {
	if (!line) return null;
	const str = line.trim();
	if (!str || str.startsWith('#') || str.startsWith('//')) return null;

	const lower = str.toLowerCase();
	if (lower.startsWith('vless://')) return parseVless(str, envScv);
	if (lower.startsWith('vmess://')) return parseVmess(str, envScv);
	if (lower.startsWith('trojan://')) return parseTrojan(str, envScv);
	if (lower.startsWith('ss://')) return parseShadowsocks(str);
	if (lower.startsWith('ssr://')) return parseShadowsocksR(str);
	if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) return parseHysteria2(str);
	if (lower.startsWith('tuic://')) return parseTuic(str);

	return null;
}

export function nodeToUri(node) {
	if (node.rawUri) return node.rawUri;

	if (node.type === 'vmess') {
		const vmessObj = {
			v: "2",
			ps: node.name,
			add: node.server,
			port: String(node.port),
			id: node.uuid,
			aid: String(node.alterId || 0),
			scy: node.cipher || "auto",
			net: node.network || "tcp",
			type: "none",
			host: node.wsOpts?.headers?.Host || node.sni || "",
			path: node.wsOpts?.path || "",
			tls: node.tls ? "tls" : "",
			sni: node.sni || "",
			fp: node.clientFingerprint || ""
		};
		return `vmess://${base64Encode(JSON.stringify(vmessObj))}`;
	}

	if (node.type === 'vless') {
		const params = new URLSearchParams();
		params.set('encryption', 'none');
		if (node.tls) {
			params.set('security', node.realityOpts ? 'reality' : 'tls');
		}
		if (node.sni) params.set('sni', node.sni);
		if (node.clientFingerprint) params.set('fp', node.clientFingerprint);
		if (node.network) params.set('type', node.network);
		if (node.wsOpts?.path) params.set('path', node.wsOpts.path);
		if (node.wsOpts?.headers?.Host) params.set('host', node.wsOpts.headers.Host);
		if (node.grpcOpts?.serviceName) params.set('serviceName', node.grpcOpts.serviceName);
		if (node.realityOpts?.publicKey) params.set('pbk', node.realityOpts.publicKey);
		if (node.realityOpts?.shortId) params.set('sid', node.realityOpts.shortId);
		if (node.realityOpts?.spiderX) params.set('spx', node.realityOpts.spiderX);
		if (node.flow) params.set('flow', node.flow);

		return `vless://${node.uuid}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'trojan') {
		const params = new URLSearchParams();
		params.set('security', 'tls');
		if (node.sni) params.set('sni', node.sni);
		if (node.network) params.set('type', node.network);
		if (node.wsOpts?.path) params.set('path', node.wsOpts.path);
		if (node.wsOpts?.headers?.Host) params.set('host', node.wsOpts.headers.Host);
		if (node.skipCertVerify) params.set('allowInsecure', '1');
		return `trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'ss') {
		const userInfo = base64Encode(`${node.cipher}:${node.password}`);
		return `ss://${userInfo}@${node.server}:${node.port}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'hysteria2') {
		const params = new URLSearchParams();
		if (node.sni) params.set('sni', node.sni);
		if (node.skipCertVerify) params.set('insecure', '1');
		if (node.obfs) {
			params.set('obfs', node.obfs);
			if (node.obfsPassword) params.set('obfs-password', node.obfsPassword);
		}
		return `hysteria2://${encodeURIComponent(node.password)}@${node.server}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
	}

	return '';
}

export function processNodes(rawNodes) {
	const unique = [];
	const seenSignatures = new Set();
	const nameCounts = new Map();

	for (const node of rawNodes) {
		if (!node || !node.server || !node.port) continue;
		const sig = `${node.type}://${node.server}:${node.port}/${node.uuid || node.password || node.cipher || ''}`;
		if (seenSignatures.has(sig)) continue;
		seenSignatures.add(sig);

		let name = node.name || `${node.type}-${node.server}:${node.port}`;
		if (nameCounts.has(name)) {
			const count = nameCounts.get(name) + 1;
			nameCounts.set(name, count);
			name = `${name} ${count}`;
		} else {
			nameCounts.set(name, 1);
		}
		node.name = name;
		unique.push(node);
	}
	return unique;
}

// ==========================================
// 3. 远程 Clash YAML 订阅节点提取器
// ==========================================

export function parseClashProxies(yamlText) {
	if (!yamlText || !yamlText.includes('proxies:')) return [];
	const lines = yamlText.split(/\r?\n/);
	let inProxies = false;
	const proxies = [];
	let currentProxyLines = [];

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];

		if (/^proxies\s*:/i.test(line)) {
			inProxies = true;
			continue;
		}

		if (inProxies) {
			if (/^[a-zA-Z0-9_-]+\s*:/i.test(line) && !line.startsWith(' ') && !line.startsWith('\t')) {
				break;
			}

			if (/^\s*-\s+/.test(line)) {
				if (currentProxyLines.length > 0) {
					const p = parseSingleClashProxy(currentProxyLines);
					if (p) proxies.push(p);
					currentProxyLines = [];
				}
			}
			if (line.trim()) {
				currentProxyLines.push(line);
			}
		}
	}

	if (currentProxyLines.length > 0) {
		const p = parseSingleClashProxy(currentProxyLines);
		if (p) proxies.push(p);
	}

	return proxies;
}

function parseSingleClashProxy(lines) {
	if (!lines || lines.length === 0) return null;
	const firstLine = lines[0].replace(/^\s*-\s*/, '').trim();

	if (firstLine.startsWith('{') && firstLine.endsWith('}')) {
		return parseInlineClashProxy(firstLine);
	}

	const dict = {};
	let currentSubObjKey = null;
	let currentSubSubObjKey = null;

	for (const rawLine of lines) {
		const line = rawLine.replace(/^\s*-\s*/, '');
		const indent = rawLine.search(/\S/);
		const colonIdx = line.indexOf(':');
		if (colonIdx === -1) continue;

		const key = line.slice(0, colonIdx).trim();
		let val = line.slice(colonIdx + 1).trim();

		if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
			val = val.slice(1, -1);
		}

		if (indent <= 4 && !rawLine.startsWith('      ')) {
			if (val === '') {
				currentSubObjKey = key;
				dict[currentSubObjKey] = {};
			} else {
				currentSubObjKey = null;
				dict[key] = val;
			}
		} else if (currentSubObjKey) {
			if (val === '') {
				currentSubSubObjKey = key;
				dict[currentSubObjKey][currentSubSubObjKey] = {};
			} else if (currentSubSubObjKey && rawLine.startsWith('        ')) {
				dict[currentSubObjKey][currentSubSubObjKey][key] = val;
			} else {
				currentSubSubObjKey = null;
				dict[currentSubObjKey][key] = val;
			}
		}
	}

	return mapDictToProxy(dict);
}

function parseInlineClashProxy(line) {
	const inner = line.slice(1, -1);
	const dict = {};
	const regex = /([a-zA-Z0-9_-]+)\s*:\s*([^,}]+)/g;
	let match;
	while ((match = regex.exec(inner)) !== null) {
		const k = match[1].trim();
		let v = match[2].trim();
		if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
			v = v.slice(1, -1);
		}
		dict[k] = v;
	}
	return mapDictToProxy(dict);
}

function mapDictToProxy(dict) {
	if (!dict.server || !dict.type) return null;
	const type = dict.type.toLowerCase();
	const port = parseInt(dict.port, 10);
	const name = dict.name || `${dict.server}:${port}`;

	const proxy = {
		name,
		type,
		server: dict.server,
		port
	};

	if (dict.udp !== undefined) {
		proxy.udp = dict.udp === true || dict.udp === 'true';
	}
	if (dict.tls !== undefined) {
		proxy.tls = dict.tls === true || dict.tls === 'true';
	}
	if (dict.sni || dict.servername) {
		proxy.sni = dict.sni || dict.servername;
	}
	if (dict['skip-cert-verify'] !== undefined) {
		proxy.skipCertVerify = dict['skip-cert-verify'] === true || dict['skip-cert-verify'] === 'true';
	}
	if (dict['client-fingerprint']) {
		proxy.clientFingerprint = dict['client-fingerprint'];
	}
	if (dict.network) {
		proxy.network = dict.network;
	}

	if (type === 'vmess') {
		proxy.uuid = dict.uuid;
		if (dict.alterId !== undefined) proxy.alterId = parseInt(dict.alterId, 10);
		if (dict.cipher) proxy.cipher = dict.cipher;
	} else if (type === 'vless') {
		proxy.uuid = dict.uuid;
		if (dict.flow) proxy.flow = dict.flow;
		if (dict['reality-opts']) {
			proxy.realityOpts = {
				publicKey: dict['reality-opts']['public-key'] || dict['reality-opts'].publicKey,
				shortId: dict['reality-opts']['short-id'] || dict['reality-opts'].shortId,
				spiderX: dict['reality-opts']['spider-x'] || dict['reality-opts'].spiderX
			};
		}
	} else if (type === 'trojan') {
		proxy.password = dict.password;
	} else if (type === 'ss') {
		proxy.cipher = dict.cipher;
		proxy.password = dict.password;
		proxy.plugin = dict.plugin;
		proxy.pluginOpts = dict['plugin-opts'];
	} else if (type === 'hysteria2') {
		proxy.password = dict.password;
		proxy.obfs = dict.obfs;
		proxy.obfsPassword = dict['obfs-password'];
	} else if (type === 'tuic') {
		proxy.uuid = dict.uuid;
		proxy.password = dict.password;
		if (dict['congestion-controller']) proxy.congestionController = dict['congestion-controller'];
		if (dict['udp-relay-mode']) proxy.udpRelayMode = dict['udp-relay-mode'];
	}

	if (dict['ws-opts']) {
		proxy.wsOpts = {
			path: dict['ws-opts'].path,
			headers: dict['ws-opts'].headers
		};
	}
	if (dict['grpc-opts']) {
		proxy.grpcOpts = {
			serviceName: dict['grpc-opts']['grpc-service-name'] || dict['grpc-opts'].serviceName
		};
	}

	return proxy;
}

// ==========================================
// 4. SUBCONFIG (INI 规则文件) 解析与缓存
// ==========================================

export function parseSubConfig(iniText) {
	if (!iniText) return null;
	const lines = iniText.split(/\r?\n/);
	const rulesets = [];
	const customGroups = [];

	for (let line of lines) {
		line = line.trim();
		if (!line || line.startsWith('#') || line.startsWith(';')) continue;

		if (line.toLowerCase().startsWith('ruleset=')) {
			const val = line.slice(8).trim();
			const parts = val.split(',');
			if (parts.length >= 2) {
				const group = parts[0].trim();
				const url = parts[1].trim();
				const interval = parseInt(parts[2] || '86400', 10);
				rulesets.push({ group, url, interval });
			}
		} else if (line.toLowerCase().startsWith('custom_proxy_group=')) {
			const val = line.slice(19).trim();
			customGroups.push(val);
		}
	}

	return { rulesets, customGroups };
}

export async function loadSubConfig(url) {
	if (!url) return null;
	const now = Date.now();
	const cached = subConfigCache.get(url);
	if (cached && (now - cached.time < 600000)) {
		return cached.parsed;
	}

	try {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 3500);
		const res = await fetch(url, { signal: controller.signal });
		clearTimeout(timeout);
		if (res.ok) {
			const text = await res.text();
			const parsed = parseSubConfig(text);
			subConfigCache.set(url, { parsed, time: now });
			return parsed;
		}
	} catch (e) {
		console.error('Fetch subConfig failed for:', url, e);
	}

	return cached ? cached.parsed : null;
}

const REGION_PATTERNS = {
	'香港': /港|hk|hongkong|hong kong/i,
	'台湾': /台|tw|taiwan|新北|台北/i,
	'新加坡': /新|sg|singapore|狮城/i,
	'日本': /日|jp|japan|东京|大阪/i,
	'美国': /美|us|united states|america/i,
	'德国': /德|de|germany|法兰克福/i,
	'英国': /英|uk|gb|britain|united kingdom|伦敦/i,
	'韩国': /韩|kr|korea|首尔/i,
	'加拿大': /加|ca|canada/i,
	'澳大利亚': /澳|au|australia|悉尼/i,
	'法国': /法|fr|france|巴黎/i,
};

function matchNodesByRegion(nodes, groupName) {
	let pattern = null;
	for (const [reg, regExp] of Object.entries(REGION_PATTERNS)) {
		if (groupName.includes(reg)) {
			pattern = regExp;
			break;
		}
	}
	if (!pattern) return [];
	return nodes.filter(n => pattern.test(n.name));
}

// ==========================================
// 5. 原生 Clash / Mihomo YAML 生成器 (严格按填写的节点参数，不赋多余默认值)
// ==========================================

export function proxyToClashYaml(p) {
	const lines = [];
	lines.push(`  - name: ${JSON.stringify(p.name)}`);
	lines.push(`    type: ${p.type}`);
	lines.push(`    server: ${JSON.stringify(p.server)}`);
	lines.push(`    port: ${p.port}`);

	// udp 属性：仅在节点显式指定或默认支持时生成，支持按节点配置设置
	if (p.udp !== undefined) {
		lines.push(`    udp: ${p.udp}`);
	}

	if (p.type === 'vmess') {
		lines.push(`    uuid: ${JSON.stringify(p.uuid)}`);
		if (p.alterId !== undefined) lines.push(`    alterId: ${p.alterId}`);
		if (p.cipher) lines.push(`    cipher: ${p.cipher}`);
		if (p.tls) {
			lines.push(`    tls: true`);
			if (p.sni) lines.push(`    servername: ${JSON.stringify(p.sni)}`);
			if (p.clientFingerprint) lines.push(`    client-fingerprint: ${p.clientFingerprint}`);
		}
		if (p.skipCertVerify) lines.push(`    skip-cert-verify: true`);
		if (p.network && p.network !== 'tcp') {
			lines.push(`    network: ${p.network}`);
			if (p.network === 'ws' && p.wsOpts) {
				lines.push(`    ws-opts:`);
				if (p.wsOpts.path) lines.push(`      path: ${JSON.stringify(p.wsOpts.path)}`);
				if (p.wsOpts.headers && Object.keys(p.wsOpts.headers).length > 0) {
					lines.push(`      headers:`);
					for (const [k, v] of Object.entries(p.wsOpts.headers)) {
						if (v) lines.push(`        ${k}: ${JSON.stringify(v)}`);
					}
				}
			} else if (p.network === 'grpc' && p.grpcOpts && p.grpcOpts.serviceName) {
				lines.push(`    grpc-opts:`);
				lines.push(`      grpc-service-name: ${JSON.stringify(p.grpcOpts.serviceName)}`);
			}
		}
	} else if (p.type === 'vless') {
		lines.push(`    uuid: ${JSON.stringify(p.uuid)}`);
		if (p.tls) {
			lines.push(`    tls: true`);
			if (p.sni) lines.push(`    servername: ${JSON.stringify(p.sni)}`);
			if (p.clientFingerprint) lines.push(`    client-fingerprint: ${p.clientFingerprint}`);
			if (p.realityOpts && p.realityOpts.publicKey) {
				lines.push(`    reality-opts:`);
				lines.push(`      public-key: ${JSON.stringify(p.realityOpts.publicKey)}`);
				if (p.realityOpts.shortId) lines.push(`      short-id: ${JSON.stringify(p.realityOpts.shortId)}`);
				if (p.realityOpts.spiderX) lines.push(`      spider-x: ${JSON.stringify(p.realityOpts.spiderX)}`);
			}
		}
		if (p.flow) lines.push(`    flow: ${p.flow}`);
		if (p.skipCertVerify) lines.push(`    skip-cert-verify: true`);
		if (p.network && p.network !== 'tcp') {
			lines.push(`    network: ${p.network}`);
			if (p.network === 'ws' && p.wsOpts) {
				lines.push(`    ws-opts:`);
				if (p.wsOpts.path) lines.push(`      path: ${JSON.stringify(p.wsOpts.path)}`);
				if (p.wsOpts.headers && Object.keys(p.wsOpts.headers).length > 0) {
					lines.push(`      headers:`);
					for (const [k, v] of Object.entries(p.wsOpts.headers)) {
						if (v) lines.push(`        ${k}: ${JSON.stringify(v)}`);
					}
				}
			} else if (p.network === 'grpc' && p.grpcOpts && p.grpcOpts.serviceName) {
				lines.push(`    grpc-opts:`);
				lines.push(`      grpc-service-name: ${JSON.stringify(p.grpcOpts.serviceName)}`);
			}
		}
	} else if (p.type === 'trojan') {
		lines.push(`    password: ${JSON.stringify(p.password)}`);
		if (p.sni) lines.push(`    sni: ${JSON.stringify(p.sni)}`);
		if (p.clientFingerprint) lines.push(`    client-fingerprint: ${p.clientFingerprint}`);
		if (p.skipCertVerify) lines.push(`    skip-cert-verify: true`);
		if (p.network && p.network !== 'tcp') {
			lines.push(`    network: ${p.network}`);
			if (p.network === 'ws' && p.wsOpts) {
				lines.push(`    ws-opts:`);
				if (p.wsOpts.path) lines.push(`      path: ${JSON.stringify(p.wsOpts.path)}`);
				if (p.wsOpts.headers && Object.keys(p.wsOpts.headers).length > 0) {
					lines.push(`      headers:`);
					for (const [k, v] of Object.entries(p.wsOpts.headers)) {
						if (v) lines.push(`        ${k}: ${JSON.stringify(v)}`);
					}
				}
			} else if (p.network === 'grpc' && p.grpcOpts && p.grpcOpts.serviceName) {
				lines.push(`    grpc-opts:`);
				lines.push(`      grpc-service-name: ${JSON.stringify(p.grpcOpts.serviceName)}`);
			}
		}
	} else if (p.type === 'ss') {
		lines.push(`    cipher: ${p.cipher}`);
		lines.push(`    password: ${JSON.stringify(p.password)}`);
		if (p.plugin) {
			lines.push(`    plugin: ${p.plugin}`);
			if (p.pluginOpts && Object.keys(p.pluginOpts).length > 0) {
				lines.push(`    plugin-opts:`);
				for (const [k, v] of Object.entries(p.pluginOpts)) {
					lines.push(`      ${k}: ${JSON.stringify(v)}`);
				}
			}
		}
	} else if (p.type === 'ssr') {
		lines.push(`    cipher: ${p.cipher}`);
		lines.push(`    password: ${JSON.stringify(p.password)}`);
		lines.push(`    protocol: ${p.protocol}`);
		if (p.protocolParam) lines.push(`    protocol-param: ${JSON.stringify(p.protocolParam)}`);
		lines.push(`    obfs: ${p.obfs}`);
		if (p.obfsParam) lines.push(`    obfs-param: ${JSON.stringify(p.obfsParam)}`);
	} else if (p.type === 'hysteria2') {
		lines.push(`    password: ${JSON.stringify(p.password)}`);
		if (p.sni) lines.push(`    sni: ${JSON.stringify(p.sni)}`);
		if (p.skipCertVerify) lines.push(`    skip-cert-verify: true`);
		if (p.ports) lines.push(`    ports: ${JSON.stringify(p.ports)}`);
		if (p.obfs) {
			lines.push(`    obfs: ${p.obfs}`);
			if (p.obfsPassword) lines.push(`    obfs-password: ${JSON.stringify(p.obfsPassword)}`);
		}
	} else if (p.type === 'tuic') {
		lines.push(`    uuid: ${JSON.stringify(p.uuid)}`);
		lines.push(`    password: ${JSON.stringify(p.password)}`);
		if (p.sni) lines.push(`    sni: ${JSON.stringify(p.sni)}`);
		if (p.skipCertVerify) lines.push(`    skip-cert-verify: true`);
		if (p.congestionController) lines.push(`    congestion-controller: ${p.congestionController}`);
		if (p.udpRelayMode) lines.push(`    udp-relay-mode: ${p.udpRelayMode}`);
	}

	return lines.join('\n');
}

export function generateClashConfig(nodes, subName = 'CF-Workers-SUB', subConfigParsed = null) {
	const proxyNames = nodes.map(n => n.name);

	let yaml = `# ${subName} Clash / Mihomo Configuration
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: :9090

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query

proxies:
`;

	if (nodes.length === 0) {
		yaml += `  # 暂无可用节点\n`;
	} else {
		yaml += nodes.map(proxyToClashYaml).join('\n') + '\n';
	}

	// 规则集解析
	const rulesets = subConfigParsed?.rulesets || [];
	const neededGroups = new Set();
	for (const r of rulesets) {
		if (r.group) neededGroups.add(r.group);
	}

	// 构建策略组
	yaml += `\nproxy-groups:\n`;

	// 1. 主策略组 (节点选择)
	const regionGroups = [];
	for (const g of neededGroups) {
		if (g !== '节点选择' && g !== '全球直连' && g !== '全球拦截' && g !== '应用净化' && g !== 'DIRECT' && g !== 'REJECT') {
			regionGroups.push(g);
		}
	}

	const mainSelectProxies = ["♻️ 自动选择", "🔯 故障转移", ...regionGroups, "DIRECT", ...proxyNames];
	yaml += `  - name: "节点选择"
    type: select
    proxies:
${mainSelectProxies.map(p => `      - ${JSON.stringify(p)}`).join('\n')}

  - name: "♻️ 自动选择"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
${proxyNames.length > 0 ? proxyNames.map(name => `      - ${JSON.stringify(name)}`).join('\n') : '      - DIRECT'}

  - name: "🔯 故障转移"
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
${proxyNames.length > 0 ? proxyNames.map(name => `      - ${JSON.stringify(name)}`).join('\n') : '      - DIRECT'}
`;

	// 2. 地区与特定策略组
	for (const g of regionGroups) {
		const matchedNodes = matchNodesByRegion(nodes, g);
		const groupProxies = matchedNodes.length > 0
			? [...matchedNodes.map(n => n.name), "节点选择", "DIRECT"]
			: ["节点选择", "DIRECT", ...proxyNames];

		yaml += `
  - name: ${JSON.stringify(g)}
    type: select
    proxies:
${groupProxies.map(p => `      - ${JSON.stringify(p)}`).join('\n')}
`;
	}

	// 3. 直连与拦截组
	if (neededGroups.has('全球直连')) {
		yaml += `
  - name: "全球直连"
    type: select
    proxies:
      - DIRECT
      - "节点选择"
`;
	}

	if (neededGroups.has('全球拦截')) {
		yaml += `
  - name: "全球拦截"
    type: select
    proxies:
      - REJECT
      - DIRECT
`;
	}

	if (neededGroups.has('应用净化')) {
		yaml += `
  - name: "应用净化"
    type: select
    proxies:
      - REJECT
      - DIRECT
`;
	}

	// 4. 漏网之鱼
	yaml += `
  - name: "🐟 漏网之鱼"
    type: select
    proxies:
      - "节点选择"
      - DIRECT
`;

	// 5. Rule-providers (根据 SUBCONFIG 规则集生成)
	if (rulesets.length > 0) {
		yaml += `\nrule-providers:\n`;
		rulesets.forEach((r, idx) => {
			yaml += `  ruleset_${idx}:
    type: http
    behavior: classical
    url: ${JSON.stringify(r.url)}
    path: ./ruleset/ruleset_${idx}.yaml
    interval: ${r.interval || 86400}
`;
		});
	}

	// 6. 分流规则
	yaml += `\nrules:\n`;
	if (rulesets.length > 0) {
		rulesets.forEach((r, idx) => {
			yaml += `  - RULE-SET,ruleset_${idx},${r.group}\n`;
		});
	}
	yaml += `  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT,no-resolve
  - MATCH,🐟 漏网之鱼
`;

	return yaml;
}

// ==========================================
// 6. 原生 Base64 生成器
// ==========================================

export function generateBase64Config(nodes) {
	const uris = nodes.map(n => nodeToUri(n)).filter(Boolean);
	return base64Encode(uris.join('\n'));
}

// ==========================================
// 7. 辅助功能函数与网络请求
// ==========================================

async function parseTextLines(text) {
	if (!text) return [];
	const clean = text.replace(/[\r]+/g, '\n').replace(/[	"'|]+/g, '\n');
	return clean.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith('//'));
}

async function fetchSubscriptions(subUrls) {
	if (!subUrls || subUrls.length === 0) return [];
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 4000);

	try {
		const promises = subUrls.map(async (url) => {
			try {
				const res = await fetch(url, {
					headers: {
						'User-Agent': 'ClashforWindows/0.20.39 v2rayN/6.45'
					},
					signal: controller.signal
				});
				if (!res.ok) return '';
				return await res.text();
			} catch (e) {
				console.error(`Fetch sub error: ${url}`, e);
				return '';
			}
		});
		return await Promise.all(promises);
	} finally {
		clearTimeout(timeout);
	}
}

function md5(string) {
	function rotateLeft(lValue, iShiftBits) {
		return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
	}
	function addUnsigned(lX, lY) {
		let lX4 = lX & 0x40000000;
		let lY4 = lY & 0x40000000;
		let lX8 = lX & 0x80000000;
		let lY8 = lY & 0x80000000;
		let lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
		if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
		if (lX4 | lY4) {
			if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
			else return lResult ^ 0x40000000 ^ lX8 ^ lY8;
		} else return lResult ^ lX8 ^ lY8;
	}
	function F(x, y, z) { return (x & y) | ((~x) & z); }
	function G(x, y, z) { return (x & z) | (y & (~z)); }
	function H(x, y, z) { return x ^ y ^ z; }
	function I(x, y, z) { return y ^ (x | (~z)); }
	function FF(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function GG(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function HH(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function II(a, b, c, d, x, s, ac) {
		a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
		return addUnsigned(rotateLeft(a, s), b);
	}
	function convertToWordArray(string) {
		let lWordCount;
		let lMessageLength = string.length;
		let lNumberOfWords_temp1 = lMessageLength + 8;
		let lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
		let lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
		let lWordArray = Array(lNumberOfWords - 1);
		let lBytePosition = 0;
		let lByteCount = 0;
		while (lByteCount < lMessageLength) {
			lWordCount = (lByteCount - (lByteCount % 4)) / 4;
			lBytePosition = (lByteCount % 4) * 8;
			lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
			lByteCount++;
		}
		lWordCount = (lByteCount - (lByteCount % 4)) / 4;
		lBytePosition = (lByteCount % 4) * 8;
		lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
		lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
		lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
		return lWordArray;
	}
	function wordToHex(lValue) {
		let WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
		for (lCount = 0; lCount <= 3; lCount++) {
			lByte = (lValue >>> (lCount * 8)) & 255;
			WordToHexValue_temp = "0" + lByte.toString(16);
			WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
		}
		return WordToHexValue;
	}

	let x = convertToWordArray(unescape(encodeURIComponent(string)));
	let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
	const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
	const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
	const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
	const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

	for (let k = 0; k < x.length; k += 16) {
		let AA = a, BB = b, CC = c, DD = d;
		a = FF(a, b, c, d, x[k + 0], S11, 0xd76aa478);
		d = FF(d, a, b, c, x[k + 1], S12, 0xe8c7b756);
		c = FF(c, d, a, b, x[k + 2], S13, 0x242070db);
		b = FF(b, c, d, a, x[k + 3], S14, 0xc1bdceee);
		a = FF(a, b, c, d, x[k + 4], S11, 0xf57c0faf);
		d = FF(d, a, b, c, x[k + 5], S12, 0x4787c62a);
		c = FF(c, d, a, b, x[k + 6], S13, 0xa8304613);
		b = FF(b, c, d, a, x[k + 7], S14, 0xfd469501);
		a = FF(a, b, c, d, x[k + 8], S11, 0x698098d8);
		d = FF(d, a, b, c, x[k + 9], S12, 0x8b44f7af);
		c = FF(c, d, a, b, x[k + 10], S13, 0xffff5bb1);
		b = FF(b, c, d, a, x[k + 11], S14, 0x895cd7be);
		a = FF(a, b, c, d, x[k + 12], S11, 0x6b901122);
		d = FF(d, a, b, c, x[k + 13], S12, 0xfd987193);
		c = FF(c, d, a, b, x[k + 14], S13, 0xa679438e);
		b = FF(b, c, d, a, x[k + 15], S14, 0x49b40821);

		a = GG(a, b, c, d, x[k + 1], S21, 0xf61e2562);
		d = GG(d, a, b, c, x[k + 6], S22, 0xc040b340);
		c = GG(c, d, a, b, x[k + 11], S23, 0x265e5a51);
		b = GG(b, c, d, a, x[k + 0], S24, 0xe9b6c7aa);
		a = GG(a, b, c, d, x[k + 5], S21, 0xd62f105d);
		d = GG(d, a, b, c, x[k + 10], S22, 0x02441453);
		c = GG(c, d, a, b, x[k + 15], S23, 0xd8a1e681);
		b = GG(b, c, d, a, x[k + 4], S24, 0xe7d3fbc8);
		a = GG(a, b, c, d, x[k + 9], S21, 0x21e1cde6);
		d = GG(d, a, b, c, x[k + 14], S22, 0xc33707d6);
		c = GG(c, d, a, b, x[k + 3], S23, 0xf4d50d87);
		b = GG(b, c, d, a, x[k + 8], S24, 0x455a14ed);
		a = GG(a, b, c, d, x[k + 13], S21, 0xa9e3e905);
		d = GG(d, a, b, c, x[k + 2], S22, 0xfcefa3f8);
		c = GG(c, d, a, b, x[k + 7], S23, 0x676f02d9);
		b = GG(b, c, d, a, x[k + 12], S24, 0x8d2a4c8a);

		a = HH(a, b, c, d, x[k + 5], S31, 0xfffa3942);
		d = HH(d, a, b, c, x[k + 8], S32, 0x8771f681);
		c = HH(c, d, a, b, x[k + 11], S33, 0x6d9d6122);
		b = HH(b, c, d, a, x[k + 14], S34, 0xfde5380c);
		a = HH(a, b, c, d, x[k + 1], S31, 0xa4beea44);
		d = HH(d, a, b, c, x[k + 4], S32, 0x4bdecfa9);
		c = HH(c, d, a, b, x[k + 7], S33, 0xf6bb4b60);
		b = HH(b, c, d, a, x[k + 10], S34, 0xbebfbc70);
		a = HH(a, b, c, d, x[k + 13], S31, 0x289b7ec6);
		d = HH(d, a, b, c, x[k + 0], S32, 0xeaa127fa);
		c = HH(c, d, a, b, x[k + 3], S33, 0xd4ef3085);
		b = HH(b, c, d, a, x[k + 6], S34, 0x04881d05);
		a = HH(a, b, c, d, x[k + 9], S31, 0xd9d4d039);
		d = HH(d, a, b, c, x[k + 12], S32, 0xe6db99e5);
		c = HH(c, d, a, b, x[k + 15], S33, 0x1fa27cf8);
		b = HH(b, c, d, a, x[k + 2], S34, 0xc4ac5665);

		a = II(a, b, c, d, x[k + 0], S41, 0xf4292244);
		d = II(d, a, b, c, x[k + 7], S42, 0x432aff97);
		c = II(c, d, a, b, x[k + 14], S43, 0xab9423a7);
		b = II(b, c, d, a, x[k + 5], S44, 0xfc93a039);
		a = II(a, b, c, d, x[k + 12], S41, 0x655b59c3);
		d = II(d, a, b, c, x[k + 3], S42, 0x8f0ccc92);
		c = II(c, d, a, b, x[k + 10], S43, 0xffeff47d);
		b = II(b, c, d, a, x[k + 1], S44, 0x85845dd1);
		a = II(a, b, c, d, x[k + 8], S41, 0x6fa87e4f);
		d = II(d, a, b, c, x[k + 15], S42, 0xfe2ce6e0);
		c = II(c, d, a, b, x[k + 6], S43, 0xa3014314);
		b = II(b, c, d, a, x[k + 13], S44, 0x4e0811a1);
		a = II(a, b, c, d, x[k + 4], S41, 0xf7537e82);
		d = II(d, a, b, c, x[k + 11], S42, 0xbd3af235);
		c = II(c, d, a, b, x[k + 2], S43, 0x2ad7d2bb);
		b = II(b, c, d, a, x[k + 9], S44, 0xeb86d391);

		a = addUnsigned(a, AA);
		b = addUnsigned(b, BB);
		c = addUnsigned(c, CC);
		d = addUnsigned(d, DD);
	}
	return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

export async function MD5MD5(text) {
	try {
		const encoder = new TextEncoder();
		const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
		const firstPassArray = Array.from(new Uint8Array(firstPass));
		const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
		const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
		return Array.from(new Uint8Array(secondPass)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
	} catch {
		const firstHex = md5(text);
		return md5(firstHex.slice(7, 27));
	}
}

async function sendMessage(type, ip, add_data = "") {
	if (BotToken !== '' && ChatID !== '') {
		let msg = "";
		try {
			const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
			if (response.ok) {
				const ipInfo = await response.json();
				msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
			} else {
				msg = `${type}\nIP: ${ip}\n${add_data}`;
			}
		} catch {
			msg = `${type}\nIP: ${ip}\n${add_data}`;
		}

		const tgUrl = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
		return fetch(tgUrl, {
			headers: { 'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72' }
		}).catch(() => {});
	}
}

async function proxyURL(targetProxyURL, url) {
	const urls = await parseTextLines(targetProxyURL);
	const fullURL = urls[Math.floor(Math.random() * urls.length)];
	let parsedURL = new URL(fullURL);
	let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
	let URLHostname = parsedURL.hostname;
	let URLPathname = parsedURL.pathname.replace(/\/$/, '') + url.pathname;
	let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${parsedURL.search}`;

	const response = await fetch(newURL);
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});
}

async function nginx() {
	return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>`;
}

async function 迁移地址列表(env, txt = 'LINK.txt') {
	try {
		const 旧数据 = await env.KV.get(`/${txt}`);
		const 新数据 = await env.KV.get(txt);
		if (旧数据 && !新数据) {
			await env.KV.put(txt, 旧数据);
			await env.KV.delete(`/${txt}`);
			return true;
		}
	} catch {}
	return false;
}

// ==========================================
// 8. KV 网页管理界面
// ==========================================

async function renderKVPage(request, env, txt = 'LINK.txt', guest, currentSubConfig) {
	const url = new URL(request.url);

	if (request.method === "POST") {
		if (!env.KV) return new Response("未绑定 KV 命名空间", { status: 400 });
		try {
			const body = await request.text();
			if (body.startsWith('{')) {
				try {
					const data = JSON.parse(body);
					if (data.link !== undefined) await env.KV.put(txt, data.link);
					if (data.subConfig !== undefined) await env.KV.put('CONFIG.txt', data.subConfig.trim());
					return new Response("保存成功");
				} catch {}
			}
			await env.KV.put(txt, body);
			return new Response("保存成功");
		} catch (error) {
			return new Response("保存失败: " + error.message, { status: 500 });
		}
	}

	let content = '';
	if (env.KV) {
		try {
			content = await env.KV.get(txt) || '';
		} catch (error) {
			content = '读取数据时发生错误: ' + error.message;
		}
	}

	const html = `<!DOCTYPE html>
<html>
<head>
	<title>${FileName} 订阅配置</title>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<style>
		body { margin: 0; padding: 15px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 13px; background: #f6f8fa; color: #24292f; }
		.container { max-width: 860px; margin: 0 auto; background: #fff; padding: 22px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
		h2 { margin-top: 0; font-size: 18px; border-bottom: 2px solid #2ea44f; padding-bottom: 8px; display: flex; align-items: center; justify-content: space-between; }
		.tag { padding: 3px 8px; background: #dafbe1; color: #1a7f37; border-radius: 12px; font-size: 11px; font-weight: normal; }
		.sub-links { background: #f6f8fa; padding: 14px; border-radius: 6px; margin-bottom: 18px; border: 1px solid #d0d7de; }
		.sub-item { margin: 10px 0; }
		.sub-item a { color: #0969da; text-decoration: none; word-break: break-all; font-family: monospace; }
		.sub-item a:hover { text-decoration: underline; }
		.qrcode-box { margin: 10px 0; }
		.form-section { margin-top: 15px; }
		.form-label { font-weight: bold; margin-bottom: 6px; display: block; }
		.form-input { width: 100%; padding: 8px 10px; box-sizing: border-box; border: 1px solid #d0d7de; border-radius: 6px; font-size: 13px; font-family: monospace; }
		.preset-select { margin-top: 6px; width: 100%; padding: 6px 10px; box-sizing: border-box; border: 1px solid #d0d7de; border-radius: 6px; font-size: 12px; background: #fff; }
		.editor { width: 100%; height: 260px; padding: 10px; box-sizing: border-box; border: 1px solid #d0d7de; border-radius: 6px; font-size: 13px; font-family: monospace; line-height: 1.45; resize: vertical; }
		.save-btn { padding: 9px 22px; background: #2da44e; color: #fff; border: 1px solid rgba(27,31,36,0.15); border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; }
		.save-btn:hover { background: #2c974b; }
		.save-status { margin-left: 12px; font-size: 13px; }
		.tips { font-size: 12px; color: #57606a; margin-top: 4px; }
	</style>
	<script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
</head>
<body>
<div class="container">
	<h2>
		<span>${FileName} 汇聚订阅管理</span>
		<span class="tag">🚀 原生内置转换引擎</span>
	</h2>
	
	<div class="sub-links">
		<strong>🔗 快捷订阅地址（点击复制并生成二维码）：</strong>
		<div class="sub-item">
			<strong>自适应订阅 (自动识别客户端)：</strong><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${mytoken}','qrcode_0')">https://${url.hostname}/${mytoken}</a>
			<div id="qrcode_0" class="qrcode-box"></div>
		</div>
		<div class="sub-item">
			<strong>Clash / Mihomo 格式订阅：</strong><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${mytoken}?clash','qrcode_1')">https://${url.hostname}/${mytoken}?clash</a>
			<div id="qrcode_1" class="qrcode-box"></div>
		</div>
		<div class="sub-item">
			<strong>Base64 格式订阅 (v2rayN/NG/Shadowrocket/NekoBox)：</strong><br>
			<a href="javascript:void(0)" onclick="copyToClipboard('https://${url.hostname}/${mytoken}?b64','qrcode_2')">https://${url.hostname}/${mytoken}?b64</a>
			<div id="qrcode_2" class="qrcode-box"></div>
		</div>
	</div>

	<div class="form-section">
		<label class="form-label" for="subConfigInput">⚙️ Clash 规则转换配置文件 (SUBCONFIG)：</label>
		<input type="text" id="subConfigInput" class="form-input" value="${currentSubConfig}" placeholder="输入远程 .ini 规则配置链接" />
		<select class="preset-select" onchange="applyPreset(this.value)">
			<option value="">-- 选择常用预设规则集 (或在上方输入自定义链接) --</option>
			<option value="https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/my.ini">🌟 自定义配置 (my.ini)</option>
			<option value="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini">ACL4SSR 极简分流 (Mini)</option>
			<option value="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini">ACL4SSR 多国家分组 (MultiCountry)</option>
			<option value="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini">ACL4SSR 广告净化强化版 (AdblockPlus)</option>
		</select>
		<div class="tips">提示：生成 Clash 配置时，将自动解析此 .ini 中的 ruleset 规则集并建立对应策略组与规则。</div>
	</div>

	<div class="form-section" style="margin-top: 20px;">
		<label class="form-label" for="content">📝 节点与订阅聚合配置 (LINK.txt)：</label>
		<div class="tips" style="margin-bottom: 6px;">每行填写一个自建节点链接（vless://, vmess://, trojan://, ss://, hy2://）或机场订阅链接（Base64 / Clash YAML / 明文）：</div>
		<textarea class="editor" id="content">${content}</textarea>
		<div style="margin-top: 12px; display: flex; align-items: center;">
			<button class="save-btn" onclick="saveContent(this)">保存所有配置</button>
			<span class="save-status" id="saveStatus"></span>
		</div>
	</div>
</div>

<script>
function applyPreset(val) {
	if (val) {
		document.getElementById('subConfigInput').value = val;
	}
}

function copyToClipboard(text, qrcode) {
	navigator.clipboard.writeText(text).then(() => {
		alert('已复制到剪贴板');
	}).catch(err => {
		console.error('复制失败:', err);
	});
	const qrcodeDiv = document.getElementById(qrcode);
	qrcodeDiv.innerHTML = '';
	new QRCode(qrcodeDiv, {
		text: text,
		width: 180,
		height: 180,
		colorDark: "#000000",
		colorLight: "#ffffff",
		correctLevel: QRCode.CorrectLevel.Q
	});
}

function saveContent(button) {
	const textarea = document.getElementById('content');
	const subConfigInput = document.getElementById('subConfigInput');
	const statusElem = document.getElementById('saveStatus');
	button.disabled = true;
	button.textContent = '保存中...';
	statusElem.textContent = '';

	const payload = {
		link: textarea.value,
		subConfig: subConfigInput.value.trim()
	};

	fetch(window.location.href, {
		method: 'POST',
		body: JSON.stringify(payload),
		headers: { 'Content-Type': 'application/json' }
	}).then(res => {
		if (res.ok) {
			statusElem.textContent = '✅ 保存成功 ' + new Date().toLocaleTimeString();
			statusElem.style.color = '#1a7f37';
		} else {
			throw new Error('HTTP ' + res.status);
		}
	}).catch(err => {
		statusElem.textContent = '❌ 保存失败: ' + err.message;
		statusElem.style.color = '#cf222e';
	}).finally(() => {
		button.disabled = false;
		button.textContent = '保存所有配置';
	});
}
</script>
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html;charset=utf-8" }
	});
}