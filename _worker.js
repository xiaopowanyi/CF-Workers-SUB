/**
 * 自建汇聚订阅 CF-Workers-SUB
 * 原生内置转换引擎（无需外部后端转换服务，安全不泄露节点，无转换超时）
 * 支持 Clash (Mihomo) 与 Base64 订阅生成
 * 节点信息严格按照填写的节点配置生成，不强制添加默认值，由客户端自行处理默认策略
 * 支持通过 环境变量 (SUBCONFIG) 或 前端页面选择/填写保存自定义 .ini 规则配置链接
 */

// 默认配置常量
const DEFAULT_TOKEN = 'auto';
const DEFAULT_FILENAME = 'CF-Workers-SUB';
const DEFAULT_SUB_UPDATE_TIME = 6;
const DEFAULT_TOTAL = 99; // TB
const DEFAULT_TIMESTAMP = 4102329600000; // 2099-12-31

// 默认自建节点与订阅链接常量
const DEFAULT_MAIN_DATA = `
https://cfxr.eu.org/getSub
`;

// 默认订阅规则配置文件常量
const DEFAULT_SUBCONFIG = "https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/my.ini";

// 默认 Clash 覆写配置文件常量
const DEFAULT_OVERRIDE = "https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/override.yaml";

// 缓存容器与容量上限保护机制 (LRU/FIFO 淘汰，防止内存溢出 OOM)
const MAX_CACHE_ENTRIES = 150;
const subConfigCache = new Map();
const overrideConfigCache = new Map();
const ruleMemoryCache = new Map();

function setCacheWithLimit(map, key, value, maxItems = MAX_CACHE_ENTRIES) {
	if (map.size >= maxItems) {
		const oldestKey = map.keys().next().value;
		if (oldestKey !== undefined) {
			map.delete(oldestKey);
		}
	}
	map.set(key, value);
}

export default {
	async fetch(request, env) {
		const userAgentHeader = request.headers.get('User-Agent') || '';
		const userAgent = userAgentHeader.toLowerCase();
		const url = new URL(request.url);
		const token = url.searchParams.get('token');

		const mytoken = env.TOKEN || DEFAULT_TOKEN;
		const BotToken = env.TGTOKEN || '';
		const ChatID = env.TGID || '';
		const TG = env.TG || 0;
		const subConfig = env.SUBCONFIG || DEFAULT_SUBCONFIG;
		const FileName = env.SUBNAME || DEFAULT_FILENAME;
		const SUBUpdateTime = env.SUBUPTIME || DEFAULT_SUB_UPDATE_TIME;
		const envScv = env.SCV === 'true';

		const currentDate = new Date();
		currentDate.setHours(0, 0, 0, 0);
		const timeTemp = Math.ceil(currentDate.getTime() / 1000);
		const fakeToken = await MD5MD5(`${mytoken}${timeTemp}`);
		let guestToken = env.GUESTTOKEN || env.GUEST || '';
		if (!guestToken) guestToken = await MD5MD5(mytoken);
		const 访客订阅 = guestToken;

		// 路径解析与鉴权检查
		const pathSegments = url.pathname.split('/').filter(Boolean);
		const isRuleReq = pathSegments.includes('rule');

		let reqToken = token;
		if (!reqToken && pathSegments.length > 0) {
			if (pathSegments[0] !== 'sub' && pathSegments[0] !== 'rule') {
				reqToken = pathSegments[0];
			}
		}

		const isAuthorized = [mytoken, fakeToken, 访客订阅].includes(token) ||
			[mytoken, fakeToken, 访客订阅].includes(reqToken) ||
			url.pathname === ("/" + mytoken) ||
			url.pathname.includes("/" + mytoken + "?") ||
			(url.pathname === "/sub" && [mytoken, fakeToken, 访客订阅].includes(token));

		if (!isAuthorized) {
			if (TG == 1 && url.pathname !== "/" && url.pathname !== "/favicon.ico") {
				await sendMessage(`#异常访问 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`, BotToken, ChatID);
			}
			if (env.URL302) return Response.redirect(env.URL302, 302);
			else if (env.URL) return await proxyURL(env.URL, url);
			else return new Response(await nginx(), {
				status: 200,
				headers: { 'Content-Type': 'text/html; charset=UTF-8' }
			});
		}

		// 处理规则集中继请求 (/rule 或 /*/rule)
		if (isRuleReq) {
			const targetUrl = url.searchParams.get('url');
			if (!targetUrl) {
				return new Response('缺少 url 参数', { status: 400 });
			}
			return await handleRuleProxyRequest(request, targetUrl, env);
		}

		// 解析当前生效的 SUBCONFIG (优先级: URL参数 ?config= > KV 中保存的 CONFIG.txt > 环境变量 SUBCONFIG > 默认 subConfig)
		let currentSubConfig = url.searchParams.get('config');
		if (!currentSubConfig && env.KV) {
			currentSubConfig = await env.KV.get('CONFIG.txt');
		}
		if (!currentSubConfig) {
			currentSubConfig = env.SUBCONFIG || subConfig;
		}

		// 解析当前生效的 GHPROXY (优先级: URL参数 ?ghproxy= > KV 中保存的 GHPROXY.txt > 环境变量 GH_PROXY/GHPROXY > 默认 'worker')
		let currentGhProxy = url.searchParams.get('ghproxy');
		if (!currentGhProxy && env.KV) {
			currentGhProxy = await env.KV.get('GHPROXY.txt');
		}
		if (!currentGhProxy) {
			currentGhProxy = env.GH_PROXY || env.GHPROXY || 'worker';
		}

		// 解析当前生效的 OVERRIDE (优先级: URL参数 ?override= / ?ov= > KV 中保存的 OVERRIDE.txt > 环境变量 OVERRIDE > 默认 defaultOverride)
		let currentOverride = url.searchParams.get('override') ?? url.searchParams.get('ov');
		if (currentOverride === null && env.KV) {
			currentOverride = await env.KV.get('OVERRIDE.txt');
		}
		if (currentOverride === null || currentOverride === undefined) {
			currentOverride = (env.OVERRIDE !== undefined) ? env.OVERRIDE : DEFAULT_OVERRIDE;
		}

		// 独立的局部 MainData 变量，彻底防止并发复用时内存泄漏和状态累加
		let currentMainData = DEFAULT_MAIN_DATA;

		// KV 管理页面与数据加载
		if (env.KV) {
			await 迁移地址列表(env, 'LINK.txt');
			if ((request.method === "POST" || userAgent.includes('mozilla')) && !url.search && url.pathname !== '/sub') {
				await sendMessage(`#编辑订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`, BotToken, ChatID);
				return await renderKVPage(request, env, 'LINK.txt', 访客订阅, currentSubConfig, currentGhProxy, currentOverride, mytoken, FileName);
			} else {
				currentMainData = await env.KV.get('LINK.txt') || currentMainData;
			}
		} else {
			currentMainData = env.LINK || currentMainData;
			if (env.LINKSUB) {
				const subs = await parseTextLines(env.LINKSUB);
				currentMainData = currentMainData + '\n' + subs.join('\n');
			}
		}

		// 记录访问日志
		await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`, BotToken, ChatID);

		// 收集自建节点与远程订阅链接
		const allLines = await parseTextLines(currentMainData);
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
			// 确定有效的订阅 Token 用于构建规则中继基础 URL
			const effectiveToken = (token && [mytoken, fakeToken, 访客订阅].includes(token))
				? token
				: (reqToken && [mytoken, fakeToken, 访客订阅].includes(reqToken) ? reqToken : mytoken);
			const origin = (url.origin && url.origin !== 'null') ? url.origin : `https://${url.host}`;
			const workerRuleBase = `${origin}/${effectiveToken}/rule`;

			// 根据当前选择或配置的 SUBCONFIG 解析规则与分组
			const subConfigParsed = await loadSubConfig(currentSubConfig, currentGhProxy);
			let clashYaml = generateClashConfig(allNodes, FileName, subConfigParsed, currentGhProxy, workerRuleBase);

			// 应用 Clash YAML 覆写配置 (OVERRIDE)
			const shouldApplyOverride = currentOverride &&
				currentOverride.trim() &&
				currentOverride.trim().toLowerCase() !== 'none' &&
				currentOverride.trim().toLowerCase() !== 'off' &&
				currentOverride.trim().toLowerCase() !== 'false';
			if (shouldApplyOverride) {
				try {
					const overrideYaml = await loadOverrideConfig(currentOverride, currentGhProxy);
					if (overrideYaml) {
						clashYaml = applyYamlOverride(clashYaml, overrideYaml);
					}
				} catch (err) {
					console.error('Failed to apply YAML override:', err);
				}
			}

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
	const match = rawUri.match(/^vless:\/\/([^@]+)@(\[[^\]]+\]|[^:?#]+):([0-9]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const uuid = match[1];
	let server = match[2];
	if (server.startsWith('[') && server.endsWith(']')) {
		server = server.slice(1, -1);
	}
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
		proxy.cipher = item.scy || 'auto';
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
	const match = rawUri.match(/^trojan:\/\/([^@]+)@(\[[^\]]+\]|[^:?#]+):([0-9]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const password = match[1];
	let server = match[2];
	if (server.startsWith('[') && server.endsWith(']')) {
		server = server.slice(1, -1);
	}
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

		const spMatch = serverPort.match(/^(\[[^\]]+\]|[^:?#]+):([0-9]+)$/);
		if (spMatch) {
			server = spMatch[1];
			if (server.startsWith('[') && server.endsWith(']')) {
				server = server.slice(1, -1);
			}
			port = parseInt(spMatch[2], 10);
		}
	} else {
		try {
			const decoded = base64Decode(main);
			const m = decoded.match(/^([^:]+):([^@]+)@(\[[^\]]+\]|[^:?#]+):([0-9]+)$/);
			if (m) {
				cipher = m[1];
				password = m[2];
				server = m[3];
				if (server.startsWith('[') && server.endsWith(']')) {
					server = server.slice(1, -1);
				}
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
		const mainMatch = parts[0].match(/^(\[[^\]]+\]|[^:]+):(\d+):([^:]+):([^:]+):([^:]+):([^/]+)$/);
		if (!mainMatch) return null;

		const server = mainMatch[1].startsWith('[') && mainMatch[1].endsWith(']')
			? mainMatch[1].slice(1, -1)
			: mainMatch[1];
		const port = parseInt(mainMatch[2], 10);
		const protocol = mainMatch[3];
		const cipher = mainMatch[4];
		const obfs = mainMatch[5];
		const password = base64Decode(mainMatch[6]);

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
	const match = clean.match(/^([^@]+)@(\[[^\]]+\]|[^:?#]+):([0-9, \-]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const password = match[1];
	let server = match[2];
	if (server.startsWith('[') && server.endsWith(']')) {
		server = server.slice(1, -1);
	}
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
	const match = clean.match(/^([^:]+):([^@]+)@(\[[^\]]+\]|[^:?#]+):([0-9]+)(\?[^#]*)?(#.*)?$/i);
	if (!match) return null;

	const uuid = match[1];
	const password = match[2];
	let server = match[3];
	if (server.startsWith('[') && server.endsWith(']')) {
		server = server.slice(1, -1);
	}
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

export function formatHostForUri(server) {
	if (!server) return '';
	if (server.includes(':') && !server.startsWith('[')) {
		return `[${server}]`;
	}
	return server;
}

export function nodeToUri(node) {
	if (node.rawUri) return node.rawUri;

	const host = formatHostForUri(node.server);

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

		return `vless://${node.uuid}@${host}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'trojan') {
		const params = new URLSearchParams();
		params.set('security', 'tls');
		if (node.sni) params.set('sni', node.sni);
		if (node.network) params.set('type', node.network);
		if (node.wsOpts?.path) params.set('path', node.wsOpts.path);
		if (node.wsOpts?.headers?.Host) params.set('host', node.wsOpts.headers.Host);
		if (node.skipCertVerify) params.set('allowInsecure', '1');
		return `trojan://${encodeURIComponent(node.password)}@${host}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'ss') {
		const userInfo = base64Encode(`${node.cipher}:${node.password}`);
		return `ss://${userInfo}@${host}:${node.port}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'ssr') {
		const passB64 = base64Encode(node.password || '');
		const mainStr = `${host}:${node.port}:${node.protocol || 'origin'}:${node.cipher || 'none'}:${node.obfs || 'plain'}:${passB64}`;
		const params = new URLSearchParams();
		if (node.name) params.set('remarks', base64Encode(node.name));
		if (node.obfsParam) params.set('obfsparam', base64Encode(node.obfsParam));
		if (node.protocolParam) params.set('protoparam', base64Encode(node.protocolParam));
		const full = `${mainStr}/?${params.toString()}`;
		return `ssr://${base64Encode(full)}`;
	}

	if (node.type === 'hysteria2') {
		const params = new URLSearchParams();
		if (node.sni) params.set('sni', node.sni);
		if (node.skipCertVerify) params.set('insecure', '1');
		if (node.obfs) {
			params.set('obfs', node.obfs);
			if (node.obfsPassword) params.set('obfs-password', node.obfsPassword);
		}
		return `hysteria2://${encodeURIComponent(node.password)}@${host}:${node.port}?${params.toString()}#${encodeURIComponent(node.name)}`;
	}

	if (node.type === 'tuic') {
		const params = new URLSearchParams();
		if (node.sni) params.set('sni', node.sni);
		if (node.skipCertVerify) params.set('allow_insecure', '1');
		if (node.congestionController) params.set('congestion_controller', node.congestionController);
		if (node.udpRelayMode) params.set('udp_relay_mode', node.udpRelayMode);
		const query = params.toString() ? `?${params.toString()}` : '';
		return `tuic://${node.uuid || ''}:${node.password || ''}@${host}:${node.port}${query}#${encodeURIComponent(node.name || '')}`;
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
		proxy.cipher = dict.cipher || 'auto';
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
	const directRules = [];
	const customGroups = [];

	for (let line of lines) {
		line = line.trim();
		if (!line || line.startsWith('#') || line.startsWith(';')) continue;

		if (line.toLowerCase().startsWith('ruleset=')) {
			const val = line.slice(8).trim();
			const parts = val.split(',');
			if (parts.length >= 2) {
				const group = parts[0].trim();
				const target = parts[1].trim();

				// 1. 如果以 [] 开头，是 subconverter 的内置直连规则，不是远程 rule-provider URL
				if (target.startsWith('[]')) {
					const ruleType = target.slice(2).trim();
					if (ruleType.toUpperCase() === 'FINAL') {
						directRules.push(`MATCH,${group}`);
					} else if (ruleType.toUpperCase() === 'GEOIP') {
						const param = parts[2] ? parts[2].trim() : 'CN';
						directRules.push(`GEOIP,${param},${group},no-resolve`);
					} else {
						const restParams = parts.slice(2).map(p => p.trim()).join(',');
						directRules.push(`${ruleType}${restParams ? ',' + restParams : ''},${group}`);
					}
				} else {
					// 2. 检查是否包含 http:// 或 https:// 远程规则集 URL (支持 clash-classic: 等前缀)
					const httpMatch = target.match(/https?:\/\/.+/i);
					if (httpMatch) {
						const rawUrl = httpMatch[0].trim();
						const prefix = target.slice(0, httpMatch.index).replace(/:$/, '').trim().toLowerCase();
						let behavior = 'classical';
						if (prefix.includes('domain')) behavior = 'domain';
						else if (prefix.includes('ipcidr')) behavior = 'ipcidr';
						else if (prefix.includes('classic')) behavior = 'classical';

						const interval = parseInt(parts[2] || '86400', 10);
						rulesets.push({ group, url: rawUrl, interval, behavior });
					} else {
						// 3. 直接规则定义，如 ruleset=Group,DOMAIN-SUFFIX,example.com
						const rest = parts.slice(1).map(p => p.trim()).join(',');
						directRules.push(`${rest},${group}`);
					}
				}
			}
		} else if (line.toLowerCase().startsWith('custom_proxy_group=')) {
			const val = line.slice(19).trim();
			customGroups.push(val);
		}
	}

	return { rulesets, directRules, customGroups };
}

// ==========================================
// 4.1 GitHub 规则集多源容灾与边缘中继系统
// ==========================================

export function normalizeTargetUrl(url) {
	if (!url) return '';
	let clean = url.trim();
	const mirrorPrefixes = [
		'https://gh-proxy.com/',
		'http://gh-proxy.com/',
		'https://ghfast.top/',
		'http://ghfast.top/',
		'https://ghproxy.net/',
		'http://ghproxy.net/',
		'https://ghproxy.com/',
		'http://ghproxy.com/',
		'https://raw.gitmirror.com/'
	];
	for (const p of mirrorPrefixes) {
		if (clean.startsWith(p)) {
			let rest = clean.slice(p.length);
			if (p === 'https://raw.gitmirror.com/' && !rest.startsWith('http')) {
				rest = `https://raw.githubusercontent.com/${rest}`;
			}
			clean = rest;
			break;
		}
	}
	return clean;
}

export function getFailoverUrls(targetUrl, customMirror = '') {
	const cleanUrl = normalizeTargetUrl(targetUrl);
	const urls = [];

	// 1. 直连源站 (Cloudflare 全球骨干网络可极速直连 GitHub)
	urls.push(cleanUrl);

	// 2. 自定义镜像（若指定了非 worker / 非 direct 的 http(s) 前缀）
	if (customMirror && customMirror.startsWith('http')) {
		let prefix = customMirror.trim();
		if (!prefix.endsWith('/')) prefix += '/';
		const customUrl = `${prefix}${cleanUrl}`;
		if (!urls.includes(customUrl)) {
			urls.push(customUrl);
		}
	}

	const isGithub = cleanUrl.startsWith('https://raw.githubusercontent.com/') ||
		cleanUrl.startsWith('http://raw.githubusercontent.com/') ||
		(cleanUrl.startsWith('https://github.com/') && cleanUrl.includes('/raw/'));

	if (isGithub) {
		// 3. 权威高可用公共镜像容灾池（依稳定性排序）
		const stableMirrors = [
			'https://gh-proxy.com/',
			'https://ghfast.top/',
			'https://ghproxy.net/'
		];
		for (const m of stableMirrors) {
			const u = `${m}${cleanUrl}`;
			if (!urls.includes(u)) urls.push(u);
		}

		// 4. raw.gitmirror.com 域名替换镜像
		if (cleanUrl.includes('raw.githubusercontent.com')) {
			const gitMirrorUrl = cleanUrl.replace('raw.githubusercontent.com', 'raw.gitmirror.com');
			if (!urls.includes(gitMirrorUrl)) urls.push(gitMirrorUrl);
		}
	}

	return urls;
}

// 规则文件内容处理与格式适配
export function cleanTextRuleList(rawText) {
	if (!rawText) return '';
	const lines = rawText.split(/\r?\n/);
	const cleaned = [];
	for (let line of lines) {
		line = line.trim();
		if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//')) {
			continue;
		}
		const commentIdx = line.indexOf(' #');
		if (commentIdx !== -1) {
			line = line.slice(0, commentIdx).trim();
		}
		if (line.length > 0) {
			cleaned.push(line);
		}
	}
	return cleaned.join('\n') + '\n';
}

export function isYamlRulePayload(text) {
	if (!text) return false;
	return /^payload\s*:/m.test(text);
}

export function convertRuleListToYaml(rawText) {
	if (!rawText) return 'payload:\n';
	if (isYamlRulePayload(rawText)) {
		return rawText;
	}

	const lines = rawText.split(/\r?\n/);
	const validRules = [];

	for (let line of lines) {
		line = line.trim();
		if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//')) {
			continue;
		}
		if (line.startsWith('-')) {
			line = line.slice(1).trim();
		}
		if ((line.startsWith("'") && line.endsWith("'")) || (line.startsWith('"') && line.endsWith('"'))) {
			line = line.slice(1, -1).trim();
		}
		const commentIdx = line.indexOf(' #');
		if (commentIdx !== -1) {
			line = line.slice(0, commentIdx).trim();
		}
		if (line.length > 0) {
			validRules.push(`  - ${JSON.stringify(line)}`);
		}
	}

	return `payload:\n${validRules.join('\n')}\n`;
}

export function getRequestHeadersForUrl(url) {
	const headers = {
		'User-Agent': 'Mozilla/5.0 (compatible; Clash/Mihomo; CF-Workers-SUB)'
	};
	if (url && url.toLowerCase().includes('kelee.one')) {
		headers['User-Agent'] = 'Loon/991 CFNetwork/3896.100.1.1.1 Darwin/27.0.0';
	}
	return headers;
}

export async function handleRuleProxyRequest(request, targetUrl, env = {}) {
	const cleanUrl = normalizeTargetUrl(targetUrl);
	if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
		return new Response("Invalid target URL protocol", { status: 400 });
	}

	const reqUrl = new URL(request.url);
	let targetFormat = reqUrl.searchParams.get('format');
	if (!targetFormat) {
		const urlPath = cleanUrl.split('?')[0].toLowerCase();
		targetFormat = (urlPath.endsWith('.list') || urlPath.endsWith('.txt')) ? 'text' : 'yaml';
	}

	const now = Date.now();
	const cacheId = `${targetFormat}:${cleanUrl}`;

	// 1. 优先检查内存缓存
	const memCached = ruleMemoryCache.get(cacheId);
	if (memCached && (now - memCached.time < 86400000)) {
		const headers = new Headers();
		headers.set('Content-Type', targetFormat === 'text' ? 'text/plain; charset=utf-8' : 'text/yaml; charset=utf-8');
		headers.set('Cache-Control', 'public, max-age=86400');
		headers.set('Access-Control-Allow-Origin', '*');
		headers.set('X-Cache-Status', 'HIT-MEMORY');
		return new Response(memCached.text, { status: 200, headers });
	}

	// 2. Cloudflare Edge 边缘缓存 (caches.default)
	const cacheKey = new Request(`${cleanUrl}${cleanUrl.includes('?') ? '&' : '?'}cf_fmt=${targetFormat}`, { method: 'GET' });
	let cache = null;
	try {
		if (typeof caches !== 'undefined' && caches.default) {
			cache = caches.default;
			const cachedResponse = await cache.match(cacheKey);
			if (cachedResponse) {
				return cachedResponse;
			}
		}
	} catch (e) {
		console.warn('Edge cache match error:', e);
	}

	// 3. 多源容灾候选池依次遍历，单点镜像失效自动无缝回退
	const candidates = getFailoverUrls(cleanUrl);
	for (const cand of candidates) {
		try {
			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), 4000);
			const resp = await fetch(cand, {
				signal: controller.signal,
				headers: getRequestHeadersForUrl(cand)
			});
			clearTimeout(timeout);
			if (resp.ok) {
				const rawBody = await resp.text();
				if (rawBody && rawBody.trim().length > 0) {
					// 依据目标格式对规则内容进行规范化适配
					const processedText = targetFormat === 'text'
						? cleanTextRuleList(rawBody)
						: convertRuleListToYaml(rawBody);

					// 写入内存缓存 (控制缓存上限防止内存膨胀)
					setCacheWithLimit(ruleMemoryCache, cacheId, { text: processedText, time: now }, MAX_CACHE_ENTRIES);

					const headers = new Headers();
					headers.set('Content-Type', targetFormat === 'text' ? 'text/plain; charset=utf-8' : 'text/yaml; charset=utf-8');
					headers.set('Cache-Control', 'public, max-age=86400');
					headers.set('Access-Control-Allow-Origin', '*');
					headers.set('X-Relay-Source', cand);
					headers.set('X-Rule-Format', targetFormat);
					headers.set('X-Cache-Status', 'MISS');

					const response = new Response(processedText, { status: 200, headers });
					if (cache) {
						try {
							await cache.put(cacheKey, response.clone());
						} catch (cacheErr) {
							console.warn('Edge cache put error:', cacheErr);
						}
					}
					return response;
				}
			}
		} catch (err) {
			console.warn(`Fetch candidate ${cand} failed: ${err.message}`);
		}
	}

	return new Response(`Error: Failed to fetch rule provider from all mirror sources.\nTarget: ${cleanUrl}`, {
		status: 502,
		headers: { 'Content-Type': 'text/plain; charset=utf-8' }
	});
}

export function applyGhProxy(url, ghProxy = 'worker', workerRuleBase = '', format = '') {
	if (!url) return url;
	const cleanUrl = normalizeTargetUrl(url);

	const isKelee = cleanUrl.toLowerCase().includes('kelee.one');
	// 对于 kelee.one 等需要伪装专用 User-Agent (Loon) 的特殊源，只要有 workerRuleBase 就必须经由 Worker 中继代理
	if (isKelee && workerRuleBase) {
		const sep = workerRuleBase.includes('?') ? '&' : '?';
		let res = `${workerRuleBase}${sep}url=${encodeURIComponent(cleanUrl)}`;
		if (format) res += `&format=${format}`;
		return res;
	}

	// 直连或关闭加速
	if (!ghProxy || ghProxy === 'direct' || ghProxy === 'false' || ghProxy === 'none' || ghProxy === 'off') {
		return cleanUrl;
	}

	const isGithub = cleanUrl.startsWith('https://raw.githubusercontent.com/') ||
		cleanUrl.startsWith('http://raw.githubusercontent.com/') ||
		(cleanUrl.startsWith('https://github.com/') && cleanUrl.includes('/raw/'));

	if (!isGithub) {
		return cleanUrl;
	}

	// Worker 边缘中继模式 (默认推荐，永不因第三方镜像单点故障断联)
	if (ghProxy === 'worker' || ghProxy === 'relay' || ghProxy === 'edge') {
		if (workerRuleBase) {
			const sep = workerRuleBase.includes('?') ? '&' : '?';
			let res = `${workerRuleBase}${sep}url=${encodeURIComponent(cleanUrl)}`;
			if (format) res += `&format=${format}`;
			return res;
		}
		// 无 workerRuleBase 上下文时回退至公共高可用镜像
		return `https://gh-proxy.com/${cleanUrl}`;
	}

	// 第三方镜像前缀模式 (如 https://gh-proxy.com/ 或 https://ghproxy.net/)
	let prefix = ghProxy.trim();
	if (!prefix.endsWith('/')) prefix += '/';
	return `${prefix}${cleanUrl}`;
}

export async function loadSubConfig(url, ghProxy = 'worker') {
	if (!url || !url.trim()) return null;
	const cleanSource = url.trim();
	const isHttpSource = cleanSource.startsWith('http://') || cleanSource.startsWith('https://');

	// 如果直接是 INI 规则文本（包含换行，或者包含 [custom] / ruleset= 等特征）
	if (!isHttpSource && (cleanSource.includes('\n') || cleanSource.includes('[custom]') || cleanSource.includes('ruleset='))) {
		try {
			return parseSubConfig(cleanSource);
		} catch (e) {
			console.warn('Failed to parse inline subConfig:', e);
			return null;
		}
	}

	const now = Date.now();
	const cached = subConfigCache.get(cleanSource);
	if (cached && (now - cached.time < 600000)) {
		return cached.parsed;
	}

	if (isHttpSource) {
		// 使用多源容灾池拉取规则配置文件 (即使单一镜像宕机也能从容流转)
		const candidates = getFailoverUrls(cleanSource, ghProxy && ghProxy.startsWith('http') ? ghProxy : '');
		for (const cand of candidates) {
			try {
				const controller = new AbortController();
				const timeout = setTimeout(() => controller.abort(), 3500);
				const res = await fetch(cand, { signal: controller.signal, headers: getRequestHeadersForUrl(cand) });
				clearTimeout(timeout);
				if (res.ok) {
					const text = await res.text();
					if (text && text.trim().length > 0) {
						const parsed = parseSubConfig(text);
						setCacheWithLimit(subConfigCache, cleanSource, { parsed, time: now }, MAX_CACHE_ENTRIES);
						return parsed;
					}
				}
			} catch (e) {
				console.warn(`Fetch subConfig candidate ${cand} failed:`, e.message);
			}
		}
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

export function matchRegex(patternStr, targetStr) {
	try {
		let pattern = patternStr;
		let flags = '';
		if (pattern.startsWith('(?i)')) {
			pattern = pattern.slice(4);
			flags = 'i';
		}
		const re = new RegExp(pattern, flags);
		return re.test(targetStr);
	} catch {
		return false;
	}
}

export function parseCustomProxyGroup(rawLine) {
	const parts = rawLine.split('`').map(s => s.trim()).filter(Boolean);
	if (parts.length < 2) return null;

	const name = parts[0];
	const type = parts[1].toLowerCase();
	const rules = [];
	let url = 'http://www.gstatic.com/generate_204';
	let interval = 300;
	let tolerance = 50;

	for (let i = 2; i < parts.length; i++) {
		const part = parts[i];
		if (part.startsWith('http://') || part.startsWith('https://')) {
			url = part;
		} else if (/^\d+(?:,\s*,\s*\d+)?$/.test(part)) {
			const numParts = part.split(',').map(s => s.trim()).filter(Boolean);
			if (numParts.length >= 1) interval = parseInt(numParts[0], 10) || 300;
			if (numParts.length >= 2) tolerance = parseInt(numParts[1], 10) || 50;
		} else {
			rules.push(part);
		}
	}

	return { name, type, rules, url, interval, tolerance };
}

export function breakCycles(groups) {
	const groupMap = new Map(groups.map(g => [g.name, g]));
	const groupNames = new Set(groupMap.keys());

	function canReach(start, target, visited = new Set()) {
		if (start === target) return true;
		visited.add(start);
		const g = groupMap.get(start);
		if (!g) return false;
		for (const p of g.proxies || []) {
			if (groupNames.has(p) && !visited.has(p)) {
				if (canReach(p, target, visited)) return true;
			}
		}
		return false;
	}

	for (const g of groups) {
		const safeProxies = [];
		for (const p of g.proxies || []) {
			if (groupNames.has(p)) {
				if (canReach(p, g.name)) {
					// 环路阻断：跳过该策略，避免产生相互嵌套造成的 loop is detected in ProxyGroup
					continue;
				}
			}
			safeProxies.push(p);
		}
		if (safeProxies.length === 0) {
			safeProxies.push('DIRECT');
		}
		g.proxies = safeProxies;
	}
}

export function formatProxyGroupYaml(g) {
	let str = `  - name: ${JSON.stringify(g.name)}\n    type: ${g.type}\n`;
	if (g.type === 'url-test' || g.type === 'fallback' || g.type === 'load-balance') {
		str += `    url: ${g.url || 'http://www.gstatic.com/generate_204'}\n`;
		str += `    interval: ${g.interval || 300}\n`;
		if (g.type === 'url-test' && g.tolerance !== undefined) {
			str += `    tolerance: ${g.tolerance}\n`;
		}
	}
	str += `    proxies:\n`;
	str += (g.proxies || []).map(p => `      - ${JSON.stringify(p)}`).join('\n');
	return str;
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
		lines.push(`    cipher: ${p.cipher || 'auto'}`);
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

export function extractRuleProviderName(url, idx, seenNames) {
	try {
		const clean = url.split('?')[0].split('#')[0];
		const slashIdx = clean.lastIndexOf('/');
		let filename = slashIdx !== -1 ? clean.slice(slashIdx + 1) : clean;
		// 移除常见规则文件扩展名 (.list, .yaml, .yml, .txt, .conf, .json)
		filename = filename.replace(/\.(list|yaml|yml|txt|conf|json)$/i, '');
		// 替换非安全字符（保留字母、数字、中划线、下划线及中文常用字符）
		filename = filename.replace(/[^\w\-\u4e00-\u9fa5]/g, '_').trim();
		if (!filename) filename = `ruleset_${idx}`;

		// 冲突去重
		let baseName = filename;
		let count = 1;
		while (seenNames.has(filename)) {
			count++;
			filename = `${baseName}_${count}`;
		}
		seenNames.add(filename);
		return filename;
	} catch {
		let fallback = `ruleset_${idx}`;
		seenNames.add(fallback);
		return fallback;
	}
}

export function generateClashConfig(nodes, subName = 'CF-Workers-SUB', subConfigParsed = null, ghProxy = 'worker', workerRuleBase = '') {
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

	const directRules = subConfigParsed?.directRules || [];
	for (const dr of directRules) {
		const parts = dr.split(',');
		if (parts.length >= 2) {
			const grp = parts[parts.length - (parts[parts.length - 1] === 'no-resolve' ? 2 : 1)].trim();
			if (grp) neededGroups.add(grp);
		}
	}

	const builtGroups = [];

	if (subConfigParsed?.customGroups && subConfigParsed.customGroups.length > 0) {
		const parsedCustom = subConfigParsed.customGroups
			.map(parseCustomProxyGroup)
			.filter(Boolean);

		for (const cg of parsedCustom) {
			const proxies = [];
			for (const r of cg.rules) {
				if (r.startsWith('[]')) {
					const target = r.slice(2).trim();
					if (target) proxies.push(target);
				} else {
					const matched = nodes.filter(n => matchRegex(r, n.name)).map(n => n.name);
					proxies.push(...matched);
				}
			}

			if (proxies.length === 0) {
				if (cg.type === 'url-test' || cg.type === 'fallback') {
					if (proxyNames.length > 0) proxies.push(...proxyNames);
					else proxies.push('DIRECT');
				} else {
					proxies.push('DIRECT');
				}
			}

			builtGroups.push({
				name: cg.name,
				type: cg.type,
				url: cg.url,
				interval: cg.interval,
				tolerance: cg.tolerance,
				proxies: Array.from(new Set(proxies))
			});
		}

		// 补充在 ruleset 中出现但 custom_proxy_group 未定义的策略组
		const existingNames = new Set(builtGroups.map(g => g.name));
		for (const g of neededGroups) {
			if (existingNames.has(g) || g === 'DIRECT' || g === 'REJECT') continue;
			const matchedNodes = matchNodesByRegion(nodes, g);
			const proxies = matchedNodes.length > 0
				? [...matchedNodes.map(n => n.name), "节点选择", "DIRECT"]
				: ["节点选择", "DIRECT", ...proxyNames];
			builtGroups.push({
				name: g,
				type: 'select',
				proxies: Array.from(new Set(proxies))
			});
			existingNames.add(g);
		}
	} else {
		// 默认策略组（严格单向 DAG 拓扑无环，杜绝策略组相互嵌套）
		const regionGroups = [];
		for (const g of neededGroups) {
			if (g !== '节点选择' && g !== '全球直连' && g !== '全球拦截' && g !== '应用净化' && g !== 'DIRECT' && g !== 'REJECT' && g !== '🐟 漏网之鱼' && g !== '漏网之鱼') {
				regionGroups.push(g);
			}
		}

		// 1. 节点选择（绝不包含下游 regionGroups，防止形成相互循环引用）
		const mainSelectProxies = ["♻️ 自动选择", "🔯 故障转移", ...proxyNames, "DIRECT"];
		builtGroups.push({
			name: "节点选择",
			type: "select",
			proxies: Array.from(new Set(mainSelectProxies))
		});

		builtGroups.push({
			name: "♻️ 自动选择",
			type: "url-test",
			url: "http://www.gstatic.com/generate_204",
			interval: 300,
			tolerance: 50,
			proxies: proxyNames.length > 0 ? [...proxyNames] : ["DIRECT"]
		});

		builtGroups.push({
			name: "🔯 故障转移",
			type: "fallback",
			url: "http://www.gstatic.com/generate_204",
			interval: 300,
			proxies: proxyNames.length > 0 ? [...proxyNames] : ["DIRECT"]
		});

		for (const g of regionGroups) {
			const matchedNodes = matchNodesByRegion(nodes, g);
			const groupProxies = matchedNodes.length > 0
				? [...matchedNodes.map(n => n.name), "节点选择", "DIRECT"]
				: ["节点选择", "DIRECT", ...proxyNames];
			builtGroups.push({
				name: g,
				type: "select",
				proxies: Array.from(new Set(groupProxies))
			});
		}

		if (neededGroups.has('全球直连')) {
			builtGroups.push({
				name: "全球直连",
				type: "select",
				proxies: ["DIRECT", "节点选择"]
			});
		}

		if (neededGroups.has('全球拦截')) {
			builtGroups.push({
				name: "全球拦截",
				type: "select",
				proxies: ["REJECT", "DIRECT"]
			});
		}

		if (neededGroups.has('应用净化')) {
			builtGroups.push({
				name: "应用净化",
				type: "select",
				proxies: ["REJECT", "DIRECT"]
			});
		}

		const finalName = neededGroups.has('漏网之鱼') ? '漏网之鱼' : '🐟 漏网之鱼';
		builtGroups.push({
			name: finalName,
			type: "select",
			proxies: ["节点选择", "DIRECT"]
		});
	}

	const realNodeNames = new Set(nodes.map(n => n.name));
	const groupMap = new Map(builtGroups.map(g => [g.name, g]));

	function hasRealProxies(groupName, visited = new Set()) {
		if (visited.has(groupName)) return false;
		visited.add(groupName);
		if (realNodeNames.has(groupName)) return true;
		if (groupName === 'DIRECT' || groupName === 'REJECT') return false;
		const g = groupMap.get(groupName);
		if (!g) return false;
		for (const p of g.proxies || []) {
			if (realNodeNames.has(p)) return true;
			if (p !== 'DIRECT' && p !== 'REJECT' && groupMap.has(p)) {
				if (hasRealProxies(p, visited)) return true;
			}
		}
		return false;
	}

	// 1. 过滤测速组（url-test / fallback / load-balance）中的空分组及 DIRECT/REJECT，避免测速偏向 DIRECT
	for (const g of builtGroups) {
		if (g.type === 'url-test' || g.type === 'fallback' || g.type === 'load-balance') {
			const validProxies = (g.proxies || []).filter(p => {
				if (p === 'DIRECT' || p === 'REJECT') return false;
				if (groupMap.has(p)) return hasRealProxies(p);
				return realNodeNames.has(p);
			});
			if (validProxies.length > 0) {
				g.proxies = validProxies;
			} else {
				// 若所有子分组皆无真实节点，回退至全部可用节点
				g.proxies = proxyNames.length > 0 ? [...proxyNames] : ['DIRECT'];
			}
		}
	}

	// 2. 优化节点选择与各策略组顺序：DIRECT 移至末尾，首位优先放入测速组或有效代理节点，杜绝首次加载断网
	for (const g of builtGroups) {
		if (g.name === '节点选择') {
			let proxies = [...(g.proxies || [])];
			// 查找首选测速组（如 AI自动测速、♻️ 自动选择）
			let autoTestGroup = null;
			for (const cand of ['AI自动测速', '♻️ 自动选择']) {
				if (groupMap.has(cand) && hasRealProxies(cand)) {
					autoTestGroup = cand;
					break;
				}
			}

			const nonDirect = proxies.filter(p => p !== 'DIRECT' && p !== 'REJECT');
			const directItems = proxies.filter(p => p === 'DIRECT' || p === 'REJECT');

			if (autoTestGroup) {
				const filteredNonDirect = nonDirect.filter(p => p !== autoTestGroup);
				proxies = [autoTestGroup, ...filteredNonDirect, ...directItems];
			} else {
				proxies = [...nonDirect, ...directItems];
			}

			if (proxies.length === 0) proxies.push('DIRECT');
			g.proxies = Array.from(new Set(proxies));
		} else if (g.type === 'select' && g.name !== '全球直连' && g.name !== '全球拦截' && g.name !== '应用净化') {
			const hasReal = g.proxies.some(p => realNodeNames.has(p) || (groupMap.has(p) && hasRealProxies(p)));
			if (hasReal && g.proxies.includes('DIRECT')) {
				const rest = g.proxies.filter(p => p !== 'DIRECT' && p !== 'REJECT');
				const tail = g.proxies.filter(p => p === 'DIRECT' || p === 'REJECT');
				g.proxies = [...rest, ...tail];
			}
		}
	}

	// 最终防环检查：破除任何潜在的循环引用（有向图拓扑无环化）
	breakCycles(builtGroups);

	// 构建 YAML proxy-groups
	yaml += `\nproxy-groups:\n`;
	yaml += builtGroups.map(formatProxyGroupYaml).join('\n\n') + '\n';

	// 5. Rule-providers (根据 rule 文件名与扩展名自适应 format: text / yaml，彻底杜绝 payload 报错)
	const seenProviderNames = new Set();
	const providerEntries = rulesets.map((r, idx) => {
		const cleanUrl = r.url.split('?')[0].split('#')[0].toLowerCase();
		const isTextList = cleanUrl.endsWith('.list') || cleanUrl.endsWith('.txt');
		const format = isTextList ? 'text' : 'yaml';
		const ext = isTextList ? 'list' : 'yaml';
		return {
			name: extractRuleProviderName(r.url, idx, seenProviderNames),
			group: r.group,
			url: applyGhProxy(r.url, ghProxy, workerRuleBase, format),
			format,
			ext,
			behavior: r.behavior || 'classical',
			interval: r.interval || 86400
		};
	});

	if (providerEntries.length > 0) {
		yaml += `\nrule-providers:\n`;
		providerEntries.forEach(p => {
			yaml += `  ${p.name}:
    type: http
    behavior: ${p.behavior}
    format: ${p.format}
    url: ${JSON.stringify(p.url)}
    path: ./ruleset/${p.name}.${p.ext}
    interval: ${p.interval}
`;
		});
	}

	// 6. 分流规则
	yaml += `\nrules:\n`;
	if (providerEntries.length > 0) {
		providerEntries.forEach(p => {
			yaml += `  - RULE-SET,${p.name},${p.group}\n`;
		});
	}

	const nonMatchDirectRules = directRules.filter(r => !r.startsWith('MATCH'));
	const matchDirectRules = directRules.filter(r => r.startsWith('MATCH'));

	if (nonMatchDirectRules.length > 0) {
		for (const dr of nonMatchDirectRules) {
			yaml += `  - ${dr}\n`;
		}
	}

	const hasLan = directRules.some(r => r.includes('GEOIP,LAN'));
	const hasCn = directRules.some(r => r.includes('GEOIP,CN'));

	if (!hasLan) yaml += `  - GEOIP,LAN,DIRECT,no-resolve\n`;
	if (!hasCn) yaml += `  - GEOIP,CN,DIRECT,no-resolve\n`;

	if (matchDirectRules.length > 0) {
		for (const mr of matchDirectRules) {
			yaml += `  - ${mr}\n`;
		}
	} else {
		const finalGroup = neededGroups.has('漏网之鱼') ? '漏网之鱼' : (neededGroups.has('🐟 漏网之鱼') ? '🐟 漏网之鱼' : '节点选择');
		yaml += `  - MATCH,${finalGroup}\n`;
	}

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
// 7. Clash YAML 覆写引擎 (Clash Party 规范深度合并)
// ==========================================

function splitKeyVal(line) {
	let inSingle = false, inDouble = false;
	for (let i = 0; i < line.length; i++) {
		const ch = line[i];
		if (ch === "'" && !inDouble) inSingle = !inSingle;
		else if (ch === '"' && !inSingle) inDouble = !inDouble;
		else if (ch === ':' && !inSingle && !inDouble) {
			return [line.slice(0, i).trim(), line.slice(i + 1).trim()];
		}
	}
	return [line.trim(), ''];
}

function parseYamlValue(val) {
	val = val.trim();
	if (val === 'true') return true;
	if (val === 'false') return false;
	if (val === 'null' || val === '~' || val === '') return null;
	if (val === '{}') return {};
	if (val.startsWith('[') && val.endsWith(']')) {
		const inner = val.slice(1, -1).trim();
		if (!inner) return [];
		const items = [];
		let current = '', inSingle = false, inDouble = false;
		for (let i = 0; i < inner.length; i++) {
			const ch = inner[i];
			if (ch === "'" && !inDouble) inSingle = !inSingle;
			else if (ch === '"' && !inSingle) inDouble = !inDouble;
			else if (ch === ',' && !inSingle && !inDouble) {
				items.push(parseYamlValue(current.trim()));
				current = '';
				continue;
			}
			current += ch;
		}
		if (current.trim()) items.push(parseYamlValue(current.trim()));
		return items;
	}
	if (/^-?\d+$/.test(val)) return parseInt(val, 10);
	if (/^-?\d+\.\d+$/.test(val)) return parseFloat(val);
	if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
		return val.slice(1, -1);
	}
	return val;
}

export function parseYaml(yamlStr) {
	if (!yamlStr) return {};
	const rawLines = yamlStr.split('\n');
	const lines = [];

	for (let i = 0; i < rawLines.length; i++) {
		let line = rawLines[i];
		let inSingle = false, inDouble = false, commentIdx = -1;
		for (let j = 0; j < line.length; j++) {
			const ch = line[j];
			if (ch === "'" && !inDouble) inSingle = !inSingle;
			else if (ch === '"' && !inSingle) inDouble = !inDouble;
			else if (ch === '#' && !inSingle && !inDouble) {
				if (j === 0 || /\s/.test(line[j - 1])) {
					commentIdx = j;
					break;
				}
			}
		}
		if (commentIdx !== -1) line = line.slice(0, commentIdx);
		if (!line.trim()) continue;

		const indent = line.search(/\S/);
		lines.push({ indent, text: line.trim() });
	}

	let cursor = 0;

	function parseBlock(currentIndent) {
		if (cursor >= lines.length) return null;

		const first = lines[cursor];
		if (first.indent < currentIndent) return null;

		if (first.text.startsWith('- ') || first.text === '-') {
			const list = [];
			const listIndent = first.indent;
			while (cursor < lines.length && lines[cursor].indent === listIndent && (lines[cursor].text.startsWith('- ') || lines[cursor].text === '-')) {
				const lineObj = lines[cursor];
				cursor++;
				const itemText = lineObj.text.slice(1).trim();

				if (!itemText) {
					if (cursor < lines.length && lines[cursor].indent > listIndent) {
						list.push(parseBlock(lines[cursor].indent));
					} else {
						list.push(null);
					}
				} else if ((itemText.includes(': ') || itemText.endsWith(':')) && !itemText.startsWith('http://') && !itemText.startsWith('https://')) {
					const [kRaw, vRaw] = splitKeyVal(itemText);
					let k = kRaw;
					if ((k.startsWith('"') && k.endsWith('"')) || (k.startsWith("'") && k.endsWith("'"))) {
						k = k.slice(1, -1);
					}
					const obj = {};
					if (vRaw) {
						obj[k] = parseYamlValue(vRaw);
					} else if (cursor < lines.length && lines[cursor].indent > listIndent) {
						obj[k] = parseBlock(lines[cursor].indent);
					} else {
						obj[k] = null;
					}

					while (cursor < lines.length && lines[cursor].indent > listIndent && !lines[cursor].text.startsWith('- ')) {
						const nextLine = lines[cursor];
						const [nkRaw, nvRaw] = splitKeyVal(nextLine.text);
						cursor++;
						let nk = nkRaw;
						if ((nk.startsWith('"') && nk.endsWith('"')) || (nk.startsWith("'") && nk.endsWith("'"))) {
							nk = nk.slice(1, -1);
						}
						if (nvRaw) {
							obj[nk] = parseYamlValue(nvRaw);
						} else if (cursor < lines.length && lines[cursor].indent > nextLine.indent) {
							obj[nk] = parseBlock(lines[cursor].indent);
						} else {
							obj[nk] = null;
						}
					}
					list.push(obj);
				} else {
					list.push(parseYamlValue(itemText));
				}
			}
			return list;
		}

		const map = {};
		const mapIndent = first.indent;
		while (cursor < lines.length && lines[cursor].indent === mapIndent) {
			const lineObj = lines[cursor];
			if (lineObj.text.startsWith('- ')) break;

			const [keyRaw, valStr] = splitKeyVal(lineObj.text);
			cursor++;
			let key = keyRaw;
			if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
				key = key.slice(1, -1);
			}

			if (valStr) {
				map[key] = parseYamlValue(valStr);
			} else {
				if (cursor < lines.length && lines[cursor].indent > mapIndent) {
					map[key] = parseBlock(lines[cursor].indent);
				} else {
					map[key] = null;
				}
			}
		}
		return map;
	}

	return parseBlock(0) || {};
}

function isObject(val) {
	return val !== null && typeof val === 'object' && !Array.isArray(val);
}

export function deepMerge(target, other, isOverride = true) {
	if (!target || !isObject(target)) target = {};
	if (!other || !isObject(other)) return target;

	for (const key in other) {
		if (isObject(other[key])) {
			if (key.endsWith('!')) {
				const k = key.slice(0, -1).trim();
				target[k] = other[key];
			} else {
				const k = key.trim();
				if (!target[k] || !isObject(target[k])) target[k] = {};
				deepMerge(target[k], other[key], isOverride);
			}
		} else if (Array.isArray(other[key])) {
			if (isOverride && key.startsWith('+')) {
				const k = key.slice(1).trim();
				if (!target[k] || !Array.isArray(target[k])) target[k] = [];
				target[k] = [...other[key], ...target[k]];
			} else if (isOverride && key.endsWith('+')) {
				const k = key.slice(0, -1).trim();
				if (!target[k] || !Array.isArray(target[k])) target[k] = [];
				target[k] = [...target[k], ...other[key]];
			} else {
				const k = key.trim();
				target[k] = other[key];
			}
		} else {
			target[key] = other[key];
		}
	}
	return target;
}

function formatYamlKey(key) {
	if (typeof key !== 'string') key = String(key);
	if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
		return key;
	}
	if (
		/^[*&!%@`|>?[\]{},#~]/.test(key) ||
		key.includes(':') ||
		key.includes(' ') ||
		key.includes(',') ||
		key.includes('#') ||
		key.startsWith('-') ||
		key.startsWith('+')
	) {
		return JSON.stringify(key);
	}
	return key;
}

function formatYamlScalar(val) {
	if (val === null || val === undefined) return '';
	if (typeof val === 'boolean') return val ? 'true' : 'false';
	if (typeof val === 'number') return String(val);
	const str = String(val);
	if (str === '') return '""';
	if (str === 'true' || str === 'false' || str === 'null' || str === '~') return `"${str}"`;
	if ((str.startsWith('"') && str.endsWith('"')) || (str.startsWith("'") && str.endsWith("'"))) {
		return str;
	}
	if (
		/^[*&!%@`|>?[\]{},#~]/.test(str) ||
		str.startsWith('-') ||
		str.startsWith('+') ||
		str.includes(': ') ||
		str.includes('#') ||
		str.startsWith(' ') ||
		str.endsWith(' ') ||
		str.includes('\n') ||
		str.includes('\r')
	) {
		return JSON.stringify(str);
	}
	return str;
}

export function dumpYaml(obj, indent = 0) {
	if (!obj) return '';
	const pad = ' '.repeat(indent);
	let out = '';

	if (Array.isArray(obj)) {
		for (const item of obj) {
			if (isObject(item)) {
				const keys = Object.keys(item);
				if (keys.length === 0) {
					out += `${pad}- {}\n`;
				} else {
					const firstKey = keys[0];
					const firstVal = item[firstKey];
					const formattedFirstKey = formatYamlKey(firstKey);
					if (isObject(firstVal) || Array.isArray(firstVal)) {
						out += `${pad}- ${formattedFirstKey}:\n${dumpYaml(firstVal, indent + 4)}`;
					} else {
						out += `${pad}- ${formattedFirstKey}: ${formatYamlScalar(firstVal)}\n`;
					}
					for (let i = 1; i < keys.length; i++) {
						const k = keys[i];
						const v = item[k];
						const formattedK = formatYamlKey(k);
						if (isObject(v) || Array.isArray(v)) {
							out += `${pad}  ${formattedK}:\n${dumpYaml(v, indent + 4)}`;
						} else {
							out += `${pad}  ${formattedK}: ${formatYamlScalar(v)}\n`;
						}
					}
				}
			} else if (Array.isArray(item)) {
				out += `${pad}-\n${dumpYaml(item, indent + 2)}`;
			} else {
				out += `${pad}- ${formatYamlScalar(item)}\n`;
			}
		}
	} else if (isObject(obj)) {
		for (const [k, v] of Object.entries(obj)) {
			const formattedKey = formatYamlKey(k);
			if (isObject(v)) {
				if (Object.keys(v).length === 0) {
					out += `${pad}${formattedKey}: {}\n`;
				} else {
					out += `${pad}${formattedKey}:\n${dumpYaml(v, indent + 2)}`;
				}
			} else if (Array.isArray(v)) {
				if (v.length === 0) {
					out += `${pad}${formattedKey}: []\n`;
				} else {
					out += `${pad}${formattedKey}:\n${dumpYaml(v, indent + 2)}`;
				}
			} else {
				out += `${pad}${formattedKey}: ${formatYamlScalar(v)}\n`;
			}
		}
	}
	return out;
}

export function sanitizeDnsFakeIpFilter(dns) {
	if (!dns || typeof dns !== 'object') return;
	if (dns['fake-ip-filter-mode'] === 'rule') {
		delete dns['fake-ip-filter-mode'];
		if (Array.isArray(dns['fake-ip-filter'])) {
			const sanitized = [];
			for (const item of dns['fake-ip-filter']) {
				if (typeof item !== 'string') continue;
				const parts = item.split(',').map(s => s.trim());
				if (parts.length >= 3) {
					const [type, val, action] = parts;
					if (action.toLowerCase() === 'real-ip') {
						if (type.toUpperCase() === 'DOMAIN-SUFFIX') {
							sanitized.push(`+.${val}`);
						} else if (type.toUpperCase() === 'DOMAIN-KEYWORD') {
							sanitized.push(`*${val}*`);
						} else if (type.toUpperCase() === 'DOMAIN') {
							sanitized.push(val);
						} else {
							sanitized.push(val);
						}
					}
				} else if (parts.length === 2 && parts[0].toUpperCase() === 'MATCH') {
					// skip MATCH,fake-ip as it's default in blacklist mode
				} else {
					sanitized.push(item);
				}
			}
			dns['fake-ip-filter'] = sanitized;
		}
	}
}

export function applyYamlOverride(baseYaml, overrideYaml) {
	if (!overrideYaml || !overrideYaml.trim()) return baseYaml;
	try {
		const baseObj = parseYaml(baseYaml);
		const overrideObj = parseYaml(overrideYaml);
		const mergedObj = deepMerge(baseObj, overrideObj, true);
		if (mergedObj.dns) {
			sanitizeDnsFakeIpFilter(mergedObj.dns);
		}
		return dumpYaml(mergedObj);
	} catch (err) {
		console.error('Error in applyYamlOverride:', err);
		return baseYaml;
	}
}

export async function loadOverrideConfig(source, ghProxy = 'worker') {
	if (!source || !source.trim()) return null;
	const cleanSource = source.trim();

	// 如果直接是 YAML 文本内容（包含多行或关键字段结构）
	if (cleanSource.includes('\n') || cleanSource.includes(': ') || cleanSource.includes(':\n')) {
		return cleanSource;
	}

	const now = Date.now();
	const cached = overrideConfigCache.get(cleanSource);
	if (cached && (now - cached.time < 600000)) {
		return cached.text;
	}

	if (cleanSource.startsWith('http://') || cleanSource.startsWith('https://')) {
		const candidates = getFailoverUrls(cleanSource, ghProxy && ghProxy.startsWith('http') ? ghProxy : '');
		for (const cand of candidates) {
			try {
				const controller = new AbortController();
				const timeout = setTimeout(() => controller.abort(), 3500);
				const res = await fetch(cand, { signal: controller.signal, headers: getRequestHeadersForUrl(cand) });
				clearTimeout(timeout);
				if (res.ok) {
					const text = await res.text();
					if (text && text.trim().length > 0) {
						setCacheWithLimit(overrideConfigCache, cleanSource, { text, time: now }, MAX_CACHE_ENTRIES);
						return text;
					}
				}
			} catch (e) {
				console.warn(`Fetch override candidate ${cand} failed:`, e.message);
			}
		}
	}

	return cached ? cached.text : null;
}

// ==========================================
// 8. 辅助功能函数与网络请求
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
					headers: getRequestHeadersForUrl(url),
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

async function sendMessage(type, ip, add_data = "", botToken = "", chatId = "") {
	if (botToken !== '' && chatId !== '') {
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

		const tgUrl = `https://api.telegram.org/bot${botToken}/sendMessage?chat_id=${chatId}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
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
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
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
// 9. KV 网页管理界面
// ==========================================

async function renderKVPage(request, env, txt = 'LINK.txt', guest, currentSubConfig, currentGhProxy = 'worker', currentOverride = '', currentToken = '', subName = '') {
	const url = new URL(request.url);
	const mytoken = currentToken || env.TOKEN || DEFAULT_TOKEN;
	const FileName = subName || env.SUBNAME || DEFAULT_FILENAME;

	if (request.method === "POST") {
		if (!env.KV) return new Response("未绑定 KV 命名空间", { status: 400 });
		try {
			const body = await request.text();
			if (body.startsWith('{')) {
				try {
					const data = JSON.parse(body);
					if (data.link !== undefined) await env.KV.put(txt, data.link);
					if (data.subConfig !== undefined) await env.KV.put('CONFIG.txt', data.subConfig.trim());
					if (data.ghProxy !== undefined) await env.KV.put('GHPROXY.txt', data.ghProxy.trim());
					if (data.override !== undefined) await env.KV.put('OVERRIDE.txt', data.override.trim());
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

	const adminAutoUrl = `https://${url.hostname}/${mytoken}`;
	const adminClashUrl = `https://${url.hostname}/${mytoken}?clash`;
	const adminB64Url = `https://${url.hostname}/${mytoken}?b64`;
	const adminClashImport = `clash://install-config?url=${encodeURIComponent(adminClashUrl)}`;

	const guestTokenVal = guest || 'sub';
	const guestAutoUrl = `https://${url.hostname}/${guestTokenVal}`;
	const guestClashUrl = `https://${url.hostname}/${guestTokenVal}?clash`;
	const guestB64Url = `https://${url.hostname}/${guestTokenVal}?b64`;
	const guestClashImport = `clash://install-config?url=${encodeURIComponent(guestClashUrl)}`;

	const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<title>${FileName} 汇聚订阅管理</title>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
	<style>
		:root {
			--bg: #f8fafc;
			--card-bg: #ffffff;
			--text-main: #0f172a;
			--text-muted: #64748b;
			--primary: #3b82f6;
			--primary-hover: #2563eb;
			--primary-light: #eff6ff;
			--accent: #10b981;
			--accent-light: #ecfdf5;
			--border: #e2e8f0;
			--border-hover: #cbd5e1;
			--input-bg: #f8fafc;
			--shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
			--shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
			--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04);
			--radius-lg: 16px;
			--radius-md: 10px;
			--radius-sm: 6px;
			--font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
		}

		@media (prefers-color-scheme: dark) {
			:root {
				--bg: #0b0f19;
				--card-bg: #111827;
				--text-main: #f3f4f6;
				--text-muted: #9ca3af;
				--primary: #3b82f6;
				--primary-hover: #60a5fa;
				--primary-light: rgba(59, 130, 246, 0.12);
				--accent: #10b981;
				--accent-light: rgba(16, 185, 129, 0.12);
				--border: #1f2937;
				--border-hover: #374151;
				--input-bg: #0f172a;
				--shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.4);
				--shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
				--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
			}
		}

		* { box-sizing: border-box; }
		body {
			margin: 0;
			padding: 24px 16px;
			background-color: var(--bg);
			color: var(--text-main);
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
			line-height: 1.5;
			-webkit-font-smoothing: antialiased;
		}

		.app-container {
			max-width: 920px;
			margin: 0 auto;
		}

		/* Header Section */
		.header-card {
			background: linear-gradient(135deg, rgba(59, 130, 246, 0.08), rgba(16, 185, 129, 0.08)), var(--card-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-lg);
			padding: 24px;
			margin-bottom: 20px;
			box-shadow: var(--shadow-sm);
			display: flex;
			flex-direction: column;
			gap: 12px;
		}
		.header-title-row {
			display: flex;
			align-items: center;
			justify-content: space-between;
			flex-wrap: wrap;
			gap: 12px;
		}
		.title-group {
			display: flex;
			align-items: center;
			gap: 12px;
		}
		.logo-icon {
			width: 44px;
			height: 44px;
			background: linear-gradient(135deg, #3b82f6, #10b981);
			color: white;
			border-radius: 12px;
			display: flex;
			align-items: center;
			justify-content: center;
			font-size: 22px;
			box-shadow: 0 4px 10px rgba(59, 130, 246, 0.3);
		}
		h1 {
			margin: 0;
			font-size: 20px;
			font-weight: 700;
			letter-spacing: -0.02em;
		}
		.subtitle {
			margin: 0;
			font-size: 13px;
			color: var(--text-muted);
		}
		.header-badges {
			display: flex;
			align-items: center;
			gap: 8px;
			flex-wrap: wrap;
		}
		.badge {
			padding: 4px 10px;
			border-radius: 20px;
			font-size: 12px;
			font-weight: 500;
			display: inline-flex;
			align-items: center;
			gap: 4px;
		}
		.badge-success {
			background: var(--accent-light);
			color: var(--accent);
			border: 1px solid rgba(16, 185, 129, 0.2);
		}
		.badge-primary {
			background: var(--primary-light);
			color: var(--primary);
			border: 1px solid rgba(59, 130, 246, 0.2);
		}

		/* Main Cards */
		.card {
			background: var(--card-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-lg);
			padding: 22px;
			margin-bottom: 20px;
			box-shadow: var(--shadow-sm);
			transition: border-color 0.2s;
		}
		.card:hover {
			border-color: var(--border-hover);
		}
		.card-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			margin-bottom: 16px;
			padding-bottom: 12px;
			border-bottom: 1px solid var(--border);
		}
		.card-title {
			font-size: 16px;
			font-weight: 600;
			display: flex;
			align-items: center;
			gap: 8px;
			margin: 0;
		}

		/* Subscription Tabs */
		.tab-nav {
			display: flex;
			gap: 8px;
			background: var(--input-bg);
			padding: 4px;
			border-radius: var(--radius-md);
			margin-bottom: 16px;
			border: 1px solid var(--border);
		}
		.tab-btn {
			flex: 1;
			padding: 8px 14px;
			border: none;
			border-radius: var(--radius-sm);
			background: transparent;
			color: var(--text-muted);
			font-size: 13px;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.2s;
		}
		.tab-btn.active {
			background: var(--card-bg);
			color: var(--primary);
			box-shadow: var(--shadow-sm);
		}

		/* Link Row */
		.link-row {
			background: var(--input-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-md);
			padding: 12px 14px;
			margin-bottom: 12px;
			display: flex;
			flex-direction: column;
			gap: 8px;
		}
		.link-row:last-child { margin-bottom: 0; }
		.link-info {
			display: flex;
			align-items: center;
			justify-content: space-between;
			flex-wrap: wrap;
			gap: 6px;
		}
		.link-name {
			font-weight: 600;
			font-size: 13px;
			display: flex;
			align-items: center;
			gap: 6px;
		}
		.link-input-group {
			display: flex;
			align-items: center;
			gap: 8px;
		}
		.link-text {
			flex: 1;
			background: var(--card-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-sm);
			padding: 8px 10px;
			font-family: var(--font-mono);
			font-size: 12px;
			color: var(--text-main);
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}
		.btn-group {
			display: flex;
			align-items: center;
			gap: 6px;
			flex-shrink: 0;
		}
		.btn {
			padding: 7px 12px;
			border-radius: var(--radius-sm);
			border: 1px solid var(--border);
			background: var(--card-bg);
			color: var(--text-main);
			font-size: 12px;
			font-weight: 500;
			cursor: pointer;
			display: inline-flex;
			align-items: center;
			gap: 5px;
			transition: all 0.15s ease;
			text-decoration: none;
		}
		.btn:hover {
			background: var(--input-bg);
			border-color: var(--border-hover);
		}
		.btn-primary {
			background: var(--primary);
			border-color: var(--primary);
			color: white;
		}
		.btn-primary:hover {
			background: var(--primary-hover);
			border-color: var(--primary-hover);
		}

		/* Form Inputs */
		.form-group {
			margin-bottom: 16px;
		}
		.form-group:last-child { margin-bottom: 0; }
		.form-label {
			display: block;
			font-size: 13px;
			font-weight: 600;
			margin-bottom: 6px;
		}
		.form-desc {
			font-size: 12px;
			color: var(--text-muted);
			margin-top: 4px;
		}
		.input-text, .input-select {
			width: 100%;
			padding: 10px 12px;
			background: var(--input-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-md);
			color: var(--text-main);
			font-size: 13px;
			font-family: var(--font-mono);
			outline: none;
			transition: all 0.15s;
		}
		.input-text:focus, .input-select:focus {
			border-color: var(--primary);
			box-shadow: 0 0 0 3px var(--primary-light);
		}
		.input-select {
			font-family: inherit;
			cursor: pointer;
		}

		/* Textarea Editor */
		.editor-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			margin-bottom: 8px;
			flex-wrap: wrap;
			gap: 8px;
		}
		.editor-stats {
			font-size: 12px;
			color: var(--text-muted);
			display: flex;
			gap: 12px;
		}
		.editor-stat-item {
			display: inline-flex;
			align-items: center;
			gap: 4px;
		}
		.editor-textarea {
			width: 100%;
			min-height: 280px;
			padding: 12px;
			background: var(--input-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-md);
			color: var(--text-main);
			font-family: var(--font-mono);
			font-size: 13px;
			line-height: 1.5;
			resize: vertical;
			outline: none;
			transition: all 0.15s;
			white-space: pre;
		}
		.editor-textarea:focus {
			border-color: var(--primary);
			box-shadow: 0 0 0 3px var(--primary-light);
		}

		/* Actions Bar */
		.action-bar {
			display: flex;
			align-items: center;
			justify-content: space-between;
			margin-top: 16px;
			flex-wrap: wrap;
			gap: 12px;
		}
		.save-btn {
			padding: 10px 24px;
			background: linear-gradient(135deg, #10b981, #059669);
			color: white;
			border: none;
			border-radius: var(--radius-md);
			font-size: 14px;
			font-weight: 600;
			cursor: pointer;
			display: inline-flex;
			align-items: center;
			gap: 6px;
			box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
			transition: all 0.15s;
		}
		.save-btn:hover {
			opacity: 0.95;
			transform: translateY(-1px);
		}
		.save-btn:active {
			transform: translateY(0);
		}
		.save-btn:disabled {
			opacity: 0.6;
			cursor: not-allowed;
			transform: none;
		}

		/* Modal for QR Code */
		.modal-backdrop {
			display: none;
			position: fixed;
			top: 0; left: 0; right: 0; bottom: 0;
			background: rgba(0, 0, 0, 0.5);
			backdrop-filter: blur(4px);
			z-index: 1000;
			align-items: center;
			justify-content: center;
			padding: 16px;
		}
		.modal-backdrop.show {
			display: flex;
		}
		.modal-content {
			background: var(--card-bg);
			border: 1px solid var(--border);
			border-radius: var(--radius-lg);
			padding: 24px;
			max-width: 340px;
			width: 100%;
			text-align: center;
			box-shadow: var(--shadow-lg);
			animation: modalPop 0.2s ease-out;
		}
		@keyframes modalPop {
			from { opacity: 0; transform: scale(0.95); }
			to { opacity: 1; transform: scale(1); }
		}
		.modal-title {
			font-size: 16px;
			font-weight: 600;
			margin-top: 0;
			margin-bottom: 14px;
		}
		.qr-wrapper {
			display: inline-block;
			padding: 12px;
			background: white;
			border-radius: 12px;
			box-shadow: var(--shadow-sm);
			border: 1px solid var(--border);
			margin-bottom: 14px;
		}
		.modal-close {
			width: 100%;
			padding: 9px;
			border: 1px solid var(--border);
			border-radius: var(--radius-sm);
			background: var(--input-bg);
			color: var(--text-main);
			font-weight: 600;
			cursor: pointer;
			transition: background 0.15s;
		}
		.modal-close:hover {
			background: var(--border);
		}

		/* Toast Notification */
		.toast {
			position: fixed;
			bottom: 24px;
			right: 24px;
			padding: 10px 18px;
			background: #1f2937;
			color: #fff;
			border-radius: var(--radius-md);
			box-shadow: var(--shadow-lg);
			font-size: 13px;
			font-weight: 500;
			display: flex;
			align-items: center;
			gap: 8px;
			z-index: 1100;
			opacity: 0;
			transform: translateY(12px);
			transition: all 0.25s ease;
			pointer-events: none;
		}
		.toast.show {
			opacity: 1;
			transform: translateY(0);
		}
	</style>
</head>
<body>

<div class="app-container">
	<!-- Header Section -->
	<header class="header-card">
		<div class="header-title-row">
			<div class="title-group">
				<div class="logo-icon">⚡</div>
				<div>
					<h1>${FileName} 汇聚订阅中心</h1>
					<p class="subtitle">原生内置多协议转换 · 零外部后端依赖 · 毫秒级生成</p>
				</div>
			</div>
			<div class="header-badges">
				<span class="badge badge-success">● 内置原生引擎</span>
				<span class="badge badge-primary">Clash & Base64</span>
			</div>
		</div>
	</header>

	<!-- Subscriptions Card -->
	<section class="card">
		<div class="card-header">
			<h2 class="card-title">🔗 快捷订阅链接</h2>
		</div>

		<!-- Tab Navigation -->
		<div class="tab-nav">
			<button class="tab-btn active" onclick="switchTab('admin', event)">🔑 管理员全权订阅</button>
			<button class="tab-btn" onclick="switchTab('guest', event)">🛡️ 访客安全订阅 (防篡改/分享用)</button>
		</div>

		<!-- Admin Subscriptions Panel -->
		<div id="tab-admin" class="tab-panel">
			<!-- Link 1: Auto Adaptive -->
			<div class="link-row">
				<div class="link-info">
					<span class="link-name">🌐 智能自适应订阅 <small style="color:var(--text-muted);font-weight:normal;">(自动识别 Clash / v2rayN / Shadowrocket 等)</small></span>
				</div>
				<div class="link-input-group">
					<div class="link-text">${adminAutoUrl}</div>
					<div class="btn-group">
						<button class="btn btn-primary" onclick="copyText('${adminAutoUrl}')">📋 复制</button>
						<button class="btn" onclick="showQr('智能自适应订阅 (管理员)', '${adminAutoUrl}')">📱 二维码</button>
					</div>
				</div>
			</div>

			<!-- Link 2: Clash / Mihomo -->
			<div class="link-row">
				<div class="link-info">
					<span class="link-name">🐱 Clash / Mihomo 配置订阅 <small style="color:var(--text-muted);font-weight:normal;">(?clash 强制 YAML 格式)</small></span>
				</div>
				<div class="link-input-group">
					<div class="link-text">${adminClashUrl}</div>
					<div class="btn-group">
						<button class="btn btn-primary" onclick="copyText('${adminClashUrl}')">📋 复制</button>
						<a class="btn" href="${adminClashImport}" title="一键导入到本地 Clash 客户端">⚡ 一键导入</a>
						<button class="btn" onclick="showQr('Clash 订阅 (管理员)', '${adminClashUrl}')">📱 二维码</button>
					</div>
				</div>
			</div>

			<!-- Link 3: Base64 -->
			<div class="link-row">
				<div class="link-info">
					<span class="link-name">📦 Base64 通用订阅 <small style="color:var(--text-muted);font-weight:normal;">(?b64 适用于 v2rayN / v2rayNG / NekoBox)</small></span>
				</div>
				<div class="link-input-group">
					<div class="link-text">${adminB64Url}</div>
					<div class="btn-group">
						<button class="btn btn-primary" onclick="copyText('${adminB64Url}')">📋 复制</button>
						<button class="btn" onclick="showQr('Base64 订阅 (管理员)', '${adminB64Url}')">📱 二维码</button>
					</div>
				</div>
			</div>
		</div>

		<!-- Guest Subscriptions Panel -->
		<div id="tab-guest" class="tab-panel" style="display:none;">
			<div class="link-row">
				<div class="link-info">
					<span class="link-name">🌐 访客自适应订阅 <small style="color:var(--text-muted);font-weight:normal;">(只读节点，不可查看或编辑管理后台)</small></span>
				</div>
				<div class="link-input-group">
					<div class="link-text">${guestAutoUrl}</div>
					<div class="btn-group">
						<button class="btn btn-primary" onclick="copyText('${guestAutoUrl}')">📋 复制</button>
						<button class="btn" onclick="showQr('访客自适应订阅', '${guestAutoUrl}')">📱 二维码</button>
					</div>
				</div>
			</div>

			<div class="link-row">
				<div class="link-info">
					<span class="link-name">🐱 访客 Clash / Mihomo 订阅</span>
				</div>
				<div class="link-input-group">
					<div class="link-text">${guestClashUrl}</div>
					<div class="btn-group">
						<button class="btn btn-primary" onclick="copyText('${guestClashUrl}')">📋 复制</button>
						<a class="btn" href="${guestClashImport}">⚡ 一键导入</a>
						<button class="btn" onclick="showQr('访客 Clash 订阅', '${guestClashUrl}')">📱 二维码</button>
					</div>
				</div>
			</div>

			<div class="link-row">
				<div class="link-info">
					<span class="link-name">📦 访客 Base64 订阅</span>
				</div>
				<div class="link-input-group">
					<div class="link-text">${guestB64Url}</div>
					<div class="btn-group">
						<button class="btn btn-primary" onclick="copyText('${guestB64Url}')">📋 复制</button>
						<button class="btn" onclick="showQr('访客 Base64 订阅', '${guestB64Url}')">📱 二维码</button>
					</div>
				</div>
			</div>
		</div>
	</section>

	<!-- SUBCONFIG Section -->
	<section class="card">
		<div class="card-header">
			<h2 class="card-title">⚙️ Clash 规则转换配置 (SUBCONFIG)</h2>
		</div>
		<div class="form-group">
			<label class="form-label" for="subConfigInput">远程规则集 (.ini 配置文件链接)：</label>
			<input type="text" id="subConfigInput" class="input-text" value="${currentSubConfig}" placeholder="请输入 .ini 规则配置链接" />
			<div class="form-desc">支持自定义 ruleset 远程分流规则与 custom_proxy_group 策略组结构，生成 Clash 配置时将按此文件自动构建。</div>
		</div>
		<div class="form-group">
			<label class="form-label">快速预设规则集：</label>
			<select class="input-select" onchange="applyPreset(this.value)">
				<option value="">-- 选择常用预设规则集 (或在上方手动输入) --</option>
				<option value="https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/my.ini">🌟 个人专属配置 (my.ini - 包含 OpenAI/油管/奈飞/测速/地区分流)</option>
				<option value="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini">⚡ ACL4SSR 极简精简版 (Mini)</option>
				<option value="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini">🌍 ACL4SSR 多国家地区分组版 (MultiCountry)</option>
				<option value="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini">🛡️ ACL4SSR 全网去广告净化增强版 (AdblockPlus)</option>
			</select>
		</div>
	</section>

	<!-- GHPROXY Acceleration Section -->
	<section class="card">
		<div class="card-header">
			<h2 class="card-title">🚀 规则集加速与容灾中继 (GHPROXY)</h2>
			<span class="badge badge-success" id="ghProxyBadge">● 多源容灾保护</span>
		</div>
		<div class="form-group">
			<label class="form-label">加速策略模式：</label>
			<select class="input-select" id="ghProxySelect" onchange="onGhProxySelectChange(this.value)">
				<option value="worker">⚡ Worker 边缘中继与多源容灾池 (推荐，绝不断连，多源自动故障转移与边缘缓存)</option>
				<option value="https://gh-proxy.com/">🌐 gh-proxy.com 公共镜像</option>
				<option value="https://ghfast.top/">🌐 ghfast.top 备用镜像</option>
				<option value="https://ghproxy.net/">🌐 ghproxy.net 传统镜像</option>
				<option value="direct">🚫 直连 GitHub (无代理)</option>
				<option value="custom">🛠️ 自定义镜像前缀...</option>
			</select>
			<div class="form-desc">彻底解决单一第三方镜像（如 ghproxy.net）宕机导致 Clash 规则集下载失败问题。推荐 Worker 边缘中继模式：由 Cloudflare 全球边缘节点直连 GitHub，自动尝试多源镜像容灾池并缓存 24 小时。</div>
		</div>
		<div class="form-group" id="customGhProxyGroup" style="display:none;">
			<label class="form-label" for="ghProxyInput">自定义镜像/中继前缀：</label>
			<input type="text" id="ghProxyInput" class="input-text" value="${currentGhProxy}" placeholder="例如: https://gh-proxy.com/" />
		</div>
	</section>

	<!-- OVERRIDE Section -->
	<section class="card">
		<div class="card-header">
			<h2 class="card-title">🧩 Clash YAML 覆写配置 (OVERRIDE)</h2>
			<span class="badge badge-primary">● Clash Party 语义深度合并</span>
		</div>
		<div class="form-group">
			<label class="form-label" for="overrideInput">覆写配置文件链接 (YAML) 或留空禁用：</label>
			<input type="text" id="overrideInput" class="input-text" value="${currentOverride || ''}" placeholder="请输入 override.yaml 链接或留空禁用" />
			<div class="form-desc">支持 Clash Party 标准覆写语义 (+rules 前置分流、rules+ 追加、! 强制覆盖、DNS/TUN 深度合并)。服务端自动合并下发，无需在多台客户端设备重复配置。</div>
		</div>
		<div class="form-group">
			<label class="form-label">快速预设覆写配置：</label>
			<select class="input-select" onchange="applyOverridePreset(this.value)">
				<option value="">-- 选择常用覆写配置 (或在上方手动输入) --</option>
				<option value="https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/override.yaml">🌟 个人专属覆写 (增强 Fake-IP / 防 DNS 泄露 / TUN 栈模式 / +rules 自定义分流)</option>
				<option value="none">🚫 不使用覆写 (禁用)</option>
			</select>
		</div>
	</section>

	<!-- Content Management Card -->
	<section class="card">
		<div class="card-header">
			<h2 class="card-title">📝 节点与机场订阅列表 (LINK.txt)</h2>
			<div class="btn-group">
				<button class="btn" onclick="formatDeduplicate()" title="去除重复行并整理">✨ 去重整理</button>
				<button class="btn" onclick="clearEditor()" title="清空全部内容">🗑️ 清空</button>
			</div>
		</div>

		<div class="editor-header">
			<div class="editor-stats">
				<span class="editor-stat-item" id="nodeCount">📦 节点链接: 0 行</span>
				<span class="editor-stat-item" id="charCount">🔤 字符数: 0</span>
			</div>
		</div>

		<textarea class="editor-textarea" id="content" placeholder="每行填写一个自建节点链接 (vless://, vmess://, trojan://, ss://, hy2://) 或机场远程订阅链接 (支持 Base64 / Clash YAML / 明文链接)..." oninput="updateStats()">${content}</textarea>

		<div class="action-bar">
			<button class="save-btn" id="saveBtn" onclick="saveData()">
				<span id="saveBtnText">💾 保存所有配置</span>
			</button>
			<span id="saveStatus" style="font-size:13px;"></span>
		</div>
	</section>
</div>

<!-- Modal QR Code -->
<div class="modal-backdrop" id="qrModal" onclick="closeQr(event)">
	<div class="modal-content" onclick="event.stopPropagation()">
		<h3 class="modal-title" id="qrTitle">二维码订阅</h3>
		<div class="qr-wrapper">
			<div id="qrcode"></div>
		</div>
		<p style="font-size:12px;color:var(--text-muted);margin:0 0 14px 0;">使用手机客户端扫码可快速导入订阅</p>
		<button class="modal-close" onclick="closeQr()">关闭</button>
	</div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
<script>
let qrcodeInstance = null;

function switchTab(tab, event) {
	document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
	if (event && event.currentTarget) event.currentTarget.classList.add('active');
	document.getElementById('tab-admin').style.display = tab === 'admin' ? 'block' : 'none';
	document.getElementById('tab-guest').style.display = tab === 'guest' ? 'block' : 'none';
}

function showToast(msg, duration = 2000) {
	const t = document.getElementById('toast');
	t.textContent = msg;
	t.classList.add('show');
	setTimeout(() => t.classList.remove('show'), duration);
}

function copyText(text) {
	if (navigator.clipboard && window.isSecureContext) {
		navigator.clipboard.writeText(text).then(() => {
			showToast('✅ 已复制到剪贴板');
		}).catch(() => fallbackCopy(text));
	} else {
		fallbackCopy(text);
	}
}

function fallbackCopy(text) {
	const ta = document.createElement('textarea');
	ta.value = text;
	document.body.appendChild(ta);
	ta.select();
	document.execCommand('copy');
	document.body.removeChild(ta);
	showToast('✅ 已复制到剪贴板');
}

function showQr(title, text) {
	document.getElementById('qrTitle').textContent = title;
	const container = document.getElementById('qrcode');
	container.innerHTML = '';
	qrcodeInstance = new QRCode(container, {
		text: text,
		width: 200,
		height: 200,
		colorDark: "#000000",
		colorLight: "#ffffff",
		correctLevel: QRCode.CorrectLevel.M
	});
	document.getElementById('qrModal').classList.add('show');
}

function closeQr(e) {
	if (!e || e.target.id === 'qrModal' || e.target.classList.contains('modal-close')) {
		document.getElementById('qrModal').classList.remove('show');
	}
}

function applyPreset(val) {
	if (val) {
		document.getElementById('subConfigInput').value = val;
		showToast('已加载预设规则配置');
	}
}

function applyOverridePreset(val) {
	document.getElementById('overrideInput').value = val === 'none' ? '' : val;
	showToast(val && val !== 'none' ? '已加载预设覆写配置' : '已选择禁用覆写');
}

function updateStats() {
	const text = document.getElementById('content').value;
	const lines = text.split('\\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
	document.getElementById('nodeCount').textContent = '📦 有效节点/链接: ' + lines.length + ' 条';
	document.getElementById('charCount').textContent = '🔤 字符数: ' + text.length;
}

function formatDeduplicate() {
	const ta = document.getElementById('content');
	const lines = ta.value.split('\\n').map(l => l.trim()).filter(Boolean);
	const unique = Array.from(new Set(lines));
	const removed = lines.length - unique.length;
	ta.value = unique.join('\\n');
	updateStats();
	showToast(removed > 0 ? '✨ 已去除 ' + removed + ' 个重复项' : '✨ 无重复项');
}

function clearEditor() {
	if (confirm('确定要清空编辑框中的全部内容吗？')) {
		document.getElementById('content').value = '';
		updateStats();
		showToast('已清空');
	}
}

function onGhProxySelectChange(val) {
	const customGroup = document.getElementById('customGhProxyGroup');
	const input = document.getElementById('ghProxyInput');
	const badge = document.getElementById('ghProxyBadge');
	if (val === 'custom') {
		customGroup.style.display = 'block';
		badge.textContent = '● 自定义代理';
		badge.className = 'badge badge-primary';
	} else {
		customGroup.style.display = 'none';
		input.value = val;
		if (val === 'worker') {
			badge.textContent = '● 多源容灾保护';
			badge.className = 'badge badge-success';
		} else if (val === 'direct') {
			badge.textContent = '● 直连模式';
			badge.className = 'badge';
		} else {
			badge.textContent = '● 镜像加速';
			badge.className = 'badge badge-primary';
		}
	}
}

(function initGhProxy() {
	const current = ${JSON.stringify(currentGhProxy)};
	const select = document.getElementById('ghProxySelect');
	const input = document.getElementById('ghProxyInput');
	input.value = current;
	let matched = false;
	for (let opt of select.options) {
		if (opt.value === current) {
			select.value = current;
			matched = true;
			break;
		}
	}
	if (!matched) {
		select.value = 'custom';
		document.getElementById('customGhProxyGroup').style.display = 'block';
	}
	onGhProxySelectChange(select.value);
})();

function saveData() {
	const btn = document.getElementById('saveBtn');
	const btnText = document.getElementById('saveBtnText');
	const statusElem = document.getElementById('saveStatus');
	const linkVal = document.getElementById('content').value;
	const subConfigVal = document.getElementById('subConfigInput').value.trim();
	const ghProxyVal = document.getElementById('ghProxyInput').value.trim() || 'worker';
	const overrideVal = document.getElementById('overrideInput').value.trim();

	btn.disabled = true;
	btnText.textContent = '⏳ 保存中...';
	statusElem.textContent = '';

	const payload = {
		link: linkVal,
		subConfig: subConfigVal,
		ghProxy: ghProxyVal,
		override: overrideVal
	};

	fetch(window.location.href, {
		method: 'POST',
		body: JSON.stringify(payload),
		headers: { 'Content-Type': 'application/json' }
	}).then(res => {
		if (res.ok) {
			showToast('🎉 保存成功！订阅已即时生效');
			statusElem.textContent = '✅ 保存成功 (' + new Date().toLocaleTimeString() + ')';
			statusElem.style.color = '#10b981';
		} else {
			throw new Error('HTTP ' + res.status);
		}
	}).catch(err => {
		showToast('❌ 保存失败: ' + err.message);
		statusElem.textContent = '❌ 保存失败: ' + err.message;
		statusElem.style.color = '#ef4444';
	}).finally(() => {
		btn.disabled = false;
		btnText.textContent = '💾 保存所有配置';
	});
}

// 初始化统计
updateStats();
</script>
</body>
</html>`;

	return new Response(html, {
		headers: { "Content-Type": "text/html;charset=utf-8" }
	});
}
