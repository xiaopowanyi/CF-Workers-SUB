# ⚙ 自建汇聚订阅 CF-Workers-SUB（原生内置转换引擎版）

![自建汇聚订阅 CF-Workers-SUB](./sub.png)

这是一个将多个节点和订阅合并为单一链接的工具。**内置原生轻量级转换引擎，完全无需依赖任何外部第三方后端转换服务（如 subconverter）**，毫秒级响应，彻底杜绝节点信息泄露与超时问题。

> [!TIP]
> **🚀 原生内置转换**：本版本直接在 Cloudflare Worker 本地完成所有节点解析、订阅聚合、规则分组与 Clash / Base64 配置生成，零外部网络中转，隐私安全 100% 保障，节点数量庞大时也能即刻响应！

---

## 🛠 功能特点

1. **原生 Clash (Mihomo) 配置生成：** 
   - 自动生成标准规范的 Clash / Mihomo YAML 配置文件。
   - 包含科学策略组：`节点选择`、`♻️ 自动选择`（url-test 延迟选优）、`🔯 故障转移`、`全球直连`、`全球拦截`、`🐟 漏网之鱼` 等。
   - **支持自定义规则配置文件 (SUBCONFIG)**：支持在后台管理页面自由选择预设或填写任何远程 `.ini` 规则集链接（如 `my.ini` 或 ACL4SSR 系列），自动生成对应的 `rule-providers` 与分流规则。
2. **原生 Base64 订阅生成：**
   - 将所有汇聚的自建节点和远程订阅解码后重新整合成纯净的 Base64 订阅链接，兼容 v2rayN、v2rayNG、Shadowrocket、NekoBox 等。
3. **真实节点参数保真（不预设多余默认值）：**
   - 严格根据节点链接填写的参数生成配置，不强制注入 `client-fingerprint`、`skip-cert-verify` 等默认字段，把控制权还给客户端自行处理默认策略。
   - 支持通过 `SCV` 环境变量控制证书验证全局策略。
4. **多格式与多协议深度支持：**
   - 协议支持：VLESS（含 Reality / XTLS / WS / gRPC）、VMess、Trojan、Shadowsocks (SS)、ShadowsocksR (SSR)、Hysteria 2 (Hy2)、TUIC 等。
   - 订阅聚合：支持聚合明文节点、Base64 订阅，以及**直接从远程 Clash YAML 订阅中提取 proxies 节点**。
5. **便捷的 Web 可视化管理面板：**
   - 绑定 KV 后，访问 `/auto`（或自定义 TOKEN）即可进入管理面板，在线编辑保存节点列表与 SUBCONFIG 规则链接，并自动生成快捷二维码。

---

## 📦 部署方法

### 方式一：Cloudflare Worker 快速部署（推荐）

1. 在 Cloudflare Worker 控制台中创建一个新的 Worker。
2. 将项目根目录下的 [_worker.js](file:///_worker.js) 内容完整复制并粘贴到 Worker 代码编辑器中保存并部署。
3. （可选）在 Worker 设置中绑定一个名为 `KV` 的 KV 命名空间，即可启用 Web 在线编辑后台。
4. 访问 `https://your-worker.workers.dev/auto` 即可开始使用！

### 方式二：Cloudflare Pages 部署

1. Fork 本项目到您的 GitHub 仓库。
2. 在 Cloudflare 控制台选择 Pages -> 连接到 Git，选择本项目进行部署。
3. 绑定自定义域并在环境变量或 KV 绑定设置即可。

---

## 📋 环境变量说明

| 变量名 | 示例 | 必填 | 备注 | 
|---|---|---|---|
| `TOKEN` | `auto` | ✅ | 快速订阅与后台管理的访问凭证，例如 `/auto` | 
| `GUEST` / `GUESTTOKEN` | `visitor123` | ❌ | 访客订阅凭证，只允许获取订阅，无法查看与编辑后台配置 | 
| `SUBCONFIG` | `https://raw.githubusercontent.com/xiaopowanyi/Base/refs/heads/main/my.ini` | ❌ | Clash 规则集配置文件链接（也可直接在 Web 后台在线填写保存） |
| `LINK` | `vless://... \n vmess://...` | ❌ | 节点链接与订阅链接列表（未绑定 KV 时使用环境变量作为数据源） |
| `LINKSUB` | `https://sub1.com \n https://sub2.com` | ❌ | 远程订阅链接列表 |
| `SUBNAME` | `CF-Workers-SUB` | ❌ | 导出的订阅与文件名称 |
| `SUBUPTIME` | `6` | ❌ | 客户端订阅自动更新时间间隔（小时） |
| `SCV` | `false` | ❌ | 是否跳过 TLS 证书验证（默认 `false` 保障安全；自签名证书可设为 `true`） |
| `TGTOKEN` | `6894123456:XXXXXX` | ❌ | Telegram 访问通知机器人 Token |
| `TGID` | `6946912345` | ❌ | 接收 TG 通知的账户或群组数字 ID |

---

## 🔗 客户端订阅方式

- **自适应订阅（推荐）**：`https://你的域名/auto`（自动根据客户端 UA 返回 Clash 配置或 Base64 订阅）
- **强制 Clash 订阅**：`https://你的域名/auto?clash`
- **强制 Base64 订阅**：`https://你的域名/auto?b64`
- **临时指定规则配置**：`https://你的域名/auto?clash&config=https://.../custom.ini`
