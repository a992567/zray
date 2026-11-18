# UDP 分组与失败即关闭

这是本 fork 的自用说明，不是上游已合并的行为。只描述代码实际做了什么。

## 行为

SOCKS5 `UDP ASSOCIATE` 不再在看到目标之前就连接 `default`。关联先进入等待，第一条能归组的数据报决定唯一的上游：

- 目标是域名：和 TCP 一样按 `rules` 选组。命中的组只在组内故障切换。组里全都失败、都在 `fail_backoff_s` 内，或者都不是带 Vision 的 TCP 节点时，关联关闭，不会改走 `default`。
- 目标是 IPv4 或 IPv6：域名规则对不上。`udp_unknown` 为 `default`（缺省，旧配置不变）时，这条关联用默认组。为 `reject` 时丢掉该数据报，不打开任何出站。
- 一条关联只有一条 XUDP 上游。之后目标如果属于别的组，数据报丢掉，不从这个隧道送出，也不把隧道改到另一组。

`network: "ws"` 或没有 Vision 的节点不能带 UDP。出口组如果全是这种节点，命中该组的 UDP 会失败并关闭，同样不会退回默认组。TCP 不受影响。

## 代码保证不了的事

- **没有透明 UDP。** `redirect` 只对 TCP 的 netfilter `REDIRECT` 生效。没进 SOCKS 的 UDP 仍然由系统路由直接发出，zray 看不到。
- **IP 和 QUIC 认不出“这是哪个域名”。** 这里不做 DNS 应答缓存，也不解析 QUIC Initial。客户端如果先在本地把名字解析成 IP，再把 IP 放进 UDP 头，规则不会命中。
- **一条 SOCKS UDP 关联通常被客户端拿来发所有目的地。** 第一条数据报把关联锁死后，另一组的包会被丢。想让受保护的域名走出口组，这条关联的第一条可归组数据报就得是那个域名；否则该包被丢，而不是悄悄改走默认组。
- **大约 600 字节以上的 UDP 仍可能被服务器出口丢掉。** 这不是这次改动能解决的。
- **整机不泄漏**还要靠路由器自己的防火墙和 DNS，见下。

## 路由器上要另外做的事

1. 受保护的名字必须作为域名到达 zray（SOCKS 远端解析，或 UDP 头里就是域名）。本地解析后再转发 IP，应用层无法把它们认成规则。
2. 若要求这些目的地在出口组不可用时也不能从日本默认节点或国内直连出去：防火墙应丢弃没有进入 zray 的相应 UDP，而不是指望本程序拦截。透明 UDP（TPROXY）没有实现。
3. `udp_unknown: "reject"` 会丢掉所有 IP 目标，包括发往 `8.8.8.8` 这类地址的 DNS。需要 DNS 时，让它走未命中规则的域名，或把该字段留为 `default`。留为 `default` 时，无法归类的 IP 仍走默认组，这是有意保留的旧行为。
4. 示例 [config.example.udp-guard.json](../config.example.udp-guard.json) 只有占位地址和占位密钥，不能直接拿去连接真实服务。其中出口是带 Vision 的 TCP，因此示例路径可以承载 UDP。若真实出口是 WebSocket，命中规则的 UDP 会失败关闭。

## 安装与回滚

不要在这台开发机上安装，也不要写到路由器。若以后自行替换设备上的二进制：

- 新程序能读没有 `udp_unknown` 的旧配置，缺省等于 `"default"`。
- 旧程序会拒绝带 `udp_unknown` 的配置（未知字段是错误）。回滚二进制时先删掉这个字段，或恢复旧配置文件。
- 回滚就是换回替换前的二进制和配置。本次没有改默认分支，也没有在任何设备上启动进程。

## 本次候选构建

对比基线是本分支上一条提交 `bd01107`（只有 TCP 回归）。两边都用 Zig 0.17.0、`--release -Doptimize=small`，已 strip。mipsel 另加 `-Dtarget=mipsel-linux-musl -Dcpu=mips32r2+soft_float`。二进制不在 git 里。

| 文件 | 字节 | 相对基线 |
|---|---:|---:|
| x86_64 | 502048 | +2816（基线 499232） |
| mipsel | 902848 | +2176（基线 900672） |

SHA-256：

```
66969fb21d60f3f4bc1e6dd355c5ec0dc2eab38666c70245d000d943ddb622b6  zray-0.5.0-udpguard-mipsel
e7ba6534bb996da14c79b9cd1bca809f61d0f3d1c0a5237d20dbb9fa52c28c23  zray-0.5.0-udpguard-x86_64
b92c0b0cf59fb97d66947f8e80f08d35d54f86d56cb65fa1e2a7181805332448  config.example.udp-guard.json
```

版本号仍是 `0.5.0`。这只是候选文件名，不是一次发布。
