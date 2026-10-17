# zray TODO

## Upstream resolution and connect backoff (deferred 2026-10-17)

Current behaviour: `main.zig` resolves `server` once at startup (blocking) and
exits if that fails; `conn.zig` connects every client to the cached IP with no
failure accounting.

Problems:
- Server IP change (migration / DDNS) is never picked up until a manual restart.
- Boot before DNS is usable -> process exits -> procd respawns every 5 s.
- Only the first A record is used; no failover.
- Upstream down -> every incoming client still does a full connect + waits for
  `handshake_timeout_s` (15 s), occupying a 92 KiB slot; 64 slots fill up with
  doomed connections, then `conn table full`.

Plan (~100-200 lines):
- `Upstream` state in `Loop`: `addrs: [4]SockAddr`, `cur`, `resolved_at`,
  `fail_streak`, `backoff_until`.
- Periodic re-resolve from the 1 s tick (`resolve_interval_s`, default 300).
  Must be non-blocking: send a UDP A query to the nameserver from
  `/etc/resolv.conf` on an epoll fd; minimal DNS response parser.
- On connect / handshake / `CertificateRejected` failure: `fail_streak += 1`,
  rotate to next A record; `fail_streak >= 3` triggers re-resolve;
  `backoff = min(1 s << streak, max_backoff_s)`.
- While in backoff: reject clients immediately (RST / SOCKS reply 0x04), do not
  occupy a slot.
- `handshake_complete` resets streak and backoff.
- Startup resolve failure no longer exits; start listening with backoff set.
- Split `connect_timeout_s` (default 5) out of `handshake_timeout_s`.
- Config: `resolve_interval_s`, `connect_timeout_s`, `max_backoff_s`, all
  optional with sane defaults.

Note: the REALITY server's domain must stay out of chinadns-ng's gfwlist, otherwise its
DoT lookup is REDIRECTed to zray itself and boot deadlocks. Re-resolve logic
should log loudly when resolution fails for this reason.

## Other open items

- Log level switch (`"log": "warn"`): only errors and abnormal close reasons.
- Transparent UDP (TPROXY): `kmod-nft-tproxy`, `ip rule` + table, nft `tproxy to`,
  `IP_TRANSPARENT` + `recvmsg(IP_RECVORIGDSTADDR)`. Low priority: server drops
  UDP payloads >= ~600 B, so QUIC would not work anyway.
- Server-side UDP size limit (~600 B): check freedom outbound fragment / cloud
  provider UDP policy. Confirmed not a client issue (official xray same).
- `compress_certificate` is offered on the outer hello; must be disabled if the
  REALITY server is ever replaced by a non-Go implementation.
- ML-KEM: implemented, enabled, server negotiates `x25519_ml_kem768`.
- SOCKS5 UDP fragmentation: no real client uses it, skip.
- Config hot reload.
- Update `/etc/chinadns/gfwlist.txt` on mir (has `twitter.com`, lacks `x.com`).
