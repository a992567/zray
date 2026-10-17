//! One proxied connection: SOCKS5 client <-> REALITY/VLESS/Vision upstream.
//!
//! Non-blocking, single-threaded, driven by `Loop`. All buffers are fixed
//! size members so a connection's memory footprint is a compile-time constant
//! (`@sizeOf(Conn)`), and the pool is allocated once at startup.
//!
//! Data path (per direction) is strictly "read one chunk -> transform -> queue
//! -> drain". A side is only read when its outgoing queue is empty, which
//! gives natural back-pressure without any dynamic allocation.

const std = @import("std");
const mem = std.mem;
const tls = std.crypto.tls;
const sys = @import("sys.zig");
const client = @import("../tls/client.zig");
const hello = @import("../tls/hello.zig");
const record = @import("../tls/record.zig");
const reality = @import("../tls/reality.zig");
const vless = @import("../proxy/vless.zig");
const vision = @import("../proxy/vision.zig");
const socks5 = @import("../proxy/socks5.zig");
const fingerprint = @import("../tls/fingerprint.zig");

const max_rec = tls.max_ciphertext_record_len;
/// Largest chunk read from the SOCKS client per event (xray uses 8 KiB).
const client_chunk = 8192;

pub const Config = struct {
    server_addr: sys.SockAddr,
    sni: []const u8,
    reality: reality.Config,
    uuid: [16]u8,
    handshake_timeout_s: u64 = 15,
    idle_timeout_s: u64 = 600,
    /// Per-socket SO_RCVBUF / SO_SNDBUF; 0 = kernel default.
    sock_buf: i32 = 0,
};

pub const Side = enum(u1) { client = 0, upstream = 1 };

pub const State = enum {
    free,
    socks_greeting,
    socks_request,
    connecting,
    tls_handshake,
    relay,
};

pub const Conn = struct {
    state: State = .free,
    slot: u32,
    /// Incremented on every reuse so stale epoll events can be ignored.
    gen: u32 = 0,
    client_fd: sys.fd_t = -1,
    up_fd: sys.fd_t = -1,
    client_ev: u32 = 0,
    up_ev: u32 = 0,
    last_active: u64 = 0,
    client_eof: bool = false,
    /// Upstream finished sending; close once `c_out` is drained.
    up_eof: bool = false,

    // client -> upstream
    cin: [client_chunk]u8 = undefined,
    cin_len: usize = 0,
    up_out: [max_rec]u8 = undefined,
    up_out_off: usize = 0,
    up_out_len: usize = 0,

    // upstream -> client
    uin: [max_rec]u8 = undefined,
    uin_len: usize = 0,
    c_out: [2 * max_rec]u8 = undefined,
    c_out_off: usize = 0,
    c_out_len: usize = 0,

    // protocol state
    tls: client.Client = undefined,
    hs_buf: [8192]u8 = undefined,
    rl: reality.Reality = undefined,
    vstate: vision.State = undefined,
    padder: vision.Padder = undefined,
    unpadder: vision.Unpadder = undefined,
    got_resp_hdr: bool = false,
    target_kind: enum { ipv4, ipv6, domain } = .domain,
    target_buf: [255]u8 = undefined,
    target_len: u8 = 0,
    target_port: u16 = 0,

    pub fn token(c: *const Conn, side: Side) u64 {
        return (@as(u64, c.gen) << 33) | (@as(u64, c.slot) << 1) | @backingInt(side);
    }

    /// Both directions switched to Vision direct copy: outer TLS is gone.
    fn fullyDirect(c: *const Conn) bool {
        return c.padder.direct and c.unpadder.direct;
    }

    fn consumeClient(c: *Conn, n: usize) void {
        mem.copyForwards(u8, c.cin[0 .. c.cin_len - n], c.cin[n..c.cin_len]);
        c.cin_len -= n;
    }
};

pub const Loop = struct {
    ep: sys.fd_t,
    cfg: *const Config,
    conns: []Conn,
    csprng: std.Random.DefaultCsprng,
    active: usize = 0,

    pub fn init(ep: sys.fd_t, cfg: *const Config, conns: []Conn) Loop {
        var seed: [32]u8 = undefined;
        sys.randomBytes(&seed);
        for (conns, 0..) |*c, i| c.* = .{ .slot = @intCast(i) };
        return .{ .ep = ep, .cfg = cfg, .conns = conns, .csprng = std.Random.DefaultCsprng.init(seed) };
    }

    // ---- lifecycle -----------------------------------------------------------

    pub fn accept(l: *Loop, fd: sys.fd_t) void {
        const c = l.findFree() orelse {
            sys.log("conn table full, dropping client", .{});
            sys.close(fd);
            return;
        };
        c.gen +%= 1;
        c.state = .socks_greeting;
        c.client_fd = fd;
        c.up_fd = -1;
        c.client_ev = 0;
        c.up_ev = 0;
        c.cin_len = 0;
        c.up_out_off = 0;
        c.up_out_len = 0;
        c.uin_len = 0;
        c.c_out_off = 0;
        c.c_out_len = 0;
        c.client_eof = false;
        c.up_eof = false;
        c.got_resp_hdr = false;
        c.last_active = sys.monotonicSeconds();
        sys.setNoDelay(fd);
        if (l.cfg.sock_buf > 0) sys.setBufferSizes(fd, l.cfg.sock_buf, l.cfg.sock_buf);
        sys.epollAdd(l.ep, fd, sys.EPOLL.IN | sys.EPOLL.RDHUP, c.token(.client)) catch {
            sys.close(fd);
            c.state = .free;
            return;
        };
        c.client_ev = sys.EPOLL.IN | sys.EPOLL.RDHUP;
        l.active += 1;
    }

    fn findFree(l: *Loop) ?*Conn {
        for (l.conns) |*c| if (c.state == .free) return c;
        return null;
    }

    pub fn close(l: *Loop, c: *Conn, why: []const u8) void {
        if (c.state == .free) return;
        sys.log("[{d}] close: {s}", .{ c.slot, why });
        if (c.client_fd >= 0) {
            sys.epollDel(l.ep, c.client_fd);
            sys.close(c.client_fd);
            c.client_fd = -1;
        }
        if (c.up_fd >= 0) {
            sys.epollDel(l.ep, c.up_fd);
            sys.close(c.up_fd);
            c.up_fd = -1;
        }
        c.state = .free;
        l.active -= 1;
    }

    /// Close connections that have been idle too long.
    pub fn sweep(l: *Loop) void {
        const now = sys.monotonicSeconds();
        for (l.conns) |*c| {
            if (c.state == .free) continue;
            const limit = if (c.state == .relay) l.cfg.idle_timeout_s else l.cfg.handshake_timeout_s;
            if (now - c.last_active > limit) l.close(c, "timeout");
        }
    }

    /// Dispatch one epoll event.
    pub fn handle(l: *Loop, tok: u64, events: u32) void {
        const slot: usize = @intCast((tok >> 1) & 0xffff_ffff);
        const gen: u32 = @intCast(tok >> 33);
        const side: Side = @fromBackingInt(@as(u1, @intCast(tok & 1)));
        if (slot >= l.conns.len) return;
        const c = &l.conns[slot];
        if (c.state == .free or c.gen != gen) return; // stale
        c.last_active = sys.monotonicSeconds();

        const fail = events & (sys.EPOLL.ERR | sys.EPOLL.HUP) != 0;
        switch (side) {
            .client => {
                if (events & sys.EPOLL.OUT != 0) l.flushClient(c) catch |e| return l.close(c, @errorName(e));
                if (events & (sys.EPOLL.IN | sys.EPOLL.RDHUP) != 0) l.readClient(c) catch |e| return l.close(c, @errorName(e));
                if (fail and c.state != .free) return l.close(c, "client hup");
            },
            .upstream => {
                if (events & sys.EPOLL.OUT != 0) l.upstreamWritable(c) catch |e| return l.close(c, @errorName(e));
                if (events & (sys.EPOLL.IN | sys.EPOLL.RDHUP) != 0) l.readUpstream(c) catch |e| switch (e) {
                    error.UpstreamEof, error.UpstreamCloseNotify => return l.upstreamDone(c),
                    else => return l.close(c, @errorName(e)),
                };
                if (fail and c.state != .free) return l.upstreamDone(c);
            },
        }
        if (c.state != .free) l.updateInterest(c);
    }

    /// Upstream has nothing more to send: deliver what is queued, then close.
    fn upstreamDone(l: *Loop, c: *Conn) void {
        if (c.c_out_len == 0) return l.close(c, "upstream eof");
        c.up_eof = true;
        if (c.up_fd >= 0) {
            sys.epollDel(l.ep, c.up_fd);
            sys.close(c.up_fd);
            c.up_fd = -1;
        }
        l.updateInterest(c);
    }

    /// Derive epoll interest sets from buffer state. Read a side only when the
    /// queue feeding the other side is empty.
    fn updateInterest(l: *Loop, c: *Conn) void {
        var cev: u32 = sys.EPOLL.RDHUP;
        if (c.c_out_len > 0) cev |= sys.EPOLL.OUT;
        if (!c.client_eof and c.up_out_len == 0 and c.cin_len < c.cin.len) cev |= sys.EPOLL.IN;
        if (cev != c.client_ev) {
            sys.epollMod(l.ep, c.client_fd, cev, c.token(.client)) catch {};
            c.client_ev = cev;
        }
        if (c.up_fd < 0) return;
        var uev: u32 = sys.EPOLL.RDHUP;
        if (c.state == .connecting or c.up_out_len > 0) uev |= sys.EPOLL.OUT;
        if (c.state != .connecting and c.c_out_len == 0) uev |= sys.EPOLL.IN;
        if (uev != c.up_ev) {
            sys.epollMod(l.ep, c.up_fd, uev, c.token(.upstream)) catch {};
            c.up_ev = uev;
        }
    }

    // ---- client side ---------------------------------------------------------

    fn readClient(l: *Loop, c: *Conn) !void {
        if (c.client_eof) return; // RDHUP can be reported more than once
        if (c.up_out_len > 0 or c.cin_len == c.cin.len) return; // back-pressure
        const n = sys.read(c.client_fd, c.cin[c.cin_len..]) catch |e| switch (e) {
            error.WouldBlock => return,
            else => return e,
        };
        if (n == 0) {
            c.client_eof = true;
            // Nothing more to forward: let upstream finish, then close on its EOF.
            if (c.state == .relay and c.cin_len == 0 and c.up_out_len == 0) {
                if (c.fullyDirect()) sys.shutdownWrite(c.up_fd) else {
                    const rec = c.tls.close(&c.up_out) catch |e| {
                        sys.log("[{d}] tls close: {s} (tls state {s})", .{ c.slot, @errorName(e), @tagName(c.tls.state) });
                        return error.TlsClose;
                    };
                    c.up_out_off = 0;
                    c.up_out_len = rec.len;
                    try l.flushUpstream(c);
                }
            } else if (c.state != .relay) return error.ClientClosedEarly;
            return;
        }
        c.cin_len += n;
        try l.processClient(c);
    }

    fn processClient(l: *Loop, c: *Conn) !void {
        switch (c.state) {
            .socks_greeting => {
                const used = (socks5.parseGreeting(c.cin[0..c.cin_len]) catch {
                    l.queueClient(c, &socks5.greeting_reject);
                    return error.SocksGreeting;
                }) orelse return;
                c.consumeClient(used);
                l.queueClient(c, &socks5.greeting_reply);
                c.state = .socks_request;
                try l.flushClient(c);
                if (c.cin_len > 0) try l.processClient(c);
            },
            .socks_request => {
                const req = (socks5.parseRequest(c.cin[0..c.cin_len]) catch |e| {
                    l.queueClient(c, &socks5.replyForError(e));
                    l.flushClient(c) catch {};
                    return error.SocksRequest;
                }) orelse return;
                switch (req.address) {
                    .ipv4 => |a| {
                        c.target_kind = .ipv4;
                        c.target_buf[0..4].* = a;
                        c.target_len = 4;
                    },
                    .ipv6 => |a| {
                        c.target_kind = .ipv6;
                        c.target_buf[0..16].* = a;
                        c.target_len = 16;
                    },
                    .domain => |d| {
                        c.target_kind = .domain;
                        @memcpy(c.target_buf[0..d.len], d);
                        c.target_len = @intCast(d.len);
                    },
                }
                c.target_port = req.port;
                c.consumeClient(req.len);
                // Reply right away (like xray) so the client starts its own TLS
                // handshake while we connect upstream; its bytes queue in `cin`.
                l.queueClient(c, &socks5.reply(.succeeded));
                try l.flushClient(c);
                try l.connectUpstream(c);
            },
            .connecting, .tls_handshake => {}, // buffer in cin until the tunnel is up
            .relay => try l.forwardClient(c),
            .free => unreachable,
        }
    }

    /// Encode everything buffered in `cin` for the upstream and start writing.
    fn forwardClient(l: *Loop, c: *Conn) !void {
        if (c.cin_len == 0 or c.up_out_len > 0) return;
        const data = c.cin[0..c.cin_len];
        if (c.padder.direct) {
            @memcpy(c.up_out[0..data.len], data);
            c.up_out_len = data.len;
        } else {
            var padded_buf: [client_chunk + 2 * vision.max_overhead]u8 = undefined;
            const padded = c.padder.pad(data, &padded_buf) catch return error.VisionPad;
            const rec = c.tls.encrypt(padded, &c.up_out) catch return error.TlsEncrypt;
            c.up_out_len = rec.len;
            if (c.padder.direct) sys.log("[{d}] vision uplink -> direct", .{c.slot});
        }
        c.up_out_off = 0;
        c.cin_len = 0;
        try l.flushUpstream(c);
    }

    fn queueClient(_: *Loop, c: *Conn, bytes: []const u8) void {
        if (c.c_out_len + bytes.len > c.c_out.len) return; // caller sizes guarantee this never trips
        if (c.c_out_off > 0 and c.c_out_len == 0) c.c_out_off = 0;
        @memcpy(c.c_out[c.c_out_off + c.c_out_len ..][0..bytes.len], bytes);
        c.c_out_len += bytes.len;
    }

    fn flushClient(l: *Loop, c: *Conn) !void {
        while (c.c_out_len > 0) {
            const n = sys.write(c.client_fd, c.c_out[c.c_out_off..][0..c.c_out_len]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            c.c_out_off += n;
            c.c_out_len -= n;
        }
        c.c_out_off = 0;
        if (c.up_eof) return error.Done;
        // Queue drained: records still buffered in uin can now be processed.
        if (c.uin_len > 0 and c.state == .relay and !c.unpadder.direct) {
            try processRecords(c);
            if (c.c_out_len > 0) try l.flushClient(c);
        }
    }

    // ---- upstream side -------------------------------------------------------

    fn connectUpstream(l: *Loop, c: *Conn) !void {
        const fd = try sys.tcpSocket(l.cfg.server_addr.family());
        sys.setNoDelay(fd);
        if (l.cfg.sock_buf > 0) sys.setBufferSizes(fd, l.cfg.sock_buf, l.cfg.sock_buf);
        c.up_fd = fd;
        c.state = .connecting;
        const immediate = sys.connect(fd, &l.cfg.server_addr) catch |e| return e;
        const ev: u32 = sys.EPOLL.OUT | sys.EPOLL.RDHUP;
        try sys.epollAdd(l.ep, fd, ev, c.token(.upstream));
        c.up_ev = ev;
        if (immediate) try l.startTls(c);
    }

    fn upstreamWritable(l: *Loop, c: *Conn) !void {
        if (c.state == .connecting) {
            try sys.connectResult(c.up_fd);
            try l.startTls(c);
            return;
        }
        try l.flushUpstream(c);
    }

    fn startTls(l: *Loop, c: *Conn) !void {
        c.state = .tls_handshake;
        var entropy: [64]u8 = undefined;
        sys.randomBytes(&entropy);
        c.rl = reality.Reality.init(l.cfg.reality, sys.realtimeSeconds());
        c.tls = client.Client.init(.{
            .entropy = entropy,
            .verifier = c.rl.verifier(),
            .handshake_buf = &c.hs_buf,
        });
        c.vstate = vision.State.init(l.cfg.uuid);
        c.padder = vision.Padder.init(&c.vstate, l.csprng.random());
        c.unpadder = vision.Unpadder.init(&c.vstate);

        const zero_sid: [32]u8 = @splat(0);
        const ks = [_]hello.KeyShareEntry{.{ .group = .x25519, .public_key = c.tls.publicKey() }};
        const exts = fingerprint.chromeExtensions(l.cfg.sni, &ks);
        const first = c.tls.clientHello(&c.up_out, .{
            .random = undefined,
            .session_id = &zero_sid,
            .cipher_suites = &fingerprint.chrome_suites,
            .extensions = &exts,
        }, c.rl.helloHook()) catch return error.ClientHello;
        if (c.rl.err != null) return error.RealityHook;
        c.up_out_off = 0;
        c.up_out_len = first.len;
        try l.flushUpstream(c);
    }

    fn flushUpstream(_: *Loop, c: *Conn) !void {
        while (c.up_out_len > 0) {
            const n = sys.write(c.up_fd, c.up_out[c.up_out_off..][0..c.up_out_len]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            c.up_out_off += n;
            c.up_out_len -= n;
        }
        c.up_out_off = 0;
    }

    fn readUpstream(l: *Loop, c: *Conn) !void {
        if (c.c_out_len > 0) return; // back-pressure
        if (c.state == .relay and c.unpadder.direct) {
            // Raw inner stream: straight copy.
            const n = sys.read(c.up_fd, c.c_out[0..max_rec]) catch |e| switch (e) {
                error.WouldBlock => return,
                else => return e,
            };
            if (n == 0) return error.UpstreamEof;
            c.c_out_off = 0;
            c.c_out_len = n;
            try l.flushClient(c);
            return;
        }
        if (c.uin_len == c.uin.len) return error.RecordTooLarge;
        const n = sys.read(c.up_fd, c.uin[c.uin_len..]) catch |e| switch (e) {
            error.WouldBlock => return,
            else => return e,
        };
        if (n == 0) return error.UpstreamEof;
        c.uin_len += n;
        try l.processUpstream(c);
    }

    fn processUpstream(l: *Loop, c: *Conn) !void {
        try processRecords(c);
        if (c.c_out_len > 0) try l.flushClient(c);
        if (c.up_out_len > 0) try l.flushUpstream(c);
        if (c.state == .relay and c.cin_len > 0) try l.forwardClient(c);
    }

    /// Consume complete outer records from `uin`. Stops when `c_out` has data
    /// (one record's worth) so back-pressure applies per record.
    fn processRecords(c: *Conn) !void {
        while (c.uin_len >= record.header_len and c.c_out_len == 0) {
            // We already sent close_notify; whatever arrives now is the peer's.
            if (c.tls.state == .closed) return error.UpstreamCloseNotify;
            const hdr = record.Header.parse(c.uin[0..record.header_len]);
            const total = record.header_len + hdr.len;
            if (total > c.uin.len) return error.RecordTooLarge;
            if (c.uin_len < total) break;

            var scratch: [max_rec]u8 = undefined;
            const res = c.tls.handleRecord(c.uin[0..total], &scratch) catch |e| {
                if (c.tls.last_alert) |a| sys.log("[{d}] tls alert {s}", .{ c.slot, @tagName(a.description) });
                return e;
            };
            if (res.to_send.len > 0) {
                if (c.up_out_len + res.to_send.len > c.up_out.len) return error.UpstreamQueueFull;
                @memcpy(c.up_out[c.up_out_off + c.up_out_len ..][0..res.to_send.len], res.to_send);
                c.up_out_len += res.to_send.len;
            }
            if (res.event == .close_notify) return error.UpstreamCloseNotify;
            if (res.event == .handshake_complete) try sendVlessRequest(c);

            var data = res.app_data;
            if (c.state == .relay and data.len > 0) {
                if (!c.got_resp_hdr) {
                    const resp = (vless.parseResponse(data) catch return error.VlessResponse) orelse return error.VlessResponse;
                    c.got_resp_hdr = true;
                    data = data[resp.len..];
                }
                const content = c.unpadder.feed(data);
                @memcpy(c.c_out[0..content.len], content);
                c.c_out_off = 0;
                c.c_out_len = content.len;
            }

            // Drop the consumed record.
            const rest = c.uin_len - total;
            mem.copyForwards(u8, c.uin[0..rest], c.uin[total..c.uin_len]);
            c.uin_len = rest;

            if (c.state == .relay and c.unpadder.direct) {
                sys.log("[{d}] vision downlink -> direct", .{c.slot});
                // Whatever is left in uin is already the raw inner stream.
                @memcpy(c.c_out[c.c_out_len..][0..c.uin_len], c.uin[0..c.uin_len]);
                c.c_out_len += c.uin_len;
                c.uin_len = 0;
                return;
            }
        }
    }

    /// Outer handshake done: VLESS header + first payload (or an empty
    /// padding block) in one record.
    fn sendVlessRequest(c: *Conn) !void {
        c.state = .relay;
        var buf: [vless.max_request_len + client_chunk + 2 * vision.max_overhead]u8 = undefined;
        const addr: vless.Address = switch (c.target_kind) {
            .ipv4 => .{ .ipv4 = c.target_buf[0..4].* },
            .ipv6 => .{ .ipv6 = c.target_buf[0..16].* },
            .domain => .{ .domain = c.target_buf[0..c.target_len] },
        };
        const hdr = vless.encodeRequest(&buf, .{
            .uuid = c.vstate.uuid,
            .flow = .vision,
            .address = addr,
            .port = c.target_port,
        }) catch return error.VlessRequest;
        var n = hdr.len;
        const padded = if (c.cin_len > 0)
            c.padder.pad(c.cin[0..c.cin_len], buf[n..]) catch return error.VisionPad
        else
            c.padder.padEmpty(buf[n..]) catch return error.VisionPad;
        n += padded.len;
        c.cin_len = 0;
        // Goes right behind the client Finished that is still queued in up_out.
        var rec_buf: [max_rec]u8 = undefined;
        const rec = c.tls.encrypt(buf[0..n], &rec_buf) catch return error.TlsEncrypt;
        if (c.up_out_off + c.up_out_len + rec.len > c.up_out.len) return error.UpstreamQueueFull;
        @memcpy(c.up_out[c.up_out_off + c.up_out_len ..][0..rec.len], rec);
        c.up_out_len += rec.len;
    }
};
