//! zray: minimal REALITY (VLESS + xtls-rprx-vision) client for routers.
//!
//!   zray [config.json]      (default: ./config.json)
//!
//! Linux only; single thread; epoll; fixed memory (connection pool sized by
//! `max_connections`).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const version = "0.1.0";

const FileConfig = struct {
    /// SOCKS5 inbound; empty string disables it.
    listen: []const u8 = "127.0.0.1:1080",
    /// Transparent inbound for netfilter REDIRECT (iptables -j REDIRECT /
    /// nft redirect to); empty string disables it.
    redirect: []const u8 = "",
    sniff: bool = true,
    server: []const u8,
    port: u16 = 443,
    sni: []const u8 = "",
    public_key: []const u8,
    short_id: []const u8 = "",
    uuid: []const u8,
    max_connections: u32 = 128,
    handshake_timeout_s: u64 = 15,
    idle_timeout_s: u64 = 600,
    sock_buf: i32 = 0,
};

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .linux) {
        var buf: [256]u8 = undefined;
        var w: Io.File.Writer = .init(.stdout(), init.io, &buf);
        try w.interface.print("zray {s}: the proxy service runs on Linux only (built for {s}-{s}). Use `zig build probe` here.\n", .{ version, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag) });
        try w.interface.flush();
        return;
    }
    return linuxMain(init);
}

fn linuxMain(init: std.process.Init) !void {
    const sys = @import("linux/sys.zig");
    const conn = @import("linux/conn.zig");
    const reality = @import("tls/reality.zig");
    const vless = @import("proxy/vless.zig");

    const arena = init.arena.allocator();
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const cfg_path = args.next() orelse "config.json";

    const text = Io.Dir.cwd().readFileAlloc(init.io, cfg_path, arena, .limited(64 * 1024)) catch |e| {
        sys.log("cannot read {s}: {s}", .{ cfg_path, @errorName(e) });
        return e;
    };
    const parsed = std.json.parseFromSliceLeaky(FileConfig, arena, text, .{ .ignore_unknown_fields = true }) catch |e| {
        sys.log("bad config: {s}", .{@errorName(e)});
        return e;
    };

    // Resolve the server once at startup (routers rarely change upstreams).
    const server_addr = resolve(init.io, parsed.server, parsed.port) catch |e| {
        sys.log("cannot resolve {s}: {s}", .{ parsed.server, @errorName(e) });
        return e;
    };
    const cfg: conn.Config = .{
        .server_addr = server_addr,
        .sni = if (parsed.sni.len > 0) parsed.sni else parsed.server,
        .reality = .{
            .server_public_key = reality.Config.publicKeyFromBase64(parsed.public_key) catch |e| {
                sys.log("bad public_key", .{});
                return e;
            },
            .short_id = reality.Config.shortIdFromHex(parsed.short_id) catch |e| {
                sys.log("bad short_id", .{});
                return e;
            },
        },
        .uuid = vless.parseUuid(parsed.uuid) catch |e| {
            sys.log("bad uuid", .{});
            return e;
        },
        .handshake_timeout_s = parsed.handshake_timeout_s,
        .idle_timeout_s = parsed.idle_timeout_s,
        .sock_buf = parsed.sock_buf,
        .sniff = parsed.sniff,
    };

    if (parsed.listen.len == 0 and parsed.redirect.len == 0) {
        sys.log("nothing to listen on: set listen and/or redirect", .{});
        return error.BadListen;
    }
    sys.ignoreSigpipe();
    const ep = try sys.epollCreate();
    const socks_token: u64 = std.math.maxInt(u64);
    const redirect_token: u64 = std.math.maxInt(u64) - 1;
    const socks_fd: ?sys.fd_t = if (parsed.listen.len > 0) try listenOn(parsed.listen) else null;
    const redirect_fd: ?sys.fd_t = if (parsed.redirect.len > 0) try listenOn(parsed.redirect) else null;
    if (socks_fd) |fd| try sys.epollAdd(ep, fd, sys.EPOLL.IN, socks_token);
    if (redirect_fd) |fd| try sys.epollAdd(ep, fd, sys.EPOLL.IN, redirect_token);

    const conns = try std.heap.page_allocator.alloc(conn.Conn, parsed.max_connections);
    var loop = conn.Loop.init(ep, &cfg, conns);
    sys.log("zray {s} socks5 [{s}] redirect [{s}] sniff {}, upstream {s}:{d} (sni {s}), {d} slots x {d} KiB = {d} KiB", .{
        version,     parsed.listen, parsed.redirect,        parsed.sniff,              parsed.server,
        parsed.port, cfg.sni,       parsed.max_connections, @sizeOf(conn.Conn) / 1024, (@sizeOf(conn.Conn) * parsed.max_connections) / 1024,
    });

    var events: [64]sys.Event = undefined;
    var last_sweep = sys.monotonicSeconds();
    while (true) {
        const n = sys.epollWait(ep, &events, 1000) catch |e| {
            sys.log("epoll_wait: {s}", .{@errorName(e)});
            continue;
        };
        for (events[0..n]) |ev| {
            if (ev.data.u64 == socks_token or ev.data.u64 == redirect_token) {
                const is_socks = ev.data.u64 == socks_token;
                const lfd = if (is_socks) socks_fd.? else redirect_fd.?;
                while (true) {
                    const fd = sys.accept(lfd) catch break;
                    loop.accept(fd, if (is_socks) .socks5 else .redirect);
                }
            } else {
                loop.handle(ev.data.u64, ev.events);
            }
        }
        const now = sys.monotonicSeconds();
        if (now != last_sweep) {
            last_sweep = now;
            loop.sweep();
        }
    }
}

fn listenOn(spec: []const u8) !@import("linux/sys.zig").fd_t {
    const sys = @import("linux/sys.zig");
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadListen;
    const addr = try sys.SockAddr.parseIp(spec[0..colon], try std.fmt.parseInt(u16, spec[colon + 1 ..], 10));
    const fd = try sys.tcpSocket(addr.family());
    sys.setReuseAddr(fd);
    sys.bind(fd, &addr) catch |e| {
        sys.log("cannot bind {s}: {s}", .{ spec, @errorName(e) });
        return e;
    };
    try sys.listen(fd, 128);
    return fd;
}

/// IP literal or DNS name -> socket address (blocking, startup only).
fn resolve(io: Io, host: []const u8, port: u16) !@import("linux/sys.zig").SockAddr {
    const sys = @import("linux/sys.zig");
    if (sys.SockAddr.parseIp(host, port)) |a| return a else |_| {}
    const hn = try Io.net.HostName.init(host);
    var buf: [16]Io.net.HostName.LookupResult = undefined;
    var q: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    try hn.lookup(io, &q, .{ .port = port, .family = .ip4 });
    var got: [16]Io.net.HostName.LookupResult = undefined;
    const n = try q.get(io, &got, 0);
    for (got[0..n]) |r| switch (r) {
        .address => |a| switch (a) {
            .ip4 => |v4| return sys.SockAddr.fromIpv4(v4.bytes, port),
            .ip6 => |v6| return sys.SockAddr.fromIpv6(v6.bytes, port),
        },
        .canonical_name => {},
    };
    return error.NoAddress;
}
