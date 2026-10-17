//! Destination sniffing for transparently redirected connections: recover the
//! host name from the first bytes the client sends so the VLESS request can
//! carry a domain instead of a (possibly poisoned) IP.
//!
//! Supported: TLS ClientHello server_name (single record), HTTP/1.x Host.

const std = @import("std");
const mem = std.mem;

pub const Result = union(enum) {
    /// Not enough bytes yet to decide.
    need_more,
    /// Not a protocol we sniff, or malformed.
    none,
    host: []const u8,
};

pub fn sniff(b: []const u8) Result {
    if (b.len < 5) return .need_more;
    if (b[0] == 0x16 and b[1] == 0x03) return sniffTls(b);
    return sniffHttp(b);
}

fn sniffTls(b: []const u8) Result {
    const rec_len: usize = mem.readInt(u16, b[3..5], .big);
    if (b.len < 5 + rec_len) return .need_more;
    const hs = b[5 .. 5 + rec_len];
    if (hs.len < 4 or hs[0] != 0x01) return .none;
    const body_len: usize = (@as(usize, hs[1]) << 16) | (@as(usize, hs[2]) << 8) | hs[3];
    if (hs.len < 4 + body_len) return .none; // ClientHello spans records; give up
    var r = Reader{ .buf = hs[4 .. 4 + body_len] };
    r.skip(2 + 32) orelse return .none; // version, random
    const sid_len = r.byte() orelse return .none;
    r.skip(sid_len) orelse return .none;
    const cs_len = r.word() orelse return .none;
    r.skip(cs_len) orelse return .none;
    const cm_len = r.byte() orelse return .none;
    r.skip(cm_len) orelse return .none;
    const ext_len = r.word() orelse return .none;
    var exts = Reader{ .buf = r.take(ext_len) orelse return .none };
    while (exts.buf.len > 0) {
        const typ = exts.word() orelse return .none;
        const len = exts.word() orelse return .none;
        const data = exts.take(len) orelse return .none;
        if (typ != 0) continue;
        var sni = Reader{ .buf = data };
        const list_len = sni.word() orelse return .none;
        var list = Reader{ .buf = sni.take(list_len) orelse return .none };
        while (list.buf.len > 0) {
            const name_type = list.byte() orelse return .none;
            const name_len = list.word() orelse return .none;
            const name = list.take(name_len) orelse return .none;
            if (name_type == 0 and validHost(name)) return .{ .host = name };
        }
        return .none;
    }
    return .none;
}

fn sniffHttp(b: []const u8) Result {
    const methods = [_][]const u8{ "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT " };
    var is_http = false;
    for (methods) |m| {
        if (b.len >= m.len and mem.eql(u8, b[0..m.len], m)) is_http = true;
    }
    if (!is_http) return .none;
    const end = mem.indexOf(u8, b, "\r\n\r\n") orelse {
        if (b.len > 8192) return .none;
        return .need_more;
    };
    var lines = mem.splitSequence(u8, b[0..end], "\r\n");
    _ = lines.next(); // request line
    while (lines.next()) |line| {
        if (line.len > 5 and std.ascii.eqlIgnoreCase(line[0..5], "host:")) {
            var host = mem.trim(u8, line[5..], " \t");
            if (mem.lastIndexOfScalar(u8, host, ':')) |i| {
                if (mem.indexOfScalar(u8, host, ']') == null) host = host[0..i]; // strip :port (not IPv6 literal)
            }
            if (validHost(host)) return .{ .host = host };
            return .none;
        }
    }
    return .none;
}

fn validHost(h: []const u8) bool {
    if (h.len == 0 or h.len > 253) return false;
    var has_alpha = false;
    for (h) |c| {
        if (std.ascii.isAlphabetic(c)) has_alpha = true else if (!(std.ascii.isDigit(c) or c == '.' or c == '-')) return false;
    }
    return has_alpha; // reject bare IPv4 literals
}

const Reader = struct {
    buf: []const u8,
    fn byte(r: *Reader) ?u8 {
        if (r.buf.len < 1) return null;
        const v = r.buf[0];
        r.buf = r.buf[1..];
        return v;
    }
    fn word(r: *Reader) ?u16 {
        if (r.buf.len < 2) return null;
        const v = mem.readInt(u16, r.buf[0..2], .big);
        r.buf = r.buf[2..];
        return v;
    }
    fn take(r: *Reader, n: usize) ?[]const u8 {
        if (r.buf.len < n) return null;
        const v = r.buf[0..n];
        r.buf = r.buf[n..];
        return v;
    }
    fn skip(r: *Reader, n: usize) ?void {
        _ = r.take(n) orelse return null;
    }
};

const testing = std.testing;
const hello = @import("../tls/hello.zig");

test "sniff TLS SNI from our own ClientHello" {
    var buf: [1024]u8 = undefined;
    const exts = [_]hello.Extension{
        .{ .supported_versions = &.{.tls_1_3} },
        .{ .server_name = "www.example.org" },
        .{ .alpn = &.{"h2"} },
    };
    const enc = try hello.encode(buf[5..], .{
        .random = @splat(1),
        .cipher_suites = &.{.AES_128_GCM_SHA256},
        .extensions = &exts,
    });
    _ = enc.recordHeader(buf[0..5]);
    const total = 5 + enc.msg.len;
    try testing.expectEqualSlices(u8, "www.example.org", sniff(buf[0..total]).host);
    try testing.expectEqual(Result.need_more, sniff(buf[0 .. total - 1]));
}

test "sniff HTTP Host" {
    try testing.expectEqualSlices(u8, "example.com", sniff("GET / HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: x\r\n\r\n").host);
    try testing.expectEqual(Result.need_more, sniff("GET / HTTP/1.1\r\nHost: exa"));
    try testing.expectEqual(Result.none, sniff("GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"));
    try testing.expectEqual(Result.none, sniff("SSH-2.0-OpenSSH\r\n"));
}
