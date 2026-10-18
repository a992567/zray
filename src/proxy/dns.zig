//! Minimal DNS wire format (RFC 1035): one A query, first A answer. Used to
//! resolve `server` through a bootstrap nameserver at startup, so zray does
//! not depend on a local resolver that may itself depend on the tunnel.
//!
//! Sans-I/O: `encodeQuery` builds the datagram, `firstA` reads the reply.

const std = @import("std");
const mem = std.mem;

pub const max_message = 512;

pub const Error = error{
    BadName,
    BufferTooSmall,
    Truncated,
    WrongId,
    NotAResponse,
    /// RCODE != 0 (NXDOMAIN, SERVFAIL, REFUSED, ...).
    ServerError,
    NoAddress,
};

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Standard recursive query for the A record of `name`. Returns the length.
pub fn encodeQuery(buf: []u8, id: u16, name: []const u8) Error!usize {
    if (name.len == 0 or name.len > 253) return error.BadName;
    const n = mem.trimEnd(u8, name, ".");
    // header (12) + name (len + 2) + qtype/qclass (4)
    if (buf.len < 12 + n.len + 2 + 4) return error.BufferTooSmall;
    mem.writeInt(u16, buf[0..2], id, .big);
    mem.writeInt(u16, buf[2..4], 0x0100, .big); // RD
    mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    @memset(buf[6..12], 0);
    var off: usize = 12;
    var labels = mem.splitScalar(u8, n, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadName;
        buf[off] = @intCast(label.len);
        @memcpy(buf[off + 1 .. off + 1 + label.len], label);
        off += 1 + label.len;
    }
    buf[off] = 0;
    off += 1;
    mem.writeInt(u16, buf[off..][0..2], TYPE_A, .big);
    mem.writeInt(u16, buf[off + 2 ..][0..2], CLASS_IN, .big);
    return off + 4;
}

/// First A record in the answer section of a reply to query `id`. CNAME and
/// other records are skipped; compression pointers are followed only to the
/// extent of skipping the name.
pub fn firstA(msg: []const u8, id: u16) Error![4]u8 {
    if (msg.len < 12) return error.Truncated;
    if (mem.readInt(u16, msg[0..2], .big) != id) return error.WrongId;
    const flags = mem.readInt(u16, msg[2..4], .big);
    if (flags & 0x8000 == 0) return error.NotAResponse;
    if (flags & 0x000f != 0) return error.ServerError;
    const qdcount = mem.readInt(u16, msg[4..6], .big);
    const ancount = mem.readInt(u16, msg[6..8], .big);
    var off: usize = 12;
    var i: usize = 0;
    while (i < qdcount) : (i += 1) {
        off = try skipName(msg, off);
        off += 4; // qtype, qclass
        if (off > msg.len) return error.Truncated;
    }
    i = 0;
    while (i < ancount) : (i += 1) {
        off = try skipName(msg, off);
        if (off + 10 > msg.len) return error.Truncated;
        const typ = mem.readInt(u16, msg[off..][0..2], .big);
        const class = mem.readInt(u16, msg[off + 2 ..][0..2], .big);
        const rdlen = mem.readInt(u16, msg[off + 8 ..][0..2], .big);
        off += 10;
        if (off + rdlen > msg.len) return error.Truncated;
        if (typ == TYPE_A and class == CLASS_IN and rdlen == 4) return msg[off..][0..4].*;
        off += rdlen;
    }
    return error.NoAddress;
}

fn skipName(msg: []const u8, start: usize) Error!usize {
    var off = start;
    while (true) {
        if (off >= msg.len) return error.Truncated;
        const len = msg[off];
        if (len == 0) return off + 1;
        if (len & 0xc0 == 0xc0) {
            if (off + 2 > msg.len) return error.Truncated;
            return off + 2;
        }
        if (len & 0xc0 != 0) return error.Truncated; // reserved label types
        off += 1 + len;
    }
}

const testing = std.testing;

test "encodeQuery" {
    var buf: [max_message]u8 = undefined;
    const n = try encodeQuery(&buf, 0x1234, "example.com");
    try testing.expectEqualSlices(u8, &[_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    }, buf[0..n]);
    try testing.expectEqual(n, try encodeQuery(&buf, 0x1234, "example.com."));
    try testing.expectError(error.BadName, encodeQuery(&buf, 1, "a..b"));
    try testing.expectError(error.BadName, encodeQuery(&buf, 1, ""));
    try testing.expectError(error.BufferTooSmall, encodeQuery(buf[0..20], 1, "example.com"));
}

test "firstA follows CNAME and compression pointers" {
    const msg = [_]u8{
        0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        // question: www.example.com A IN
        3,    'w',  'w',  'w',  7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,    0x00, 0x01, 0x00, 0x01,
        // answer 1: ptr(12) CNAME IN ttl=60 rdlen=6 "ex" + ptr(16)
        0xc0, 0x0c, 0x00,
        0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x06, 2,    'e',  'x',
        0xc0, 0x10, 0x00,
        // answer 2: ptr(33) A IN ttl=60 rdlen=4 93.184.216.34
        0xc0, 0x21, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x3c, 0x00, 0x04, 93,   184,  216,  34,
    };
    try testing.expectEqual([4]u8{ 93, 184, 216, 34 }, try firstA(&msg, 0xabcd));
    try testing.expectError(error.WrongId, firstA(&msg, 0xabce));
    try testing.expectError(error.Truncated, firstA(msg[0 .. msg.len - 1], 0xabcd));

    var nx = msg;
    nx[3] = 0x83; // NXDOMAIN
    try testing.expectError(error.ServerError, firstA(&nx, 0xabcd));

    var q = msg;
    q[2] = 0x01; // QR clear: it is a query, not a response
    try testing.expectError(error.NotAResponse, firstA(&q, 0xabcd));

    // Only the CNAME: no A record.
    var only_cname = msg;
    only_cname[7] = 1;
    try testing.expectError(error.NoAddress, firstA(only_cname[0 .. msg.len - 16], 0xabcd));
}
