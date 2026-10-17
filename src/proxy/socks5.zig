//! SOCKS5 server-side parsing (RFC 1928), CONNECT and UDP ASSOCIATE, no
//! authentication.
//! Sans-I/O: feed buffered bytes, get back how many were consumed and what to
//! reply.

const std = @import("std");
const mem = std.mem;

pub const Error = error{ BadVersion, NoAcceptableAuth, BadRequest, UnsupportedCommand, UnsupportedAddress };

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,
    domain: []const u8,
};

pub const Command = enum(u8) { connect = 1, udp_associate = 3 };

pub const Request = struct {
    command: Command,
    address: Address,
    port: u16,
    /// Bytes consumed from the input.
    len: usize,
};

/// Parse the client greeting. Returns bytes consumed, or null if incomplete.
pub fn parseGreeting(input: []const u8) Error!?usize {
    if (input.len < 2) return null;
    if (input[0] != 5) return error.BadVersion;
    const n: usize = input[1];
    if (input.len < 2 + n) return null;
    if (mem.indexOfScalar(u8, input[2 .. 2 + n], 0) == null) return error.NoAcceptableAuth;
    return 2 + n;
}

pub const greeting_reply = [_]u8{ 5, 0 };
pub const greeting_reject = [_]u8{ 5, 0xff };

/// Parse the request (CONNECT / UDP ASSOCIATE). Returns null if incomplete.
pub fn parseRequest(input: []const u8) Error!?Request {
    if (input.len < 4) return null;
    if (input[0] != 5) return error.BadVersion;
    if (input[2] != 0) return error.BadRequest;
    const cmd: Command = switch (input[1]) {
        1 => .connect,
        3 => .udp_associate,
        else => return error.UnsupportedCommand, // BIND
    };
    const a = (try parseAddress(input[3..])) orelse return null;
    return .{ .command = cmd, .address = a.address, .port = a.port, .len = 3 + a.len };
}

const AddrPort = struct { address: Address, port: u16, len: usize };

/// atyp(1) | addr | port(2 BE), shared by requests and UDP datagram headers.
fn parseAddress(input: []const u8) Error!?AddrPort {
    if (input.len < 1) return null;
    switch (input[0]) {
        1 => {
            if (input.len < 7) return null;
            return .{ .address = .{ .ipv4 = input[1..5].* }, .port = mem.readInt(u16, input[5..7], .big), .len = 7 };
        },
        3 => {
            if (input.len < 2) return null;
            const dlen: usize = input[1];
            if (dlen == 0) return error.BadRequest;
            if (input.len < 2 + dlen + 2) return null;
            return .{
                .address = .{ .domain = input[2 .. 2 + dlen] },
                .port = mem.readInt(u16, input[2 + dlen ..][0..2], .big),
                .len = 2 + dlen + 2,
            };
        },
        4 => {
            if (input.len < 19) return null;
            return .{ .address = .{ .ipv6 = input[1..17].* }, .port = mem.readInt(u16, input[17..19], .big), .len = 19 };
        },
        else => return error.UnsupportedAddress,
    }
}

fn writeAddress(out: []u8, address: Address, port: u16) error{BufferTooSmall}!usize {
    const need: usize = 1 + 2 + switch (address) {
        .ipv4 => @as(usize, 4),
        .ipv6 => 16,
        .domain => |d| 1 + d.len,
    };
    if (out.len < need) return error.BufferTooSmall;
    var n: usize = 0;
    switch (address) {
        .ipv4 => |a| {
            out[0] = 1;
            out[1..5].* = a;
            n = 5;
        },
        .domain => |d| {
            out[0] = 3;
            out[1] = @intCast(d.len);
            @memcpy(out[2..][0..d.len], d);
            n = 2 + d.len;
        },
        .ipv6 => |a| {
            out[0] = 4;
            out[1..17].* = a;
            n = 17;
        },
    }
    mem.writeInt(u16, out[n..][0..2], port, .big);
    return n + 2;
}

// ---- UDP ASSOCIATE ------------------------------------------------------------

pub const UdpHeader = struct {
    address: Address,
    port: u16,
    /// Header length; the payload is `datagram[len..]`.
    len: usize,
};

/// Parse the header of a datagram sent to the relay:
/// rsv(2) | frag(1) | atyp | addr | port | data. Fragments are not supported.
pub fn parseUdpHeader(dgram: []const u8) Error!?UdpHeader {
    if (dgram.len < 4) return error.BadRequest;
    if (dgram[0] != 0 or dgram[1] != 0) return error.BadRequest;
    if (dgram[2] != 0) return error.UnsupportedCommand; // fragment
    const a = (try parseAddress(dgram[3..])) orelse return error.BadRequest;
    return .{ .address = a.address, .port = a.port, .len = 3 + a.len };
}

pub const max_udp_header_len = 3 + 1 + 1 + 255 + 2;

/// Write the header of a datagram going back to the client.
pub fn encodeUdpHeader(out: []u8, address: Address, port: u16) error{BufferTooSmall}![]u8 {
    if (out.len < 3) return error.BufferTooSmall;
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    const n = try writeAddress(out[3..], address, port);
    return out[0 .. 3 + n];
}

/// Successful reply carrying the relay's bound address (UDP ASSOCIATE).
pub fn replyBound(out: *[22]u8, address: Address, port: u16) []u8 {
    out[0] = 5;
    out[1] = 0;
    out[2] = 0;
    const n = writeAddress(out[3..], address, port) catch unreachable;
    return out[0 .. 3 + n];
}

pub const Reply = enum(u8) {
    succeeded = 0,
    general_failure = 1,
    not_allowed = 2,
    network_unreachable = 3,
    host_unreachable = 4,
    connection_refused = 5,
    ttl_expired = 6,
    command_not_supported = 7,
    address_type_not_supported = 8,
};

/// Reply with a zero IPv4 bind address (clients ignore it for CONNECT).
pub fn reply(code: Reply) [10]u8 {
    return .{ 5, @backingInt(code), 0, 1, 0, 0, 0, 0, 0, 0 };
}

pub fn replyForError(e: Error) [10]u8 {
    return reply(switch (e) {
        error.UnsupportedCommand => .command_not_supported,
        error.UnsupportedAddress => .address_type_not_supported,
        else => .general_failure,
    });
}

const testing = std.testing;

test "greeting" {
    try testing.expectEqual(@as(?usize, null), try parseGreeting(&.{5}));
    try testing.expectEqual(@as(?usize, 3), try parseGreeting(&.{ 5, 1, 0 }));
    try testing.expectEqual(@as(?usize, 4), try parseGreeting(&.{ 5, 2, 2, 0, 0xee }));
    try testing.expectError(error.NoAcceptableAuth, parseGreeting(&.{ 5, 1, 2 }));
    try testing.expectError(error.BadVersion, parseGreeting(&.{ 4, 1, 0 }));
}

test "connect requests" {
    const d = (try parseRequest("\x05\x01\x00\x03\x0bexample.com\x01\xbb")).?;
    try testing.expectEqualSlices(u8, "example.com", d.address.domain);
    try testing.expectEqual(@as(u16, 443), d.port);
    try testing.expectEqual(@as(usize, 18), d.len);

    const v4 = (try parseRequest(&.{ 5, 1, 0, 1, 10, 0, 0, 1, 0, 80, 0xff })).?;
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &v4.address.ipv4);
    try testing.expectEqual(@as(usize, 10), v4.len);

    try testing.expectEqual(@as(?Request, null), try parseRequest("\x05\x01\x00\x03\x0bexam"));
    try testing.expectError(error.UnsupportedCommand, parseRequest(&.{ 5, 2, 0, 1, 0, 0, 0, 0, 0, 0 }));
    const ua = (try parseRequest(&.{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 })).?;
    try testing.expect(ua.command == .udp_associate);
    try testing.expectEqual(@as(usize, 10), ua.len);
    try testing.expectEqualSlices(u8, &.{ 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, &replyForError(error.UnsupportedCommand));
}

test "udp datagram header" {
    const h = (try parseUdpHeader("\x00\x00\x00\x01\x08\x08\x08\x08\x00\x35hello")).?;
    try testing.expectEqualSlices(u8, &.{ 8, 8, 8, 8 }, &h.address.ipv4);
    try testing.expectEqual(@as(u16, 53), h.port);
    try testing.expectEqual(@as(usize, 10), h.len);
    try testing.expectError(error.UnsupportedCommand, parseUdpHeader(&.{ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 }));

    var out: [max_udp_header_len]u8 = undefined;
    const e = try encodeUdpHeader(&out, .{ .domain = "dns.google" }, 53);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x03\x0adns.google\x00\x35", e);

    var rb: [22]u8 = undefined;
    const r = replyBound(&rb, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 0x1234);
    try testing.expectEqualSlices(u8, &.{ 5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34 }, r);
}
