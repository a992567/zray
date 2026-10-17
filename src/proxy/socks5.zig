//! SOCKS5 server-side parsing (RFC 1928), CONNECT only, no authentication.
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

pub const Request = struct {
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

/// Parse the CONNECT request. Returns null if incomplete.
pub fn parseRequest(input: []const u8) Error!?Request {
    if (input.len < 4) return null;
    if (input[0] != 5) return error.BadVersion;
    if (input[2] != 0) return error.BadRequest;
    if (input[1] != 1) return error.UnsupportedCommand; // CONNECT only
    switch (input[3]) {
        1 => {
            if (input.len < 10) return null;
            return .{ .address = .{ .ipv4 = input[4..8].* }, .port = mem.readInt(u16, input[8..10], .big), .len = 10 };
        },
        3 => {
            if (input.len < 5) return null;
            const dlen: usize = input[4];
            if (dlen == 0) return error.BadRequest;
            if (input.len < 5 + dlen + 2) return null;
            return .{
                .address = .{ .domain = input[5 .. 5 + dlen] },
                .port = mem.readInt(u16, input[5 + dlen ..][0..2], .big),
                .len = 5 + dlen + 2,
            };
        },
        4 => {
            if (input.len < 22) return null;
            return .{ .address = .{ .ipv6 = input[4..20].* }, .port = mem.readInt(u16, input[20..22], .big), .len = 22 };
        },
        else => return error.UnsupportedAddress,
    }
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
    try testing.expectError(error.UnsupportedCommand, parseRequest(&.{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }));
    try testing.expectEqualSlices(u8, &.{ 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, &replyForError(error.UnsupportedCommand));
}
