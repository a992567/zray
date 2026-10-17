//! VLESS wire format (client side), matching xray-core proxy/vless/encoding.
//!
//! Request:
//!   version(1)=0 | uuid(16) | addons_len(1) | addons | command(1) | port(2 BE) | addr_type(1) | addr
//!   addons is the protobuf `Addons{ string Flow = 1; }`; empty (len 0) when no flow.
//!   command: 1 = TCP, 2 = UDP, 3 = Mux (no port/addr for Mux).
//!   addr_type: 1 = IPv4(4), 2 = domain(len(1) | bytes), 3 = IPv6(16).
//!
//! Response:
//!   version(1) | addons_len(1) | addons

const std = @import("std");
const mem = std.mem;

pub const version: u8 = 0;

pub const Command = enum(u8) { tcp = 1, udp = 2, mux = 3 };

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,
    domain: []const u8,
};

pub const Flow = enum {
    none,
    vision,

    /// Protobuf encoding of `Addons{Flow: "xtls-rprx-vision"}`: tag 1, wire type 2.
    const vision_addons = [_]u8{ 0x0a, 0x10 } ++ "xtls-rprx-vision".*;

    fn addons(f: Flow) []const u8 {
        return switch (f) {
            .none => &.{},
            .vision => &vision_addons,
        };
    }
};

pub const Request = struct {
    uuid: [16]u8,
    flow: Flow = .none,
    command: Command = .tcp,
    address: Address,
    port: u16,
};

pub const Error = error{ BufferTooSmall, DomainTooLong };

/// Max encoded request size: 1 + 16 + 1 + 18 + 1 + 2 + 1 + 1 + 255.
pub const max_request_len = 296;

pub fn encodeRequest(out: []u8, r: Request) Error![]u8 {
    const addons = r.flow.addons();
    var n: usize = 0;
    const need = 1 + 16 + 1 + addons.len + 1 + switch (r.command) {
        .mux => @as(usize, 0),
        else => 2 + 1 + switch (r.address) {
            .ipv4 => @as(usize, 4),
            .ipv6 => 16,
            .domain => |d| 1 + d.len,
        },
    };
    if (out.len < need) return error.BufferTooSmall;

    out[n] = version;
    n += 1;
    out[n..][0..16].* = r.uuid;
    n += 16;
    out[n] = @intCast(addons.len);
    n += 1;
    @memcpy(out[n..][0..addons.len], addons);
    n += addons.len;
    out[n] = @backingInt(r.command);
    n += 1;
    if (r.command != .mux) {
        mem.writeInt(u16, out[n..][0..2], r.port, .big);
        n += 2;
        switch (r.address) {
            .ipv4 => |a| {
                out[n] = 1;
                out[n + 1 ..][0..4].* = a;
                n += 5;
            },
            .domain => |d| {
                if (d.len > 255) return error.DomainTooLong;
                out[n] = 2;
                out[n + 1] = @intCast(d.len);
                @memcpy(out[n + 2 ..][0..d.len], d);
                n += 2 + d.len;
            },
            .ipv6 => |a| {
                out[n] = 3;
                out[n + 1 ..][0..16].* = a;
                n += 17;
            },
        }
    }
    return out[0..n];
}

pub const Response = struct {
    addons: []const u8,
    /// Bytes consumed from the input.
    len: usize,
};

/// Parse the response header. Returns null if more bytes are needed.
pub fn parseResponse(input: []const u8) error{BadVersion}!?Response {
    if (input.len < 2) return null;
    if (input[0] != version) return error.BadVersion;
    const alen: usize = input[1];
    if (input.len < 2 + alen) return null;
    return .{ .addons = input[2..][0..alen], .len = 2 + alen };
}

pub fn parseUuid(text: []const u8) error{InvalidUuid}![16]u8 {
    // 8-4-4-4-12 hex with dashes, or 32 bare hex chars.
    var hex: [32]u8 = undefined;
    var n: usize = 0;
    for (text) |ch| {
        if (ch == '-') continue;
        if (n == 32) return error.InvalidUuid;
        hex[n] = ch;
        n += 1;
    }
    if (n != 32) return error.InvalidUuid;
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, &hex) catch return error.InvalidUuid;
    return out;
}

const testing = std.testing;

test "request header with vision flow and domain" {
    var buf: [max_request_len]u8 = undefined;
    const uuid = try parseUuid("123e4567-e89b-12d3-a456-426614174000");
    const r = try encodeRequest(&buf, .{
        .uuid = uuid,
        .flow = .vision,
        .address = .{ .domain = "example.com" },
        .port = 80,
    });
    try testing.expectEqual(@as(usize, 1 + 16 + 1 + 18 + 1 + 2 + 1 + 1 + 11), r.len);
    try testing.expectEqual(@as(u8, 0), r[0]);
    try testing.expectEqualSlices(u8, &uuid, r[1..17]);
    try testing.expectEqual(@as(u8, 18), r[17]);
    try testing.expectEqualSlices(u8, "\x0a\x10xtls-rprx-vision", r[18..36]);
    try testing.expectEqual(@as(u8, 1), r[36]); // tcp
    try testing.expectEqualSlices(u8, &.{ 0, 80, 2, 11 }, r[37..41]);
    try testing.expectEqualSlices(u8, "example.com", r[41..]);
}

test "request header without flow, ipv4" {
    var buf: [max_request_len]u8 = undefined;
    const r = try encodeRequest(&buf, .{
        .uuid = @splat(7),
        .address = .{ .ipv4 = .{ 1, 2, 3, 4 } },
        .port = 443,
    });
    try testing.expectEqualSlices(u8, &.{ 0, 1, 1, 0xbb, 1, 1, 2, 3, 4 }, r[17..]);
}

test "response header" {
    try testing.expectEqual(@as(?Response, null), try parseResponse(&.{0}));
    const r = (try parseResponse(&.{ 0, 0, 0xaa })).?;
    try testing.expectEqual(@as(usize, 2), r.len);
    try testing.expectEqual(@as(usize, 0), r.addons.len);
    try testing.expectError(error.BadVersion, parseResponse(&.{ 1, 0 }));
}
