//! XUDP: UDP packets carried in Mux.Cool frames over a single VLESS stream
//! (xray-core common/mux/frame.go + common/xudp/xudp.go, client side).
//!
//! Frame:
//!   meta_len(2 BE) | session_id(2)=0 | status(1) | option(1) | [network(1) | port(2 BE) | atyp(1) | addr]
//!   | [global_id(8)]  (New only)  | data_len(2 BE) | data  (when option has Data)
//!
//! status: 1 New, 2 Keep, 3 End, 4 KeepAlive. option: 0x01 Data, 0x02 Error.
//! atyp: 1 IPv4, 2 domain(len|bytes), 3 IPv6. Note port comes BEFORE the address.
//!
//! Every frame we send carries the packet's target (fullcone); the server
//! replies with Keep frames carrying each packet's source address.

const std = @import("std");
const mem = std.mem;
const vless = @import("vless.zig");

pub const Address = vless.Address;

pub const Status = enum(u8) { new = 1, keep = 2, end = 3, keep_alive = 4 };

pub const option_data: u8 = 0x01;
pub const option_error: u8 = 0x02;

/// xray drops packets where `len + 666 > 8192`.
pub const max_packet_len = 8192 - 666;
pub const max_meta_len = 512;
pub const max_frame_len = 2 + max_meta_len + 2 + 8192;

pub const Error = error{ BufferTooSmall, PacketTooLarge, DomainTooLong };

fn writeTarget(out: []u8, n: *usize, addr: Address, port: u16) Error!void {
    const need: usize = 1 + 2 + 1 + switch (addr) {
        .ipv4 => @as(usize, 4),
        .ipv6 => 16,
        .domain => |d| 1 + d.len,
    };
    if (out.len < n.* + need) return error.BufferTooSmall;
    out[n.*] = 2; // network UDP
    mem.writeInt(u16, out[n.* + 1 ..][0..2], port, .big);
    n.* += 3;
    switch (addr) {
        .ipv4 => |a| {
            out[n.*] = 1;
            out[n.* + 1 ..][0..4].* = a;
            n.* += 5;
        },
        .domain => |d| {
            if (d.len > 255) return error.DomainTooLong;
            out[n.*] = 2;
            out[n.* + 1] = @intCast(d.len);
            @memcpy(out[n.* + 2 ..][0..d.len], d);
            n.* += 2 + d.len;
        },
        .ipv6 => |a| {
            out[n.*] = 3;
            out[n.* + 1 ..][0..16].* = a;
            n.* += 17;
        },
    }
}

fn encode(out: []u8, status: Status, addr: Address, port: u16, global_id: ?[8]u8, data: []const u8) Error![]u8 {
    if (data.len > max_packet_len) return error.PacketTooLarge;
    if (out.len < 6) return error.BufferTooSmall;
    var n: usize = 2;
    out[2] = 0;
    out[3] = 0;
    out[4] = @backingInt(status);
    out[5] = option_data;
    n = 6;
    try writeTarget(out, &n, addr, port);
    if (global_id) |g| {
        if (out.len < n + 8) return error.BufferTooSmall;
        out[n..][0..8].* = g;
        n += 8;
    }
    mem.writeInt(u16, out[0..2], @intCast(n - 2), .big);
    if (out.len < n + 2 + data.len) return error.BufferTooSmall;
    mem.writeInt(u16, out[n..][0..2], @intCast(data.len), .big);
    n += 2;
    @memcpy(out[n..][0..data.len], data);
    return out[0 .. n + data.len];
}

/// First packet of an association: New frame with the global ID (what xray
/// derives from the client's source address; any non-zero value works).
pub fn encodeNew(out: []u8, addr: Address, port: u16, global_id: [8]u8, data: []const u8) Error![]u8 {
    return encode(out, .new, addr, port, global_id, data);
}

/// Every following packet: Keep frame carrying its own target.
pub fn encodeKeep(out: []u8, addr: Address, port: u16, data: []const u8) Error![]u8 {
    return encode(out, .keep, addr, port, null, data);
}

pub const Frame = struct {
    status: Status,
    option: u8,
    /// Packet source for Keep frames that carry one (XUDP).
    addr: ?Address,
    port: u16,
    data: []const u8,
    /// Bytes consumed from the input.
    len: usize,
};

pub const ParseError = error{ BadFrame, MetaTooLong };

/// Parse one frame from the server. Returns null if more bytes are needed.
pub fn parse(input: []const u8) ParseError!?Frame {
    if (input.len < 2) return null;
    const meta_len: usize = mem.readInt(u16, input[0..2], .big);
    if (meta_len > max_meta_len) return error.MetaTooLong;
    if (meta_len < 4) return error.BadFrame;
    if (input.len < 2 + meta_len) return null;
    const meta = input[2 .. 2 + meta_len];
    var f: Frame = .{
        .status = switch (meta[2]) {
            1 => .new,
            2 => .keep,
            3 => .end,
            4 => .keep_alive,
            else => return error.BadFrame,
        },
        .option = meta[3],
        .addr = null,
        .port = 0,
        .data = &.{},
        .len = 2 + meta_len,
    };
    if ((f.status == .new or f.status == .keep) and meta.len > 4 and meta[4] == 2) {
        // network(1) | port(2) | atyp(1) | addr
        if (meta.len < 8) return error.BadFrame;
        f.port = mem.readInt(u16, meta[5..7], .big);
        const rest = meta[7..];
        switch (rest[0]) {
            1 => {
                if (rest.len < 5) return error.BadFrame;
                f.addr = .{ .ipv4 = rest[1..5].* };
            },
            2 => {
                if (rest.len < 2) return error.BadFrame;
                const dlen: usize = rest[1];
                if (rest.len < 2 + dlen) return error.BadFrame;
                f.addr = .{ .domain = rest[2 .. 2 + dlen] };
            },
            3 => {
                if (rest.len < 17) return error.BadFrame;
                f.addr = .{ .ipv6 = rest[1..17].* };
            },
            else => return error.BadFrame,
        }
    }
    if (f.option & option_data != 0) {
        if (input.len < f.len + 2) return null;
        const dlen: usize = mem.readInt(u16, input[f.len..][0..2], .big);
        if (input.len < f.len + 2 + dlen) return null;
        f.data = input[f.len + 2 ..][0..dlen];
        f.len += 2 + dlen;
    }
    return f;
}

const testing = std.testing;

test "new frame layout" {
    var buf: [64]u8 = undefined;
    const f = try encodeNew(&buf, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 53, .{ 1, 2, 3, 4, 5, 6, 7, 8 }, "hi");
    // meta: 0000 01 01 02 0035 01 08080808 + 8 global id = 20 bytes
    try testing.expectEqualSlices(u8, &.{
        0, 20, 0,   0,   1, 1, 2, 0, 53, 1, 8, 8, 8, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        0, 2,  'h', 'i',
    }, f);
}

test "keep frame with domain and roundtrip parse" {
    var buf: [64]u8 = undefined;
    const f = try encodeKeep(&buf, .{ .domain = "a.b" }, 443, "xyz");
    try testing.expectEqualSlices(u8, &.{ 0, 12, 0, 0, 2, 1, 2, 1, 0xbb, 2, 3, 'a', '.', 'b', 0, 3, 'x', 'y', 'z' }, f);
    const p = (try parse(f)).?;
    try testing.expect(p.status == .keep);
    try testing.expectEqualSlices(u8, "a.b", p.addr.?.domain);
    try testing.expectEqual(@as(u16, 443), p.port);
    try testing.expectEqualSlices(u8, "xyz", p.data);
    try testing.expectEqual(f.len, p.len);
}

test "parse incomplete, keepalive, end" {
    var buf: [64]u8 = undefined;
    const f = try encodeKeep(&buf, .{ .ipv6 = @splat(1) }, 1, "payload");
    try testing.expectEqual(@as(?Frame, null), try parse(f[0..1]));
    try testing.expectEqual(@as(?Frame, null), try parse(f[0 .. f.len - 1]));
    const p = (try parse(f)).?;
    try testing.expect(p.addr.? == .ipv6);

    const ka = [_]u8{ 0, 4, 0, 0, 4, 0 };
    const k = (try parse(&ka)).?;
    try testing.expect(k.status == .keep_alive);
    try testing.expectEqual(@as(usize, 6), k.len);

    const end = [_]u8{ 0, 4, 0, 0, 3, 2 };
    const e = (try parse(&end)).?;
    try testing.expect(e.status == .end);
    try testing.expect(e.option & option_error != 0);

    try testing.expectError(error.MetaTooLong, parse(&.{ 0xff, 0xff }));
    const big: [7600]u8 = @splat(0);
    try testing.expectError(error.PacketTooLarge, encodeKeep(&buf, .{ .ipv4 = @splat(0) }, 1, &big));
}
