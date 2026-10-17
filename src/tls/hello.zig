//! TLS 1.3 ClientHello serializer.
//!
//! Produces a complete `Handshake` message (type + u24 length + body) into a
//! caller-provided buffer. Extension order and content are fully controlled by
//! the caller so the same code can reproduce RFC 8448 traces, mimic a browser
//! fingerprint, or carry REALITY's authenticated `session_id`.
//!
//! The returned `Encoded` keeps mutable slices into the buffer for the fields
//! that need to be filled in *after* serialization (REALITY encrypts the
//! session_id with the whole ClientHello as AAD, so the message must exist
//! before the session_id can be computed).

const std = @import("std");
const tls = std.crypto.tls;
const mem = std.mem;

pub const Error = error{
    /// Destination buffer cannot hold the message.
    BufferTooSmall,
    /// A length-prefixed vector exceeded its encodable range, or a field value
    /// is out of spec (e.g. session_id longer than 32 bytes).
    InvalidParameter,
};

pub const KeyShareEntry = struct {
    group: tls.NamedGroup,
    public_key: []const u8,
};

pub const Extension = union(enum) {
    /// RFC 6066 server_name, host_name type only.
    server_name: []const u8,
    supported_versions: []const tls.ProtocolVersion,
    supported_groups: []const tls.NamedGroup,
    signature_algorithms: []const tls.SignatureScheme,
    key_share: []const KeyShareEntry,
    psk_key_exchange_modes: []const tls.PskKeyExchangeMode,
    /// RFC 7301 ALPN protocol list, e.g. `&.{ "h2", "http/1.1" }`.
    alpn: []const []const u8,
    /// RFC 8449 record_size_limit.
    record_size_limit: u16,
    /// RFC 7685 padding; value is the number of zero bytes in the payload.
    padding: u16,
    /// Any extension with a pre-encoded payload: GREASE, renegotiation_info,
    /// session_ticket, status_request, SCT, compress_certificate, ALPS, ECH.
    raw: Raw,

    pub const Raw = struct {
        type: u16,
        data: []const u8 = &.{},
    };
};

pub const Params = struct {
    random: [32]u8,
    /// 0..32 bytes. Pass 32 bytes (any content) when the caller intends to
    /// back-fill it later via `Encoded.session_id`.
    session_id: []const u8 = &.{},
    cipher_suites: []const tls.CipherSuite,
    extensions: []const Extension,
};

pub const Encoded = struct {
    /// The full handshake message: `01 | u24 len | body`.
    msg: []u8,
    /// Mutable view of `random` inside `msg`.
    random: *[32]u8,
    /// Mutable view of `legacy_session_id` inside `msg` (length as requested).
    session_id: []u8,

    /// Fixed offset of `random` inside the handshake message.
    pub const random_offset = 4 + 2;
    /// Fixed offset of the session_id bytes (after its 1-byte length).
    pub const session_id_offset = random_offset + 32 + 1;

    /// ClientHello body without the 4-byte handshake header.
    pub fn body(e: Encoded) []u8 {
        return e.msg[4..];
    }

    /// Write a TLS record header for this message into `out` and return the
    /// header slice. Record version 0x0301 is what browsers send for the
    /// first flight.
    pub fn recordHeader(e: Encoded, out: *[tls.record_header_len]u8) []const u8 {
        out[0] = @backingInt(tls.ContentType.handshake);
        mem.writeInt(u16, out[1..3], @backingInt(tls.ProtocolVersion.tls_1_0), .big);
        mem.writeInt(u16, out[3..5], @intCast(e.msg.len), .big);
        return out;
    }
};

/// Serialize a ClientHello handshake message into `buf`.
pub fn encode(buf: []u8, p: Params) Error!Encoded {
    if (p.session_id.len > 32) return error.InvalidParameter;

    var c: Cursor = .{ .buf = buf };

    try c.byte(@backingInt(tls.HandshakeType.client_hello));
    const hs_len = try c.open(3);

    try c.word(@backingInt(tls.ProtocolVersion.tls_1_2));
    const random_at = c.pos;
    try c.bytes(&p.random);

    try c.byte(@intCast(p.session_id.len));
    const sid_at = c.pos;
    try c.bytes(p.session_id);

    {
        const at = try c.open(2);
        for (p.cipher_suites) |cs| try c.word(@backingInt(cs));
        try c.close(at, 2);
    }

    // legacy_compression_methods = { null }
    try c.byte(1);
    try c.byte(@backingInt(tls.CompressionMethod.null));

    {
        const at = try c.open(2);
        for (p.extensions) |ext| try encodeExtension(&c, ext);
        try c.close(at, 2);
    }

    try c.close(hs_len, 3);

    return .{
        .msg = buf[0..c.pos],
        .random = buf[random_at..][0..32],
        .session_id = buf[sid_at..][0..p.session_id.len],
    };
}

fn encodeExtension(c: *Cursor, ext: Extension) Error!void {
    switch (ext) {
        .server_name => |host| {
            try c.word(@backingInt(tls.ExtensionType.server_name));
            const at = try c.open(2);
            const list = try c.open(2);
            try c.byte(0); // NameType.host_name
            try c.vec(1 << 16, host);
            try c.close(list, 2);
            try c.close(at, 2);
        },
        .supported_versions => |vs| {
            try c.word(@backingInt(tls.ExtensionType.supported_versions));
            const at = try c.open(2);
            const list = try c.open(1);
            for (vs) |v| try c.word(@backingInt(v));
            try c.close(list, 1);
            try c.close(at, 2);
        },
        .supported_groups => |gs| {
            try c.word(@backingInt(tls.ExtensionType.supported_groups));
            const at = try c.open(2);
            const list = try c.open(2);
            for (gs) |g| try c.word(@backingInt(g));
            try c.close(list, 2);
            try c.close(at, 2);
        },
        .signature_algorithms => |ss| {
            try c.word(@backingInt(tls.ExtensionType.signature_algorithms));
            const at = try c.open(2);
            const list = try c.open(2);
            for (ss) |s| try c.word(@backingInt(s));
            try c.close(list, 2);
            try c.close(at, 2);
        },
        .key_share => |shares| {
            try c.word(@backingInt(tls.ExtensionType.key_share));
            const at = try c.open(2);
            const list = try c.open(2);
            for (shares) |ks| {
                try c.word(@backingInt(ks.group));
                try c.vec(1 << 16, ks.public_key);
            }
            try c.close(list, 2);
            try c.close(at, 2);
        },
        .psk_key_exchange_modes => |modes| {
            try c.word(@backingInt(tls.ExtensionType.psk_key_exchange_modes));
            const at = try c.open(2);
            const list = try c.open(1);
            for (modes) |m| try c.byte(@backingInt(m));
            try c.close(list, 1);
            try c.close(at, 2);
        },
        .alpn => |protos| {
            try c.word(@backingInt(tls.ExtensionType.application_layer_protocol_negotiation));
            const at = try c.open(2);
            const list = try c.open(2);
            for (protos) |name| try c.vec(1 << 8, name);
            try c.close(list, 2);
            try c.close(at, 2);
        },
        .record_size_limit => |limit| {
            try c.word(0x001c);
            try c.word(2);
            try c.word(limit);
        },
        .padding => |n| {
            try c.word(@backingInt(tls.ExtensionType.padding));
            try c.word(n);
            try c.need(n);
            @memset(c.buf[c.pos..][0..n], 0);
            c.pos += n;
        },
        .raw => |r| {
            try c.word(r.type);
            try c.vec(1 << 16, r.data);
        },
    }
}

/// Bounds-checked big-endian writer with support for back-patched length prefixes.
const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn need(c: *Cursor, n: usize) Error!void {
        if (c.pos + n > c.buf.len) return error.BufferTooSmall;
    }

    fn byte(c: *Cursor, v: u8) Error!void {
        try c.need(1);
        c.buf[c.pos] = v;
        c.pos += 1;
    }

    fn word(c: *Cursor, v: u16) Error!void {
        try c.need(2);
        mem.writeInt(u16, c.buf[c.pos..][0..2], v, .big);
        c.pos += 2;
    }

    fn bytes(c: *Cursor, b: []const u8) Error!void {
        try c.need(b.len);
        @memcpy(c.buf[c.pos..][0..b.len], b);
        c.pos += b.len;
    }

    /// Length-prefixed opaque vector. `limit` is the exclusive upper bound of
    /// the length field (1<<8 or 1<<16).
    fn vec(c: *Cursor, comptime limit: usize, b: []const u8) Error!void {
        if (b.len >= limit) return error.InvalidParameter;
        switch (limit) {
            1 << 8 => try c.byte(@intCast(b.len)),
            1 << 16 => try c.word(@intCast(b.len)),
            else => @compileError("unsupported vector limit"),
        }
        try c.bytes(b);
    }

    /// Reserve a `width`-byte length prefix; returns its position for `close`.
    fn open(c: *Cursor, comptime width: u8) Error!usize {
        try c.need(width);
        const at = c.pos;
        c.pos += width;
        return at;
    }

    /// Back-patch the length prefix reserved by `open` with the number of
    /// bytes written since.
    fn close(c: *Cursor, at: usize, comptime width: u8) Error!void {
        const len = c.pos - at - width;
        switch (width) {
            1 => {
                if (len > std.math.maxInt(u8)) return error.InvalidParameter;
                c.buf[at] = @intCast(len);
            },
            2 => {
                if (len > std.math.maxInt(u16)) return error.InvalidParameter;
                mem.writeInt(u16, c.buf[at..][0..2], @intCast(len), .big);
            },
            3 => {
                if (len > std.math.maxInt(u24)) return error.InvalidParameter;
                mem.writeInt(u24, c.buf[at..][0..3], @intCast(len), .big);
            },
            else => @compileError("unsupported length width"),
        }
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const rfc8448 = @import("testdata/rfc8448.zig");

fn scheme(v: u16) tls.SignatureScheme {
    return @fromBackingInt(v);
}

/// Parameters reproducing the RFC 8448 section 3 ClientHello byte-for-byte.
pub fn rfc8448Params() Params {
    const S = struct {
        const groups = [_]tls.NamedGroup{
            .x25519,    .secp256r1, .secp384r1, .secp521r1, .ffdhe2048,
            .ffdhe3072, .ffdhe4096, .ffdhe6144, .ffdhe8192,
        };
        const sigs = [_]tls.SignatureScheme{
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ecdsa_secp521r1_sha512,
            .ecdsa_sha1,             .rsa_pss_rsae_sha256,    .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,    .rsa_pkcs1_sha256,       .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,       .rsa_pkcs1_sha1,         .dsa_sha256,
            .dsa_sha384,             .dsa_sha512,             scheme(0x0202),
        };
        const shares = [_]KeyShareEntry{
            .{ .group = .x25519, .public_key = &rfc8448.client_pub },
        };
        const versions = [_]tls.ProtocolVersion{.tls_1_3};
        const modes = [_]tls.PskKeyExchangeMode{.psk_dhe_ke};
        const suites = [_]tls.CipherSuite{
            .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256, .AES_256_GCM_SHA384,
        };
        const exts = [_]Extension{
            .{ .server_name = "server" },
            .{ .raw = .{ .type = 0xff01, .data = &.{0} } }, // renegotiation_info
            .{ .supported_groups = &groups },
            .{ .raw = .{ .type = 0x0023 } }, // session_ticket (empty)
            .{ .key_share = &shares },
            .{ .supported_versions = &versions },
            .{ .signature_algorithms = &sigs },
            .{ .psk_key_exchange_modes = &modes },
            .{ .record_size_limit = 0x4001 },
        };
    };
    return .{
        .random = rfc8448.client_hello[6..38].*,
        .cipher_suites = &S.suites,
        .extensions = &S.exts,
    };
}

test "ClientHello matches RFC 8448 section 3 byte-for-byte" {
    var buf: [512]u8 = undefined;
    const enc = try encode(&buf, rfc8448Params());
    try testing.expectEqualSlices(u8, &rfc8448.client_hello, enc.msg);
    try testing.expectEqualSlices(u8, rfc8448.client_hello[6..38], enc.random);
    try testing.expectEqual(@as(usize, 0), enc.session_id.len);

    var hdr: [tls.record_header_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x16, 0x03, 0x01, 0x00, 0xc4 }, enc.recordHeader(&hdr));
}

test "session_id is reserved and back-fillable" {
    var buf: [512]u8 = undefined;
    var p = rfc8448Params();
    const zeros: [32]u8 = @splat(0);
    p.session_id = &zeros;
    const enc = try encode(&buf, p);

    try testing.expectEqual(rfc8448.client_hello.len + 32, enc.msg.len);
    try testing.expectEqual(@as(usize, Encoded.session_id_offset), @intFromPtr(enc.session_id.ptr) - @intFromPtr(enc.msg.ptr));
    try testing.expectEqual(@as(u8, 32), enc.msg[Encoded.session_id_offset - 1]);
    try testing.expectEqual(@as(usize, Encoded.random_offset), @intFromPtr(enc.random) - @intFromPtr(enc.msg.ptr));

    // Back-fill, as REALITY does after computing the AEAD over the whole message.
    var sid: [32]u8 = undefined;
    for (&sid, 0..) |*b, i| b.* = @intCast(i);
    @memcpy(enc.session_id, &sid);
    try testing.expectEqualSlices(u8, &sid, enc.msg[Encoded.session_id_offset..][0..32]);

    // Everything after the session_id is the RFC message shifted by 32.
    try testing.expectEqualSlices(u8, rfc8448.client_hello[39..], enc.msg[39 + 32 ..]);
    // Handshake length header reflects the extra 32 bytes.
    try testing.expectEqual(@as(u24, @intCast(enc.msg.len - 4)), mem.readInt(u24, enc.msg[1..4], .big));
}

test "session_id longer than 32 is rejected" {
    var buf: [512]u8 = undefined;
    var p = rfc8448Params();
    const too_long: [33]u8 = @splat(0);
    p.session_id = &too_long;
    try testing.expectError(error.InvalidParameter, encode(&buf, p));
}

test "buffer too small is reported, not overrun" {
    var buf: [100]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encode(&buf, rfc8448Params()));
}

test "alpn and padding encode per spec" {
    var buf: [256]u8 = undefined;
    const protos = [_][]const u8{ "h2", "http/1.1" };
    const exts = [_]Extension{
        .{ .alpn = &protos },
        .{ .padding = 3 },
    };
    const suites = [_]tls.CipherSuite{.AES_128_GCM_SHA256};
    const enc = try encode(&buf, .{
        .random = @splat(0xaa),
        .cipher_suites = &suites,
        .extensions = &exts,
    });
    const ext_start = 4 + 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1;
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x19, // extensions length: alpn (4+14) + padding (4+3)
        0x00, 0x10,
        0x00, 0x0e,
        0x00, 0x0c,
        0x02, 'h',
        '2',  0x08,
        'h',  't',
        't',  'p',
        '/',  '1',
        '.',  '1',
        0x00, 0x15,
        0x00, 0x03,
        0x00, 0x00,
        0x00,
    }, enc.msg[ext_start..]);
}
