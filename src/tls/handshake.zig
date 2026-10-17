//! TLS 1.3 handshake message reassembly and parsing of the server's flight:
//! ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished.
//!
//! Handshake messages may be split across records or share a record, so
//! decrypted handshake fragments are pushed into a `Reassembler` which yields
//! whole messages. Parsing is zero-copy: parsed structs borrow from the
//! reassembler's buffer until `next()` is called again.

const std = @import("std");
const tls = std.crypto.tls;
const mem = std.mem;

pub const Error = error{
    /// Message truncated or a length field exceeds its container.
    DecodeError,
    /// Field value violates RFC 8446 for a TLS 1.3 server.
    IllegalParameter,
    /// Server chose a protocol version other than TLS 1.3.
    ProtocolVersion,
    /// Server sent HelloRetryRequest; unsupported by zray.
    HelloRetryRequest,
    /// Required extension is absent.
    MissingExtension,
    /// Reassembly buffer exhausted.
    BufferTooSmall,
};

pub const Message = struct {
    type: tls.HandshakeType,
    /// Full message including the 4-byte header (feed this to the transcript).
    raw: []const u8,
    /// Message body.
    body: []const u8,
};

/// Accumulates handshake fragments and yields complete messages.
pub const Reassembler = struct {
    buf: []u8,
    /// Bytes in `buf` that are valid.
    len: usize = 0,
    /// Bytes in `buf` already returned by `next`.
    consumed: usize = 0,

    pub fn init(buf: []u8) Reassembler {
        return .{ .buf = buf };
    }

    /// Append a decrypted handshake fragment.
    pub fn push(r: *Reassembler, fragment: []const u8) Error!void {
        if (r.buf.len - r.len < fragment.len) {
            r.compact();
            if (r.buf.len - r.len < fragment.len) return error.BufferTooSmall;
        }
        @memcpy(r.buf[r.len..][0..fragment.len], fragment);
        r.len += fragment.len;
    }

    /// Return the next complete message, or null if more data is needed.
    /// Invalidates slices returned by the previous call once `push` runs.
    pub fn next(r: *Reassembler) Error!?Message {
        const avail = r.buf[r.consumed..r.len];
        if (avail.len < 4) return null;
        const body_len = mem.readInt(u24, avail[1..4], .big);
        if (body_len > tls.max_ciphertext_inner_record_len * 4) return error.DecodeError;
        const total = 4 + body_len;
        if (avail.len < total) {
            if (total > r.buf.len) return error.BufferTooSmall;
            return null;
        }
        r.consumed += total;
        return .{
            .type = @fromBackingInt(avail[0]),
            .raw = avail[0..total],
            .body = avail[4..total],
        };
    }

    /// True when no partial message is buffered.
    pub fn isEmpty(r: *const Reassembler) bool {
        return r.consumed == r.len;
    }

    fn compact(r: *Reassembler) void {
        if (r.consumed == 0) return;
        const rem = r.len - r.consumed;
        mem.copyForwards(u8, r.buf[0..rem], r.buf[r.consumed..r.len]);
        r.len = rem;
        r.consumed = 0;
    }
};

/// Bounds-checked big-endian reader over immutable bytes.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn remaining(r: *const Reader) usize {
        return r.buf.len - r.pos;
    }

    pub fn eof(r: *const Reader) bool {
        return r.pos == r.buf.len;
    }

    pub fn bytes(r: *Reader, n: usize) Error![]const u8 {
        if (r.remaining() < n) return error.DecodeError;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    pub fn readU8(r: *Reader) Error!u8 {
        return (try r.bytes(1))[0];
    }

    pub fn readU16(r: *Reader) Error!u16 {
        return mem.readInt(u16, (try r.bytes(2))[0..2], .big);
    }

    pub fn readU24(r: *Reader) Error!u24 {
        return mem.readInt(u24, (try r.bytes(3))[0..3], .big);
    }

    /// Opaque vector with a 1-, 2- or 3-byte length prefix.
    pub fn vec(r: *Reader, comptime width: u8) Error![]const u8 {
        const n: usize = switch (width) {
            1 => try r.readU8(),
            2 => try r.readU16(),
            3 => try r.readU24(),
            else => @compileError("bad width"),
        };
        return r.bytes(n);
    }

    /// Sub-reader over a length-prefixed vector.
    pub fn sub(r: *Reader, comptime width: u8) Error!Reader {
        return Reader.init(try r.vec(width));
    }
};

pub const KeyShare = struct {
    group: tls.NamedGroup,
    public_key: []const u8,
};

pub const ServerHello = struct {
    random: *const [32]u8,
    session_id_echo: []const u8,
    cipher_suite: tls.CipherSuite,
    key_share: KeyShare,

    /// Parse a ServerHello body. Rejects HelloRetryRequest and anything that
    /// does not negotiate TLS 1.3.
    pub fn parse(body: []const u8) Error!ServerHello {
        var r = Reader.init(body);
        if (try r.readU16() != @backingInt(tls.ProtocolVersion.tls_1_2)) return error.ProtocolVersion;
        const random = (try r.bytes(32))[0..32];
        if (mem.eql(u8, random, &tls.hello_retry_request_sequence)) return error.HelloRetryRequest;
        const session_id_echo = try r.vec(1);
        if (session_id_echo.len > 32) return error.IllegalParameter;
        const cipher_suite: tls.CipherSuite = @fromBackingInt(try r.readU16());
        if (try r.readU8() != @backingInt(tls.CompressionMethod.null)) return error.IllegalParameter;

        var selected_version: ?u16 = null;
        var key_share: ?KeyShare = null;

        var exts = try r.sub(2);
        if (!r.eof()) return error.DecodeError;
        while (!exts.eof()) {
            const et: tls.ExtensionType = @fromBackingInt(try exts.readU16());
            var data = try exts.sub(2);
            switch (et) {
                .supported_versions => {
                    if (selected_version != null) return error.IllegalParameter;
                    selected_version = try data.readU16();
                },
                .key_share => {
                    if (key_share != null) return error.IllegalParameter;
                    key_share = .{
                        .group = @fromBackingInt(try data.readU16()),
                        .public_key = try data.vec(2),
                    };
                },
                // pre_shared_key would appear here for resumption; we never
                // offer a PSK so a server sending it is misbehaving.
                .pre_shared_key => return error.IllegalParameter,
                else => return error.IllegalParameter,
            }
            if (!data.eof()) return error.DecodeError;
        }

        if (selected_version != @backingInt(tls.ProtocolVersion.tls_1_3)) return error.ProtocolVersion;
        return .{
            .random = random,
            .session_id_echo = session_id_echo,
            .cipher_suite = cipher_suite,
            .key_share = key_share orelse return error.MissingExtension,
        };
    }
};

pub const EncryptedExtensions = struct {
    /// Negotiated ALPN protocol, if the server selected one.
    alpn: ?[]const u8 = null,

    pub fn parse(body: []const u8) Error!EncryptedExtensions {
        var r = Reader.init(body);
        var exts = try r.sub(2);
        if (!r.eof()) return error.DecodeError;
        var out: EncryptedExtensions = .{};
        while (!exts.eof()) {
            const et: tls.ExtensionType = @fromBackingInt(try exts.readU16());
            var data = try exts.sub(2);
            switch (et) {
                .application_layer_protocol_negotiation => {
                    var list = try data.sub(2);
                    out.alpn = try list.vec(1);
                    if (!list.eof()) return error.IllegalParameter;
                    if (!data.eof()) return error.DecodeError;
                },
                // server_name (empty ack), supported_groups, early_data,
                // max_fragment_length, record_size_limit, ALPS... are all
                // informational for us.
                else => {},
            }
        }
        return out;
    }
};

pub const Certificate = struct {
    request_context: []const u8,
    /// Raw certificate_list vector contents; iterate with `entries`.
    list: []const u8,

    pub const Entry = struct {
        /// DER-encoded X.509 certificate.
        der: []const u8,
        extensions: []const u8,
    };

    pub const Iterator = struct {
        r: Reader,

        pub fn next(it: *Iterator) Error!?Entry {
            if (it.r.eof()) return null;
            const der = try it.r.vec(3);
            const extensions = try it.r.vec(2);
            if (der.len == 0) return error.IllegalParameter;
            return .{ .der = der, .extensions = extensions };
        }
    };

    pub fn parse(body: []const u8) Error!Certificate {
        var r = Reader.init(body);
        const ctx = try r.vec(1);
        const list = try r.vec(3);
        if (!r.eof()) return error.DecodeError;
        return .{ .request_context = ctx, .list = list };
    }

    pub fn entries(c: Certificate) Iterator {
        return .{ .r = Reader.init(c.list) };
    }

    /// The end-entity (leaf) certificate.
    pub fn leaf(c: Certificate) Error!Entry {
        var it = c.entries();
        return (try it.next()) orelse error.IllegalParameter;
    }
};

pub const CertificateVerify = struct {
    scheme: tls.SignatureScheme,
    signature: []const u8,

    pub fn parse(body: []const u8) Error!CertificateVerify {
        var r = Reader.init(body);
        const scheme: tls.SignatureScheme = @fromBackingInt(try r.readU16());
        const signature = try r.vec(2);
        if (!r.eof()) return error.DecodeError;
        return .{ .scheme = scheme, .signature = signature };
    }

    /// Content that was signed (RFC 8446 §4.4.3): 64 spaces, context
    /// string, 0x00, transcript hash. Written into `out`; returns the slice.
    pub fn signedContent(transcript_hash: []const u8, out: []u8) Error![]u8 {
        const ctx = "TLS 1.3, server CertificateVerify";
        const total = 64 + ctx.len + 1 + transcript_hash.len;
        if (out.len < total) return error.BufferTooSmall;
        @memset(out[0..64], 0x20);
        @memcpy(out[64..][0..ctx.len], ctx);
        out[64 + ctx.len] = 0;
        @memcpy(out[64 + ctx.len + 1 ..][0..transcript_hash.len], transcript_hash);
        return out[0..total];
    }

    pub const max_signed_content_len = 64 + "TLS 1.3, server CertificateVerify".len + 1 + 64;
};

pub const Finished = struct {
    verify_data: []const u8,

    pub fn parse(body: []const u8) Error!Finished {
        if (body.len == 0 or body.len > 64) return error.DecodeError;
        return .{ .verify_data = body };
    }

    /// Serialize a Finished message (header included) into `out`.
    pub fn encode(verify_data: []const u8, out: []u8) Error![]u8 {
        const total = 4 + verify_data.len;
        if (out.len < total) return error.BufferTooSmall;
        out[0] = @backingInt(tls.HandshakeType.finished);
        mem.writeInt(u24, out[1..4], @intCast(verify_data.len), .big);
        @memcpy(out[4..][0..verify_data.len], verify_data);
        return out[0..total];
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const rfc8448 = @import("testdata/rfc8448.zig");

test "ServerHello parse (RFC 8448)" {
    const sh = try ServerHello.parse(rfc8448.server_hello[4..]);
    try testing.expectEqualSlices(u8, rfc8448.server_hello[6..38], sh.random);
    try testing.expectEqual(@as(usize, 0), sh.session_id_echo.len);
    try testing.expectEqual(tls.CipherSuite.AES_128_GCM_SHA256, sh.cipher_suite);
    try testing.expectEqual(tls.NamedGroup.x25519, sh.key_share.group);
    try testing.expectEqualSlices(u8, &rfc8448.server_pub, sh.key_share.public_key);
}

test "ServerHello rejects HelloRetryRequest and TLS 1.2" {
    var hrr = rfc8448.server_hello;
    hrr[6..38].* = tls.hello_retry_request_sequence;
    try testing.expectError(error.HelloRetryRequest, ServerHello.parse(hrr[4..]));

    var v12 = rfc8448.server_hello;
    // supported_versions is the last extension: ... 00 2b 00 02 03 04
    v12[v12.len - 1] = 0x03;
    try testing.expectError(error.ProtocolVersion, ServerHello.parse(v12[4..]));

    // Truncated.
    try testing.expectError(error.DecodeError, ServerHello.parse(rfc8448.server_hello[4 .. rfc8448.server_hello.len - 3]));
}

test "reassemble and parse the server flight across fragments" {
    const flight = rfc8448.enc_ext ++ rfc8448.certificate ++ rfc8448.cert_verify ++ rfc8448.s_finished_msg;
    var buf: [1024]u8 = undefined;
    var ra = Reassembler.init(&buf);

    // Split inside the Certificate message and inside Finished's header.
    try ra.push(flight[0..100]);
    const m0 = (try ra.next()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(tls.HandshakeType.encrypted_extensions, m0.type);
    try testing.expectEqualSlices(u8, &rfc8448.enc_ext, m0.raw);
    const ee = try EncryptedExtensions.parse(m0.body);
    try testing.expectEqual(@as(?[]const u8, null), ee.alpn);
    try testing.expectEqual(@as(?Message, null), try ra.next());

    try ra.push(flight[100 .. flight.len - 30]);
    const m1 = (try ra.next()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(tls.HandshakeType.certificate, m1.type);
    const cert = try Certificate.parse(m1.body);
    try testing.expectEqual(@as(usize, 0), cert.request_context.len);
    const leaf = try cert.leaf();
    try testing.expectEqual(@as(usize, 0x1b0), leaf.der.len);
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x82, 0x01, 0xac }, leaf.der[0..4]);
    var it = cert.entries();
    _ = try it.next();
    try testing.expectEqual(@as(?Certificate.Entry, null), try it.next());

    const m2 = (try ra.next()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(tls.HandshakeType.certificate_verify, m2.type);
    const cv = try CertificateVerify.parse(m2.body);
    try testing.expectEqual(tls.SignatureScheme.rsa_pss_rsae_sha256, cv.scheme);
    try testing.expectEqual(@as(usize, 128), cv.signature.len);
    try testing.expectEqual(@as(?Message, null), try ra.next());

    try ra.push(flight[flight.len - 30 ..]);
    const m3 = (try ra.next()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(tls.HandshakeType.finished, m3.type);
    const fin = try Finished.parse(m3.body);
    try testing.expectEqualSlices(u8, &rfc8448.s_finished_verify, fin.verify_data);
    try testing.expect(ra.isEmpty());
}

test "reassembler compacts when buffer fills" {
    var buf: [64]u8 = undefined;
    var ra = Reassembler.init(&buf);
    // 40-byte message, then another 40-byte message: second push requires compaction.
    var msg: [40]u8 = @splat(0xab);
    msg[0] = 0x14;
    mem.writeInt(u24, msg[1..4], 36, .big);
    try ra.push(&msg);
    _ = (try ra.next()) orelse return error.TestUnexpectedResult;
    try ra.push(&msg);
    const m = (try ra.next()) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &msg, m.raw);

    // A message that can never fit is an error, not a hang.
    var huge_hdr = [_]u8{ 0x0b, 0x00, 0x10, 0x00 };
    try ra.push(&huge_hdr);
    try testing.expectError(error.BufferTooSmall, ra.next());
}

test "Finished encode round-trips RFC client Finished" {
    var out: [64]u8 = undefined;
    const msg = try Finished.encode(&rfc8448.c_finished_verify, &out);
    try testing.expectEqualSlices(u8, &rfc8448.c_finished_msg, msg);
}

test "CertificateVerify signed content layout" {
    var out: [CertificateVerify.max_signed_content_len]u8 = undefined;
    const h: [32]u8 = @splat(0x5a);
    const sc = try CertificateVerify.signedContent(&h, &out);
    try testing.expectEqual(@as(usize, 64 + 33 + 1 + 32), sc.len);
    try testing.expectEqualSlices(u8, "TLS 1.3, server CertificateVerify", sc[64..97]);
    try testing.expectEqual(@as(u8, 0), sc[97]);
    try testing.expectEqualSlices(u8, &h, sc[98..]);
}
