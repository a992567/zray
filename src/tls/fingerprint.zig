//! ClientHello parameter sets. Currently one Chrome-like profile without
//! GREASE / ML-KEM / compress_certificate; good enough for REALITY servers,
//! not a faithful fingerprint yet.

const std = @import("std");
const tls = std.crypto.tls;
const hello = @import("hello.zig");

pub const chrome_suites = [_]tls.CipherSuite{
    .AES_128_GCM_SHA256,
    .AES_256_GCM_SHA384,
    .CHACHA20_POLY1305_SHA256,
};

const groups = [_]tls.NamedGroup{ .x25519, .secp256r1, .secp384r1 };
const sig_algs = [_]tls.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .rsa_pss_rsae_sha256,
    .rsa_pkcs1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha384,
    .rsa_pkcs1_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pkcs1_sha512,
};
const versions = [_]tls.ProtocolVersion{ .tls_1_3, .tls_1_2 };
const psk_modes = [_]tls.PskKeyExchangeMode{.psk_dhe_ke};
pub const alpn_h2_http11 = [_][]const u8{ "h2", "http/1.1" };
pub const alpn_http11 = [_][]const u8{"http/1.1"};

pub const chrome_ext_count = 13;

/// Chrome-ordered extension list. `key_shares` must outlive the result.
pub fn chromeExtensions(sni: []const u8, key_shares: []const hello.KeyShareEntry) [chrome_ext_count]hello.Extension {
    return chromeExtensionsAlpn(sni, key_shares, &alpn_h2_http11);
}

pub fn chromeExtensionsAlpn(sni: []const u8, key_shares: []const hello.KeyShareEntry, alpn: []const []const u8) [chrome_ext_count]hello.Extension {
    return .{
        .{ .server_name = sni },
        .{ .raw = .{ .type = 0x0017 } }, // extended_master_secret
        .{ .raw = .{ .type = 0xff01, .data = &.{0} } }, // renegotiation_info
        .{ .supported_groups = &groups },
        .{ .raw = .{ .type = 0x000b, .data = &.{ 1, 0 } } }, // ec_point_formats
        .{ .raw = .{ .type = 0x0023 } }, // session_ticket
        .{ .alpn = alpn },
        .{ .raw = .{ .type = 0x0005, .data = &.{ 1, 0, 0, 0, 0 } } }, // status_request
        .{ .signature_algorithms = &sig_algs },
        .{ .raw = .{ .type = 0x0012 } }, // signed_certificate_timestamp
        .{ .key_share = key_shares },
        .{ .psk_key_exchange_modes = &psk_modes },
        .{ .supported_versions = &versions },
    };
}
