//! Digital signature verification for CertificateVerify (RFC 8446 §4.4.3)
//! using the leaf certificate's public key. Ported from std.crypto.tls.Client.

const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;

pub const Error = error{
    /// Scheme not supported, or does not match the certificate key type.
    BadSignatureScheme,
    /// Signature or public key malformed, or verification failed.
    BadSignature,
};

/// Public key extracted from an X.509 certificate, copied so it survives
/// reuse of the handshake buffer.
pub const PublicKey = struct {
    algo: Certificate.AlgorithmCategory,
    buf: [max_len]u8,
    len: u16,

    /// Large enough for RSA-4096 SubjectPublicKey (modulus + exponent + DER).
    pub const max_len = 600;

    pub fn fromParsed(parsed: Certificate.Parsed) error{PublicKeyTooLarge}!PublicKey {
        const key = parsed.pubKey();
        if (key.len > max_len) return error.PublicKeyTooLarge;
        var pk: PublicKey = .{ .algo = parsed.pub_key_algo, .buf = undefined, .len = @intCast(key.len) };
        @memcpy(pk.buf[0..key.len], key);
        return pk;
    }

    pub fn bytes(pk: *const PublicKey) []const u8 {
        return pk.buf[0..pk.len];
    }

    /// Verify `signature` under `scheme` over the concatenation of `msg`.
    pub fn verify(pk: *const PublicKey, scheme: tls.SignatureScheme, signature: []const u8, msg: []const []const u8) Error!void {
        const expected_algo: Certificate.AlgorithmCategory = switch (scheme) {
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => .X9_62_id_ecPublicKey,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => .rsaEncryption,
            .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 => .rsassa_pss,
            .ed25519 => .curveEd25519,
            else => return error.BadSignatureScheme,
        };
        if (pk.algo != expected_algo) return error.BadSignatureScheme;
        const pub_key = pk.bytes();

        switch (scheme) {
            inline .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => |s| {
                const Ecdsa = SchemeEcdsa(s);
                const sig = Ecdsa.Signature.fromDer(signature) catch return error.BadSignature;
                const key = Ecdsa.PublicKey.fromSec1(pub_key) catch return error.BadSignature;
                var ver = sig.verifier(key) catch return error.BadSignature;
                for (msg) |part| ver.update(part);
                ver.verify() catch return error.BadSignature;
            },
            inline .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => |s| {
                const RsaSignature = SchemeRsa(s);
                const Hash = SchemeHash(s);
                const RsaKey = Certificate.rsa.PublicKey;
                const components = RsaKey.parseDer(pub_key) catch return error.BadSignature;
                switch (components.modulus.len) {
                    inline 128, 256, 384, 512 => |modulus_len| {
                        const key: RsaKey = RsaKey.fromBytes(components.exponent, components.modulus) catch
                            return error.BadSignature;
                        if (signature.len != modulus_len) return error.BadSignature;
                        const sig = RsaSignature.fromBytes(modulus_len, signature);
                        RsaSignature.concatVerify(modulus_len, &sig, msg, key, Hash) catch
                            return error.BadSignature;
                    },
                    else => return error.BadSignature,
                }
            },
            .ed25519 => {
                const Eddsa = crypto.sign.Ed25519;
                if (signature.len != Eddsa.Signature.encoded_length) return error.BadSignature;
                if (pub_key.len != Eddsa.PublicKey.encoded_length) return error.BadSignature;
                const sig = Eddsa.Signature.fromBytes(signature[0..Eddsa.Signature.encoded_length].*);
                const key = Eddsa.PublicKey.fromBytes(pub_key[0..Eddsa.PublicKey.encoded_length].*) catch
                    return error.BadSignature;
                var ver = sig.verifier(key) catch return error.BadSignature;
                for (msg) |part| ver.update(part);
                ver.verify() catch return error.BadSignature;
            },
            else => unreachable,
        }
    }
};

fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.EcdsaP384Sha384,
        else => @compileError("bad scheme"),
    };
}

fn SchemeRsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => Certificate.rsa.PKCS1v1_5Signature,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha256,
        .rsa_pss_pss_sha384,
        .rsa_pss_pss_sha512,
        => Certificate.rsa.PSSSignature,
        else => @compileError("bad scheme"),
    };
}

fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256, .rsa_pss_rsae_sha256, .rsa_pss_pss_sha256 => crypto.hash.sha2.Sha256,
        .rsa_pkcs1_sha384, .rsa_pss_rsae_sha384, .rsa_pss_pss_sha384 => crypto.hash.sha2.Sha384,
        .rsa_pkcs1_sha512, .rsa_pss_rsae_sha512, .rsa_pss_pss_sha512 => crypto.hash.sha2.Sha512,
        else => @compileError("bad scheme"),
    };
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "ed25519 self-check" {
    const kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(3)) catch unreachable;
    const msg = "CertificateVerify content";
    const sig = kp.sign(msg, null) catch unreachable;

    var pk: PublicKey = .{ .algo = .curveEd25519, .buf = undefined, .len = 32 };
    @memcpy(pk.buf[0..32], &kp.public_key.toBytes());

    const sig_bytes = sig.toBytes();
    try pk.verify(.ed25519, &sig_bytes, &.{ "CertificateVerify", " content" });
    try testing.expectError(error.BadSignature, pk.verify(.ed25519, &sig_bytes, &.{"other"}));
    try testing.expectError(error.BadSignatureScheme, pk.verify(.rsa_pss_rsae_sha256, &sig_bytes, &.{msg}));
}
