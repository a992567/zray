//! TLS 1.3 key schedule (RFC 8446 §7.1) with transcript hash.
//!
//! The schedule is generic over the suite's hash. Secrets are derived in the
//! order the handshake forces:
//!
//!   init()                    -> early_secret
//!   update(ClientHello)
//!   update(ServerHello)
//!   setSharedSecret(ecdhe)    -> handshake_secret, master_secret
//!   handshakeTraffic()        -> c/s hs traffic secrets   (transcript = CH..SH)
//!   update(EE, Cert, CV, SFin)
//!   applicationTraffic()      -> c/s ap traffic secrets   (transcript = CH..SFin)
//!   update(CFin)
//!   resumptionMaster()        -> res master               (transcript = CH..CFin)
//!
//! Only the PSK-less path is implemented (early secret from a zero PSK). PSK
//! resumption and 0-RTT are deliberately out of scope for zray.

const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;

pub const Sha256 = KeySchedule(crypto.hash.sha2.Sha256);
pub const Sha384 = KeySchedule(crypto.hash.sha2.Sha384);

pub fn KeySchedule(comptime HashType: type) type {
    return struct {
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
        pub const digest_length = Hash.digest_length;
        pub const Secret = [digest_length]u8;

        const Self = @This();
        const zeroes: [digest_length]u8 = @splat(0);

        transcript: Hash,
        early_secret: Secret,
        handshake_secret: Secret,
        master_secret: Secret,

        pub fn init() Self {
            return .{
                .transcript = Hash.init(.{}),
                // HKDF-Extract(salt=0, IKM=0^HashLen); salt "0" and "" are
                // equivalent for HMAC key padding.
                .early_secret = Hkdf.extract(&[1]u8{0}, &zeroes),
                .handshake_secret = undefined,
                .master_secret = undefined,
            };
        }

        /// Feed one complete handshake message (including its 4-byte header)
        /// into the transcript.
        pub fn update(self: *Self, handshake_msg: []const u8) void {
            self.transcript.update(handshake_msg);
        }

        /// Current transcript hash without consuming the hasher.
        pub fn transcriptHash(self: *const Self) Secret {
            return self.transcript.peek();
        }

        /// Derive handshake_secret and master_secret from the (EC)DHE shared
        /// secret. Transcript position does not matter for this step.
        pub fn setSharedSecret(self: *Self, shared_secret: []const u8) void {
            const empty_hash = tls.emptyHash(Hash);
            const hs_derived = expandLabel(self.early_secret, "derived", &empty_hash, digest_length);
            self.handshake_secret = Hkdf.extract(&hs_derived, shared_secret);
            const ap_derived = expandLabel(self.handshake_secret, "derived", &empty_hash, digest_length);
            self.master_secret = Hkdf.extract(&ap_derived, &zeroes);
        }

        pub const TrafficSecrets = struct {
            client: Secret,
            server: Secret,
        };

        /// Call with transcript = ClientHello..ServerHello.
        pub fn handshakeTraffic(self: *const Self) TrafficSecrets {
            const h = self.transcriptHash();
            return .{
                .client = expandLabel(self.handshake_secret, "c hs traffic", &h, digest_length),
                .server = expandLabel(self.handshake_secret, "s hs traffic", &h, digest_length),
            };
        }

        /// Call with transcript = ClientHello..server Finished.
        pub fn applicationTraffic(self: *const Self) TrafficSecrets {
            const h = self.transcriptHash();
            return .{
                .client = expandLabel(self.master_secret, "c ap traffic", &h, digest_length),
                .server = expandLabel(self.master_secret, "s ap traffic", &h, digest_length),
            };
        }

        /// Call with transcript = ClientHello..server Finished.
        pub fn exporterMaster(self: *const Self) Secret {
            const h = self.transcriptHash();
            return expandLabel(self.master_secret, "exp master", &h, digest_length);
        }

        /// Call with transcript = ClientHello..client Finished.
        pub fn resumptionMaster(self: *const Self) Secret {
            const h = self.transcriptHash();
            return expandLabel(self.master_secret, "res master", &h, digest_length);
        }

        /// Per-direction AEAD key and IV for a traffic secret (RFC 8446 §7.3).
        pub fn TrafficKeys(comptime Aead: type) type {
            return struct {
                key: [Aead.key_length]u8,
                iv: [Aead.nonce_length]u8,
            };
        }

        pub fn trafficKeys(comptime Aead: type, secret: Secret) TrafficKeys(Aead) {
            return .{
                .key = expandLabel(secret, "key", "", Aead.key_length),
                .iv = expandLabel(secret, "iv", "", Aead.nonce_length),
            };
        }

        /// KeyUpdate: next-generation traffic secret (RFC 8446 §7.2).
        pub fn nextTrafficSecret(secret: Secret) Secret {
            return expandLabel(secret, "traffic upd", "", digest_length);
        }

        /// finished_key for a handshake traffic secret (RFC 8446 §4.4.4).
        pub fn finishedKey(traffic_secret: Secret) [Hmac.key_length]u8 {
            return expandLabel(traffic_secret, "finished", "", Hmac.key_length);
        }

        /// verify_data = HMAC(finished_key, transcript_hash). The caller passes
        /// the transcript hash as of just before the Finished message.
        pub fn verifyData(traffic_secret: Secret, transcript_hash: Secret) [Hmac.mac_length]u8 {
            return tls.hmac(Hmac, &transcript_hash, finishedKey(traffic_secret));
        }

        /// Constant-time comparison of a peer's Finished.verify_data.
        pub fn checkVerifyData(traffic_secret: Secret, transcript_hash: Secret, received: []const u8) bool {
            const expected = verifyData(traffic_secret, transcript_hash);
            if (received.len != expected.len) return false;
            return crypto.timing_safe.eql([Hmac.mac_length]u8, expected, received[0..Hmac.mac_length].*);
        }

        pub fn expandLabel(secret: Secret, label: []const u8, context: []const u8, comptime len: usize) [len]u8 {
            return tls.hkdfExpandLabel(Hkdf, secret, label, context, len);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests: RFC 8448 §3 full 1-RTT trace, TLS_AES_128_GCM_SHA256.

const testing = std.testing;
const rfc8448 = @import("testdata/rfc8448.zig");
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

test "RFC 8448 §3 key schedule end-to-end" {
    const KS = Sha256;
    var ks = KS.init();
    try testing.expectEqualSlices(u8, &rfc8448.early_secret, &ks.early_secret);

    // ECDHE with the RFC's ephemeral keys.
    const shared = try crypto.dh.X25519.scalarmult(rfc8448.client_priv, rfc8448.server_pub);
    try testing.expectEqualSlices(u8, &rfc8448.shared_secret, &shared);

    ks.update(&rfc8448.client_hello);
    ks.update(&rfc8448.server_hello);
    ks.setSharedSecret(&shared);
    try testing.expectEqualSlices(u8, &rfc8448.handshake_secret, &ks.handshake_secret);
    try testing.expectEqualSlices(u8, &rfc8448.master_secret, &ks.master_secret);

    const hs = ks.handshakeTraffic();
    try testing.expectEqualSlices(u8, &rfc8448.c_hs_traffic, &hs.client);
    try testing.expectEqualSlices(u8, &rfc8448.s_hs_traffic, &hs.server);

    const s_hs_keys = KS.trafficKeys(Aes128Gcm, hs.server);
    try testing.expectEqualSlices(u8, &rfc8448.s_hs_key, &s_hs_keys.key);
    try testing.expectEqualSlices(u8, &rfc8448.s_hs_iv, &s_hs_keys.iv);
    const c_hs_keys = KS.trafficKeys(Aes128Gcm, hs.client);
    try testing.expectEqualSlices(u8, &rfc8448.c_hs_key, &c_hs_keys.key);
    try testing.expectEqualSlices(u8, &rfc8448.c_hs_iv, &c_hs_keys.iv);

    ks.update(&rfc8448.enc_ext);
    ks.update(&rfc8448.certificate);
    ks.update(&rfc8448.cert_verify);

    // Server Finished is computed over the transcript *before* itself.
    const s_verify = KS.verifyData(hs.server, ks.transcriptHash());
    try testing.expectEqualSlices(u8, &rfc8448.s_finished_verify, &s_verify);
    try testing.expect(KS.checkVerifyData(hs.server, ks.transcriptHash(), rfc8448.s_finished_msg[4..]));
    try testing.expect(!KS.checkVerifyData(hs.client, ks.transcriptHash(), rfc8448.s_finished_msg[4..]));
    ks.update(&rfc8448.s_finished_msg);

    const ap = ks.applicationTraffic();
    try testing.expectEqualSlices(u8, &rfc8448.c_ap_traffic, &ap.client);
    try testing.expectEqualSlices(u8, &rfc8448.s_ap_traffic, &ap.server);
    try testing.expectEqualSlices(u8, &rfc8448.exp_master, &ks.exporterMaster());

    const s_ap_keys = KS.trafficKeys(Aes128Gcm, ap.server);
    try testing.expectEqualSlices(u8, &rfc8448.s_ap_key, &s_ap_keys.key);
    try testing.expectEqualSlices(u8, &rfc8448.s_ap_iv, &s_ap_keys.iv);
    const c_ap_keys = KS.trafficKeys(Aes128Gcm, ap.client);
    try testing.expectEqualSlices(u8, &rfc8448.c_ap_key, &c_ap_keys.key);
    try testing.expectEqualSlices(u8, &rfc8448.c_ap_iv, &c_ap_keys.iv);

    // Client Finished: transcript through server Finished.
    const c_verify = KS.verifyData(hs.client, ks.transcriptHash());
    try testing.expectEqualSlices(u8, &rfc8448.c_finished_verify, &c_verify);
    ks.update(&rfc8448.c_finished_msg);

    try testing.expectEqualSlices(u8, &rfc8448.res_master, &ks.resumptionMaster());
}

test "Sha384 schedule instantiates" {
    var ks = Sha384.init();
    ks.update("x");
    const shared: [32]u8 = @splat(1);
    ks.setSharedSecret(&shared);
    const t = ks.handshakeTraffic();
    try testing.expect(!std.mem.eql(u8, &t.client, &t.server));
    _ = Sha384.trafficKeys(crypto.aead.aes_gcm.Aes256Gcm, t.client);
}
