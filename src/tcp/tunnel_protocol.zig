const std = @import("std");
const crypto = @import("../crypto/chacha20poly1305.zig");

/// Stealth TLS Chameleon Protocol Framing for Zig TCP Tunnel.
/// Disguises all initial handshakes as genuine TLS 1.3 records
/// to complement the multidisorder:pos=2:seqovl=1:urg Desync engine.

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_MAJOR_VERSION: u8 = 0x03;
pub const TLS_MINOR_VERSION: u8 = 0x01; // TLS 1.0/1.2 wire record header
pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

pub const HANDSHAKE_PAYLOAD_LEN: usize = 48;
pub const TOTAL_HANDSHAKE_LEN: usize = 5 + HANDSHAKE_PAYLOAD_LEN; // 53 bytes

pub const DATA_HEADER_LEN: usize = 2 + 8 + 16; // Length (2) + Counter (8) + Tag (16) = 26 bytes
pub const MAX_FRAME_PAYLOAD: usize = 16384; // 16 KB per frame
pub const MAX_TOTAL_FRAME_LEN: usize = DATA_HEADER_LEN + MAX_FRAME_PAYLOAD;

/// Derives a 32-byte ChaCha20 key from an arbitrary user passphrase.
pub fn deriveKeyFromPassphrase(passphrase: []const u8, out_key: *[32]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("ZGTP-STEALTH-SALT-2026-KEY");
    hasher.update(passphrase);
    hasher.final(out_key);
}

/// Builds a TLS-Chameleon Client Handshake payload into `out_buf` (53 bytes).
pub fn buildClientHandshake(
    out_buf: []u8,
    key: *const [32]u8,
    client_nonce: *const [16]u8,
) !usize {
    std.debug.assert(out_buf.len >= TOTAL_HANDSHAKE_LEN);

    // 5-byte TLS Record Header
    out_buf[0] = TLS_RECORD_HANDSHAKE;
    out_buf[1] = TLS_MAJOR_VERSION;
    out_buf[2] = TLS_MINOR_VERSION;
    std.mem.writeInt(u16, out_buf[3..5], @as(u16, @intCast(HANDSHAKE_PAYLOAD_LEN)), .big);

    // Handshake body
    out_buf[5] = TLS_HANDSHAKE_CLIENT_HELLO;
    // 3 bytes handshake length
    out_buf[6] = 0x00;
    std.mem.writeInt(u16, out_buf[7..9], @as(u16, @intCast(HANDSHAKE_PAYLOAD_LEN - 4)), .big);

    // 16 bytes client nonce
    @memcpy(out_buf[9..25], client_nonce);

    // Session identifier padding
    @memset(out_buf[25..37], 0xAA);

    // Compute HMAC-SHA256 Auth Tag (16 bytes) over the handshake bytes
    // Store Poly1305 auth tag in the last 16 bytes
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(out_buf[0..37]);
    var full_hmac: [32]u8 = undefined;
    hmac.final(&full_hmac);
    @memcpy(out_buf[37..53], full_hmac[0..16]);

    return TOTAL_HANDSHAKE_LEN;
}

/// Verifies a received Client Handshake payload.
pub fn verifyClientHandshake(
    buf: []const u8,
    key: *const [32]u8,
    out_client_nonce: *[16]u8,
) bool {
    if (buf.len < TOTAL_HANDSHAKE_LEN) return false;
    if (buf[0] != TLS_RECORD_HANDSHAKE) return false;
    if (buf[1] != TLS_MAJOR_VERSION) return false;
    if (buf[5] != TLS_HANDSHAKE_CLIENT_HELLO) return false;

    // Verify HMAC tag
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(buf[0..37]);
    var expected_hmac: [32]u8 = undefined;
    hmac.final(&expected_hmac);

    if (!std.crypto.utils.timingSafeEql([16]u8, buf[37..53].*, expected_hmac[0..16].*)) {
        return false;
    }

    @memcpy(out_client_nonce, buf[9..25]);
    return true;
}

/// Builds a Server Handshake Response payload (53 bytes).
pub fn buildServerHandshake(
    out_buf: []u8,
    key: *const [32]u8,
    server_nonce: *const [16]u8,
) !usize {
    std.debug.assert(out_buf.len >= TOTAL_HANDSHAKE_LEN);

    out_buf[0] = TLS_RECORD_HANDSHAKE;
    out_buf[1] = TLS_MAJOR_VERSION;
    out_buf[2] = 0x03; // TLS 1.3 ServerHello indication
    std.mem.writeInt(u16, out_buf[3..5], @as(u16, @intCast(HANDSHAKE_PAYLOAD_LEN)), .big);

    out_buf[5] = TLS_HANDSHAKE_SERVER_HELLO;
    out_buf[6] = 0x00;
    std.mem.writeInt(u16, out_buf[7..9], @as(u16, @intCast(HANDSHAKE_PAYLOAD_LEN - 4)), .big);

    @memcpy(out_buf[9..25], server_nonce);
    @memset(out_buf[25..37], 0x55);

    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(out_buf[0..37]);
    var full_hmac: [32]u8 = undefined;
    hmac.final(&full_hmac);
    @memcpy(out_buf[37..53], full_hmac[0..16]);

    return TOTAL_HANDSHAKE_LEN;
}

/// Verifies a received Server Handshake response.
pub fn verifyServerHandshake(
    buf: []const u8,
    key: *const [32]u8,
    out_server_nonce: *[16]u8,
) bool {
    if (buf.len < TOTAL_HANDSHAKE_LEN) return false;
    if (buf[0] != TLS_RECORD_HANDSHAKE) return false;
    if (buf[1] != TLS_MAJOR_VERSION) return false;
    if (buf[5] != TLS_HANDSHAKE_SERVER_HELLO) return false;

    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key);
    hmac.update(buf[0..37]);
    var expected_hmac: [32]u8 = undefined;
    hmac.final(&expected_hmac);

    if (!std.crypto.utils.timingSafeEql([16]u8, buf[37..53].*, expected_hmac[0..16].*)) {
        return false;
    }

    @memcpy(out_server_nonce, buf[9..25]);
    return true;
}

/// Encrypts and frames a data packet.
/// Format: [Length: u16] [Counter: u64] [Encrypted Payload + Poly1305 Tag: 16 bytes]
pub fn encryptFrame(
    out_buf: []u8,
    engine: *const crypto.AeadEngine,
    counter: u64,
    plaintext: []const u8,
) !usize {
    const payload_len = plaintext.len;
    std.debug.assert(payload_len <= MAX_FRAME_PAYLOAD);
    const total_len = 2 + 8 + payload_len + 16;
    std.debug.assert(out_buf.len >= total_len);

    std.mem.writeInt(u16, out_buf[0..2], @as(u16, @intCast(payload_len)), .big);
    std.mem.writeInt(u64, out_buf[2..10], counter, .big);

    // Additional data covers length and counter
    const ad = out_buf[0..10];
    const sealed_len = try engine.seal(out_buf[10..total_len], counter, ad, plaintext);
    std.debug.assert(sealed_len == payload_len + 16);

    return total_len;
}

/// Decrypts a received data frame.
pub fn decryptFrame(
    out_plain: []u8,
    engine: *const crypto.AeadEngine,
    frame: []const u8,
) !struct { payload_len: usize, counter: u64 } {
    if (frame.len < DATA_HEADER_LEN) return error.ShortFrame;

    const payload_len = std.mem.readInt(u16, frame[0..2], .big);
    const counter = std.mem.readInt(u64, frame[2..10], .big);

    const expected_total = 10 + payload_len + 16;
    if (frame.len < expected_total) return error.IncompleteFrame;

    const ad = frame[0..10];
    const opened = try engine.open(out_plain, counter, ad, frame[10..expected_total]);

    return .{
        .payload_len = opened.len,
        .counter = counter,
    };
}

// ============================================================================
// Unit Tests
// ============================================================================

test "TLS chameleon handshake build and verification" {
    var key: [32]u8 = undefined;
    deriveKeyFromPassphrase("MySecurePassword2026", &key);

    var client_nonce: [16]u8 = [_]u8{0x42} ** 16;
    var hs_buf: [128]u8 = undefined;

    const len = try buildClientHandshake(&hs_buf, &key, &client_nonce);
    try std.testing.expectEqual(TOTAL_HANDSHAKE_LEN, len);

    // Verify TLS record header
    try std.testing.expectEqual(TLS_RECORD_HANDSHAKE, hs_buf[0]);
    try std.testing.expectEqual(TLS_MAJOR_VERSION, hs_buf[1]);
    try std.testing.expectEqual(TLS_MINOR_VERSION, hs_buf[2]);

    // Verify verification succeeds
    var out_nonce: [16]u8 = undefined;
    try std.testing.expect(verifyClientHandshake(hs_buf[0..len], &key, &out_nonce));
    try std.testing.expectEqualSlices(u8, &client_nonce, &out_nonce);

    // Verify tampering fails
    hs_buf[10] ^= 0xFF;
    try std.testing.expect(!verifyClientHandshake(hs_buf[0..len], &key, &out_nonce));
}

test "data frame encryption and decryption" {
    var key: [32]u8 = undefined;
    deriveKeyFromPassphrase("SessionKey123", &key);
    const engine = crypto.AeadEngine.init(key);

    const msg = "HELLO SECURE ZIG TCP TUNNEL WITH DESYNC!";
    var frame_buf: [256]u8 = undefined;

    const frame_len = try encryptFrame(&frame_buf, &engine, 42, msg);

    var decrypted: [256]u8 = undefined;
    const res = try decryptFrame(&decrypted, &engine, frame_buf[0..frame_len]);

    try std.testing.expectEqual(@as(u64, 42), res.counter);
    try std.testing.expectEqualStrings(msg, decrypted[0..res.payload_len]);
}
