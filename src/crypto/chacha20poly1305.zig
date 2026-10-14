const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

/// High-performance AEAD engine for BackPack tunnel protocol.
/// Implements ChaCha20-Poly1305 with Noise protocol 96-bit nonce derivation.
/// All hot-path methods operate strictly with zero heap memory allocations.
pub const AeadEngine = struct {
    key: [KEY_LEN]u8,

    pub const KEY_LEN: usize = 32;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;
    pub const MAX_FRAME_SIZE: usize = 65535;

    pub fn init(key: [KEY_LEN]u8) AeadEngine {
        return .{ .key = key };
    }

    /// Wipes sensitive key material from memory.
    pub fn wipe(self: *AeadEngine) void {
        @memset(&self.key, 0);
    }

    /// Derives 96-bit Noise protocol nonce from 64-bit counter:
    /// 4 zero bytes followed by 8 big-endian counter bytes.
    pub inline fn nonceFromCounter(counter: u64) [NONCE_LEN]u8 {
        var nonce: [NONCE_LEN]u8 = [_]u8{0} ** NONCE_LEN;
        std.mem.writeInt(u64, nonce[4..12], counter, .big);
        return nonce;
    }

    /// Encrypts in-place or into dst buffer using an explicit 12-byte nonce.
    /// Appends 16-byte Poly1305 authentication tag to dst[plaintext.len .. plaintext.len + TAG_LEN].
    /// Returns total ciphertext length (plaintext.len + TAG_LEN).
    /// Zero heap allocations in the hot path.
    pub fn sealWithNonce(
        self: AeadEngine,
        dst: []u8,
        nonce: [NONCE_LEN]u8,
        ad: []const u8,
        plaintext: []const u8,
    ) error{BufferTooSmall}!usize {
        const required = plaintext.len + TAG_LEN;
        if (dst.len < required) return error.BufferTooSmall;

        var tag: [TAG_LEN]u8 = undefined;
        ChaCha20Poly1305.encrypt(dst[0..plaintext.len], &tag, plaintext, ad, nonce, self.key);
        @memcpy(dst[plaintext.len..required], &tag);

        return required;
    }

    /// Encrypts using 64-bit packet sequence counter (Noise protocol nonce).
    /// Appends 16-byte Poly1305 authentication tag to dst[plaintext.len .. plaintext.len + TAG_LEN].
    /// Returns total ciphertext length (plaintext.len + TAG_LEN).
    /// Zero heap allocations in the hot path.
    pub inline fn seal(
        self: AeadEngine,
        dst: []u8,
        counter: u64,
        ad: []const u8,
        plaintext: []const u8,
    ) error{BufferTooSmall}!usize {
        return self.sealWithNonce(dst, nonceFromCounter(counter), ad, plaintext);
    }

    /// In-place seal directly modifying the buffer using an explicit 12-byte nonce.
    /// buffer must have at least payload_len + TAG_LEN capacity.
    /// Zero heap allocations in the hot path.
    pub fn sealWithNonceInPlace(
        self: AeadEngine,
        buffer: []u8,
        payload_len: usize,
        nonce: [NONCE_LEN]u8,
        ad: []const u8,
    ) error{BufferTooSmall}!usize {
        const required = payload_len + TAG_LEN;
        if (buffer.len < required) return error.BufferTooSmall;

        var tag: [TAG_LEN]u8 = undefined;
        ChaCha20Poly1305.encrypt(buffer[0..payload_len], &tag, buffer[0..payload_len], ad, nonce, self.key);
        @memcpy(buffer[payload_len..required], &tag);

        return required;
    }

    /// In-place seal directly modifying the buffer using 64-bit sequence counter.
    /// buffer must have at least payload_len + TAG_LEN capacity.
    /// Zero heap allocations in the hot path.
    pub inline fn sealInPlace(
        self: AeadEngine,
        buffer: []u8,
        payload_len: usize,
        counter: u64,
        ad: []const u8,
    ) error{BufferTooSmall}!usize {
        return self.sealWithNonceInPlace(buffer, payload_len, nonceFromCounter(counter), ad);
    }

    /// Decrypts ciphertext with authentication using an explicit 12-byte nonce.
    /// body must contain ciphertext followed by 16-byte tag.
    /// Returns slice of plaintext in dst.
    /// Wipes dst on authentication failure to prevent plaintext leakage.
    /// Zero heap allocations in the hot path.
    pub fn openWithNonce(
        self: AeadEngine,
        dst: []u8,
        nonce: [NONCE_LEN]u8,
        ad: []const u8,
        body: []const u8,
    ) error{ ShortCiphertext, AuthenticationFailed, BufferTooSmall }![]u8 {
        if (body.len < TAG_LEN) return error.ShortCiphertext;
        const ciphertext_len = body.len - TAG_LEN;
        if (dst.len < ciphertext_len) return error.BufferTooSmall;

        var tag: [TAG_LEN]u8 = undefined;
        @memcpy(&tag, body[ciphertext_len..]);

        ChaCha20Poly1305.decrypt(dst[0..ciphertext_len], body[0..ciphertext_len], tag, ad, nonce, self.key) catch {
            @memset(dst[0..ciphertext_len], 0);
            return error.AuthenticationFailed;
        };

        return dst[0..ciphertext_len];
    }

    /// Decrypts ciphertext with authentication using 64-bit sequence counter.
    /// body must contain ciphertext followed by 16-byte tag.
    /// Returns slice of plaintext in dst.
    /// Zero heap allocations in the hot path.
    pub inline fn open(
        self: AeadEngine,
        dst: []u8,
        counter: u64,
        ad: []const u8,
        body: []const u8,
    ) error{ ShortCiphertext, AuthenticationFailed, BufferTooSmall }![]u8 {
        return self.openWithNonce(dst, nonceFromCounter(counter), ad, body);
    }

    /// In-place open directly in body buffer using an explicit 12-byte nonce.
    /// Returns slice of decrypted plaintext.
    /// Wipes body on authentication failure to prevent plaintext leakage.
    /// Zero heap allocations in the hot path.
    pub fn openWithNonceInPlace(
        self: AeadEngine,
        body: []u8,
        nonce: [NONCE_LEN]u8,
        ad: []const u8,
    ) error{ ShortCiphertext, AuthenticationFailed }![]u8 {
        if (body.len < TAG_LEN) return error.ShortCiphertext;
        const ciphertext_len = body.len - TAG_LEN;

        var tag: [TAG_LEN]u8 = undefined;
        @memcpy(&tag, body[ciphertext_len..]);

        ChaCha20Poly1305.decrypt(body[0..ciphertext_len], body[0..ciphertext_len], tag, ad, nonce, self.key) catch {
            @memset(body[0..ciphertext_len], 0);
            return error.AuthenticationFailed;
        };

        return body[0..ciphertext_len];
    }

    /// In-place open directly in body buffer using 64-bit sequence counter.
    /// Returns slice of decrypted plaintext.
    /// Zero heap allocations in the hot path.
    pub inline fn openInPlace(
        self: AeadEngine,
        body: []u8,
        counter: u64,
        ad: []const u8,
    ) error{ ShortCiphertext, AuthenticationFailed }![]u8 {
        return self.openWithNonceInPlace(body, nonceFromCounter(counter), ad);
    }
};

/// High-resolution benchmark result measuring throughput and timings.
pub const BenchmarkResult = struct {
    payload_len: usize,
    iterations: usize,
    enc_duration_ns: u64,
    dec_duration_ns: u64,
    enc_mb_per_sec: f64, // Decimal MB/s (10^6 bytes/s)
    dec_mb_per_sec: f64,
    enc_mib_per_sec: f64, // Binary MiB/s (2^20 bytes/s)
    dec_mib_per_sec: f64,
    enc_gb_per_sec: f64, // Decimal GB/s (10^9 bytes/s)
    dec_gb_per_sec: f64,

    pub fn format(
        self: BenchmarkResult,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print(
            "ChaCha20-Poly1305 Benchmark [{d} bytes, {d} iters]:\n" ++
                "  Encrypt: {d:.2} ms | {d:.2} MB/s ({d:.2} MiB/s) | {d:.3} GB/s\n" ++
                "  Decrypt: {d:.2} ms | {d:.2} MB/s ({d:.2} MiB/s) | {d:.3} GB/s\n",
            .{
                self.payload_len,
                self.iterations,
                @as(f64, @floatFromInt(self.enc_duration_ns)) / 1_000_000.0,
                self.enc_mb_per_sec,
                self.enc_mib_per_sec,
                self.enc_gb_per_sec,
                @as(f64, @floatFromInt(self.dec_duration_ns)) / 1_000_000.0,
                self.dec_mb_per_sec,
                self.dec_mib_per_sec,
                self.dec_gb_per_sec,
            },
        );
    }
};

/// Preallocated zero-allocation buffers for static benchmark execution up to MAX_FRAME_SIZE.
const BenchStaticBuffers = struct {
    var plain_buf: [AeadEngine.MAX_FRAME_SIZE]u8 = undefined;
    var cipher_buf: [AeadEngine.MAX_FRAME_SIZE + AeadEngine.TAG_LEN]u8 = undefined;
    var dec_buf: [AeadEngine.MAX_FRAME_SIZE]u8 = undefined;
    var initialized: bool = false;

    fn initBuffers() void {
        if (!initialized) {
            for (&plain_buf, 0..) |*b, i| {
                b.* = @truncate(i *% 37 +% 11);
            }
            initialized = true;
        }
    }
};

/// Runs benchmark with caller-provided buffers (100% zero memory allocations).
pub fn benchmarkWithBuffers(
    engine: AeadEngine,
    plain: []const u8,
    cipher_buf: []u8,
    dec_buf: []u8,
    ad: []const u8,
    iterations: usize,
) !BenchmarkResult {
    if (cipher_buf.len < plain.len + AeadEngine.TAG_LEN) return error.BufferTooSmall;
    if (dec_buf.len < plain.len) return error.BufferTooSmall;

    var timer = try std.time.Timer.start();

    // 1. Benchmark Encryption
    var counter: u64 = 0;
    while (counter < iterations) : (counter += 1) {
        _ = try engine.seal(cipher_buf, counter, ad, plain);
    }
    const enc_duration_ns = timer.lap();

    // 2. Benchmark Decryption
    // cipher_buf holds the valid ciphertext from the final iteration (counter = iterations - 1)
    const final_counter = if (iterations > 0) iterations - 1 else 0;
    const sealed_len = plain.len + AeadEngine.TAG_LEN;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        _ = try engine.open(dec_buf, final_counter, ad, cipher_buf[0..sealed_len]);
    }
    const dec_duration_ns = timer.read();

    const total_bytes = @as(f64, @floatFromInt(plain.len * iterations));
    const enc_secs = @as(f64, @floatFromInt(enc_duration_ns)) / 1_000_000_000.0;
    const dec_secs = @as(f64, @floatFromInt(dec_duration_ns)) / 1_000_000_000.0;

    const enc_mb_s = if (enc_secs > 0) (total_bytes / 1_000_000.0) / enc_secs else 0.0;
    const dec_mb_s = if (dec_secs > 0) (total_bytes / 1_000_000.0) / dec_secs else 0.0;

    const enc_mib_s = if (enc_secs > 0) (total_bytes / (1024.0 * 1024.0)) / enc_secs else 0.0;
    const dec_mib_s = if (dec_secs > 0) (total_bytes / (1024.0 * 1024.0)) / dec_secs else 0.0;

    return BenchmarkResult{
        .payload_len = plain.len,
        .iterations = iterations,
        .enc_duration_ns = enc_duration_ns,
        .dec_duration_ns = dec_duration_ns,
        .enc_mb_per_sec = enc_mb_s,
        .dec_mb_per_sec = dec_mb_s,
        .enc_mib_per_sec = enc_mib_s,
        .dec_mib_per_sec = dec_mib_s,
        .enc_gb_per_sec = enc_mb_s / 1000.0,
        .dec_gb_per_sec = dec_mb_s / 1000.0,
    };
}

/// Convenience benchmark measuring AEAD throughput for a given payload size up to 65535 bytes.
/// Uses static buffers ensuring ZERO heap allocations during benchmark execution.
pub fn benchmark(payload_size: usize, iterations: usize) !BenchmarkResult {
    if (payload_size > AeadEngine.MAX_FRAME_SIZE) return error.PayloadTooLarge;

    BenchStaticBuffers.initBuffers();

    const key = [_]u8{0x5A} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const ad = [_]u8{ 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 };

    const plain = BenchStaticBuffers.plain_buf[0..payload_size];
    const cipher = BenchStaticBuffers.cipher_buf[0 .. payload_size + AeadEngine.TAG_LEN];
    const dec = BenchStaticBuffers.dec_buf[0..payload_size];

    return benchmarkWithBuffers(engine, plain, cipher, dec, &ad, iterations);
}

// ============================================================================
//                                UNIT TESTS
// ============================================================================

test "AeadEngine - RFC 8439 Section 2.8.2 official test vector" {
    // Official RFC 8439 Section 2.8.2 Test Vector
    const key = [_]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce = [_]u8{ 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    const ad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    const expected_ciphertext = [_]u8{
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    };
    const expected_tag = [_]u8{
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };

    const engine = AeadEngine.init(key);

    // 1. Out-of-place seal verification
    var cipher_buf: [plaintext.len + AeadEngine.TAG_LEN]u8 = undefined;
    const sealed_len = try engine.sealWithNonce(&cipher_buf, nonce, &ad, plaintext);
    try std.testing.expectEqual(plaintext.len + AeadEngine.TAG_LEN, sealed_len);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, cipher_buf[0..plaintext.len]);
    try std.testing.expectEqualSlices(u8, &expected_tag, cipher_buf[plaintext.len..sealed_len]);

    // 2. Out-of-place open verification
    var plain_buf: [plaintext.len]u8 = undefined;
    const decrypted = try engine.openWithNonce(&plain_buf, nonce, &ad, cipher_buf[0..sealed_len]);
    try std.testing.expectEqualStrings(plaintext, decrypted);

    // 3. In-place seal & open verification
    var in_place_buf: [plaintext.len + AeadEngine.TAG_LEN]u8 = undefined;
    @memcpy(in_place_buf[0..plaintext.len], plaintext);
    const in_place_sealed_len = try engine.sealWithNonceInPlace(&in_place_buf, plaintext.len, nonce, &ad);
    try std.testing.expectEqual(plaintext.len + AeadEngine.TAG_LEN, in_place_sealed_len);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, in_place_buf[0..plaintext.len]);
    try std.testing.expectEqualSlices(u8, &expected_tag, in_place_buf[plaintext.len..in_place_sealed_len]);

    const in_place_decrypted = try engine.openWithNonceInPlace(&in_place_buf, nonce, &ad);
    try std.testing.expectEqualStrings(plaintext, in_place_decrypted);
}

test "AeadEngine - Noise protocol nonce derivation from counter" {
    // 1. Counter = 0
    const nonce0 = AeadEngine.nonceFromCounter(0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &nonce0);

    // 2. Counter = 1
    const nonce1 = AeadEngine.nonceFromCounter(1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &nonce1);

    // 3. Counter = 0x0123456789abcdef (Big Endian)
    const nonce_hex = AeadEngine.nonceFromCounter(0x0123456789abcdef);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, &nonce_hex);

    // 4. Counter = maxInt(u64)
    const nonce_max = AeadEngine.nonceFromCounter(std.math.maxInt(u64));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, &nonce_max);
}

test "AeadEngine - standard roundtrip and in-place roundtrip" {
    const key = [_]u8{0x42} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);

    const plaintext = "Hello BackPack Tunnel from Zig DataPlane Core!";
    const ad = [_]u8{ 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07 };
    const counter: u64 = 7;

    // Out-of-place
    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, &ad, plaintext);
    try std.testing.expectEqual(plaintext.len + AeadEngine.TAG_LEN, sealed_len);

    var plain_buf: [128]u8 = undefined;
    const opened = try engine.open(&plain_buf, counter, &ad, cipher_buf[0..sealed_len]);
    try std.testing.expectEqualStrings(plaintext, opened);

    // In-place
    var in_place_buf: [128]u8 = undefined;
    @memcpy(in_place_buf[0..plaintext.len], plaintext);
    const ip_sealed_len = try engine.sealInPlace(&in_place_buf, plaintext.len, counter, &ad);
    try std.testing.expectEqual(plaintext.len + AeadEngine.TAG_LEN, ip_sealed_len);

    const ip_opened = try engine.openInPlace(in_place_buf[0..ip_sealed_len], counter, &ad);
    try std.testing.expectEqualStrings(plaintext, ip_opened);
}

test "AeadEngine - edge case: empty payload (0 bytes)" {
    const key = [_]u8{0x33} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const counter: u64 = 100;
    const empty_plaintext = "";
    const ad = "header-auth-only";

    // 1. With non-empty AD
    var cipher_buf: [AeadEngine.TAG_LEN]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, ad, empty_plaintext);
    try std.testing.expectEqual(AeadEngine.TAG_LEN, sealed_len);

    var plain_buf: [16]u8 = undefined;
    const opened = try engine.open(&plain_buf, counter, ad, cipher_buf[0..sealed_len]);
    try std.testing.expectEqual(@as(usize, 0), opened.len);

    // In-place with empty payload
    var in_place_buf: [AeadEngine.TAG_LEN]u8 = undefined;
    const ip_sealed_len = try engine.sealInPlace(&in_place_buf, 0, counter, ad);
    try std.testing.expectEqual(AeadEngine.TAG_LEN, ip_sealed_len);
    const ip_opened = try engine.openInPlace(&in_place_buf, counter, ad);
    try std.testing.expectEqual(@as(usize, 0), ip_opened.len);

    // 2. With empty AD
    const empty_ad = "";
    var cipher_buf2: [AeadEngine.TAG_LEN]u8 = undefined;
    const sealed_len2 = try engine.seal(&cipher_buf2, counter, empty_ad, empty_plaintext);
    try std.testing.expectEqual(AeadEngine.TAG_LEN, sealed_len2);

    const opened2 = try engine.open(&plain_buf, counter, empty_ad, cipher_buf2[0..sealed_len2]);
    try std.testing.expectEqual(@as(usize, 0), opened2.len);
}

test "AeadEngine - edge case: 1-byte payload" {
    const key = [_]u8{0x77} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const counter: u64 = 200;
    const one_byte = [_]u8{0x99};
    const ad = "ad-for-1-byte";

    // Out-of-place
    var cipher_buf: [1 + AeadEngine.TAG_LEN]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, ad, &one_byte);
    try std.testing.expectEqual(@as(usize, 1 + AeadEngine.TAG_LEN), sealed_len);

    var plain_buf: [1]u8 = undefined;
    const opened = try engine.open(&plain_buf, counter, ad, cipher_buf[0..sealed_len]);
    try std.testing.expectEqualSlices(u8, &one_byte, opened);

    // In-place
    var in_place_buf: [1 + AeadEngine.TAG_LEN]u8 = undefined;
    in_place_buf[0] = one_byte[0];
    const ip_sealed_len = try engine.sealInPlace(&in_place_buf, 1, counter, ad);
    try std.testing.expectEqual(@as(usize, 1 + AeadEngine.TAG_LEN), ip_sealed_len);

    const ip_opened = try engine.openInPlace(&in_place_buf, counter, ad);
    try std.testing.expectEqualSlices(u8, &one_byte, ip_opened);
}

test "AeadEngine - edge case: typical MTU packets (1420 bytes)" {
    const key = [_]u8{0x88} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const counter: u64 = 555;
    const ad = [_]u8{ 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 55 };

    var plaintext: [1420]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @truncate(i *% 17 +% 3);
    }

    var cipher_buf: [1420 + AeadEngine.TAG_LEN]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, &ad, &plaintext);
    try std.testing.expectEqual(@as(usize, 1420 + AeadEngine.TAG_LEN), sealed_len);

    var plain_buf: [1420]u8 = undefined;
    const opened = try engine.open(&plain_buf, counter, &ad, cipher_buf[0..sealed_len]);
    try std.testing.expectEqualSlices(u8, &plaintext, opened);
}

test "AeadEngine - edge case: max jumbo frame (65535 bytes)" {
    const key = [_]u8{0xAB} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const counter: u64 = 0xFFFF_0000;
    const ad = "jumbo-frame-header-test-ad-bytes";

    // Allocate on BSS / static to preserve stack
    const JumboState = struct {
        var plain: [AeadEngine.MAX_FRAME_SIZE]u8 = undefined;
        var cipher: [AeadEngine.MAX_FRAME_SIZE + AeadEngine.TAG_LEN]u8 = undefined;
        var plain_out: [AeadEngine.MAX_FRAME_SIZE]u8 = undefined;
    };

    for (&JumboState.plain, 0..) |*b, i| {
        b.* = @truncate(i *% 63 +% 19);
    }

    // 1. Out-of-place 65535 bytes
    const sealed_len = try engine.seal(&JumboState.cipher, counter, ad, &JumboState.plain);
    try std.testing.expectEqual(@as(usize, 65535 + AeadEngine.TAG_LEN), sealed_len);

    const opened = try engine.open(&JumboState.plain_out, counter, ad, JumboState.cipher[0..sealed_len]);
    try std.testing.expectEqualSlices(u8, &JumboState.plain, opened);

    // 2. In-place 65535 bytes
    @memcpy(JumboState.cipher[0..65535], &JumboState.plain);
    const ip_sealed_len = try engine.sealInPlace(&JumboState.cipher, 65535, counter, ad);
    try std.testing.expectEqual(@as(usize, 65535 + AeadEngine.TAG_LEN), ip_sealed_len);

    const ip_opened = try engine.openInPlace(JumboState.cipher[0..ip_sealed_len], counter, ad);
    try std.testing.expectEqualSlices(u8, &JumboState.plain, ip_opened);

    // 3. Tamper 1 bit in jumbo frame payload -> must fail
    JumboState.cipher[32768] ^= 0x01;
    const tampered = engine.open(&JumboState.plain_out, counter, ad, JumboState.cipher[0..ip_sealed_len]);
    try std.testing.expectError(error.AuthenticationFailed, tampered);
}

test "AeadEngine - tampered counter rejection" {
    const key = [_]u8{0x99} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const plaintext = "Payload protected under counter 12345";
    const ad = "anti-replay-counter-ad";
    const counter: u64 = 12345;

    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, ad, plaintext);

    var plain_buf: [128]u8 = undefined;

    // 1. Counter incremented (+1)
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter + 1, ad, cipher_buf[0..sealed_len]),
    );

    // 2. Counter decremented (-1)
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter - 1, ad, cipher_buf[0..sealed_len]),
    );

    // 3. Counter bit flip
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter ^ 1, ad, cipher_buf[0..sealed_len]),
    );

    // 4. Counter 0
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, 0, ad, cipher_buf[0..sealed_len]),
    );

    // 5. Counter max
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, std.math.maxInt(u64), ad, cipher_buf[0..sealed_len]),
    );
}

test "AeadEngine - tampered nonce rejection" {
    const key = [_]u8{0xAA} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const plaintext = "Payload with explicit nonce testing";
    const ad = "nonce-integrity-check";
    const nonce = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine.sealWithNonce(&cipher_buf, nonce, ad, plaintext);

    var plain_buf: [128]u8 = undefined;

    // Test flipping a bit in each byte of the 12-byte nonce
    var i: usize = 0;
    while (i < AeadEngine.NONCE_LEN) : (i += 1) {
        var tampered_nonce = nonce;
        tampered_nonce[i] ^= 0x01;

        try std.testing.expectError(
            error.AuthenticationFailed,
            engine.openWithNonce(&plain_buf, tampered_nonce, ad, cipher_buf[0..sealed_len]),
        );
    }
}

test "AeadEngine - tampered ciphertext rejection" {
    const key = [_]u8{0xBB} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const plaintext = "Sensitive VPN packet data must fail authentication if modified anywhere!";
    const ad = "ad-tag";
    const counter: u64 = 777;

    var cipher_buf: [256]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, ad, plaintext);

    var plain_buf: [256]u8 = undefined;

    // 1. Tamper byte 0 (start)
    var c1 = cipher_buf;
    c1[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, engine.open(&plain_buf, counter, ad, c1[0..sealed_len]));

    // 2. Tamper byte plaintext.len / 2 (middle)
    var c2 = cipher_buf;
    c2[plaintext.len / 2] ^= 0x80;
    try std.testing.expectError(error.AuthenticationFailed, engine.open(&plain_buf, counter, ad, c2[0..sealed_len]));

    // 3. Tamper byte plaintext.len - 1 (end of ciphertext right before tag)
    var c3 = cipher_buf;
    c3[plaintext.len - 1] ^= 0x40;
    try std.testing.expectError(error.AuthenticationFailed, engine.open(&plain_buf, counter, ad, c3[0..sealed_len]));
}

test "AeadEngine - tampered tag rejection" {
    const key = [_]u8{0xCC} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const plaintext = "Testing Poly1305 authentication tag tamper detection";
    const ad = "ad-data";
    const counter: u64 = 888;

    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, ad, plaintext);

    var plain_buf: [128]u8 = undefined;

    // Test flipping a bit in every byte of the 16-byte Poly1305 tag
    var tag_offset: usize = plaintext.len;
    while (tag_offset < sealed_len) : (tag_offset += 1) {
        var tampered = cipher_buf;
        tampered[tag_offset] ^= 0x01;

        try std.testing.expectError(
            error.AuthenticationFailed,
            engine.open(&plain_buf, counter, ad, tampered[0..sealed_len]),
        );
    }
}

test "AeadEngine - tampered associated data (AD) rejection" {
    const key = [_]u8{0xDD} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const plaintext = "Payload bound to specific associated header data";
    const ad = "tunnel-header-v1";
    const counter: u64 = 999;

    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, counter, ad, plaintext);

    var plain_buf: [128]u8 = undefined;

    // 1. Modified AD
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter, "tunnel-header-v2", cipher_buf[0..sealed_len]),
    );

    // 2. Truncated AD
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter, "tunnel-header-v", cipher_buf[0..sealed_len]),
    );

    // 3. Appended AD
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter, "tunnel-header-v1!", cipher_buf[0..sealed_len]),
    );

    // 4. Empty AD
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine.open(&plain_buf, counter, "", cipher_buf[0..sealed_len]),
    );
}

test "AeadEngine - wrong key rejection" {
    const key_a = [_]u8{0x11} ** AeadEngine.KEY_LEN;
    const key_b = [_]u8{0x22} ** AeadEngine.KEY_LEN;
    const engine_a = AeadEngine.init(key_a);
    const engine_b = AeadEngine.init(key_b);

    const plaintext = "Secret payload encrypted with key A";
    const counter: u64 = 1;

    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine_a.seal(&cipher_buf, counter, "", plaintext);

    var plain_buf: [128]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        engine_b.open(&plain_buf, counter, "", cipher_buf[0..sealed_len]),
    );
}

test "AeadEngine - short ciphertext and buffer boundary error handling" {
    const key = [_]u8{0xEE} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    var plain_buf: [64]u8 = undefined;

    // Short ciphertext (< TAG_LEN = 16)
    var short_buf: [15]u8 = [_]u8{0} ** 15;
    var len: usize = 0;
    while (len < AeadEngine.TAG_LEN) : (len += 1) {
        try std.testing.expectError(
            error.ShortCiphertext,
            engine.open(&plain_buf, 0, "", short_buf[0..len]),
        );
        try std.testing.expectError(
            error.ShortCiphertext,
            engine.openInPlace(short_buf[0..len], 0, ""),
        );
    }

    // Destination buffer too small for seal
    const plaintext = "Testing buffer sizes";
    var tiny_cipher: [plaintext.len + AeadEngine.TAG_LEN - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        engine.seal(&tiny_cipher, 0, "", plaintext),
    );

    // Buffer too small for sealInPlace
    var tiny_ip: [plaintext.len + AeadEngine.TAG_LEN - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        engine.sealInPlace(&tiny_ip, plaintext.len, 0, ""),
    );

    // Destination buffer too small for open
    var valid_cipher: [plaintext.len + AeadEngine.TAG_LEN]u8 = undefined;
    const sealed_len = try engine.seal(&valid_cipher, 0, "", plaintext);
    var tiny_dst: [plaintext.len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        engine.open(&tiny_dst, 0, "", valid_cipher[0..sealed_len]),
    );
}

test "AeadEngine - memory wipe on authentication failure" {
    const key = [_]u8{0xFF} ** AeadEngine.KEY_LEN;
    const engine = AeadEngine.init(key);
    const plaintext = "Payload that should not leak in dst buffer on failure!";

    var cipher_buf: [128]u8 = undefined;
    const sealed_len = try engine.seal(&cipher_buf, 1, "", plaintext);

    // Tamper ciphertext
    cipher_buf[0] ^= 0x01;

    // Initialize destination buffer with sentinel non-zero value
    var dst_buf: [128]u8 = [_]u8{0xAA} ** 128;
    const res = engine.open(&dst_buf, 1, "", cipher_buf[0..sealed_len]);
    try std.testing.expectError(error.AuthenticationFailed, res);

    // Plaintext section must be securely wiped with zeros
    for (dst_buf[0..plaintext.len]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "AeadEngine - throughput benchmark" {
    // Benchmark 64B (control / ping packets)
    const res64 = try benchmark(64, 1000);
    try std.testing.expect(res64.enc_mb_per_sec > 0);
    try std.testing.expect(res64.dec_mb_per_sec > 0);

    // Benchmark 1420B (standard VPN MTU)
    const res1420 = try benchmark(1420, 1000);
    try std.testing.expect(res1420.enc_mb_per_sec > 0);
    try std.testing.expect(res1420.dec_mb_per_sec > 0);

    // Benchmark 65535B (max jumbo frame)
    const res65k = try benchmark(65535, 50);
    try std.testing.expect(res65k.enc_mb_per_sec > 0);
    try std.testing.expect(res65k.dec_mb_per_sec > 0);

    // Output formatted results to debug log
    std.debug.print("\n=== ChaCha20-Poly1305 Throughput Benchmark Results ===\n", .{});
    std.debug.print("{}\n", .{res64});
    std.debug.print("{}\n", .{res1420});
    std.debug.print("{}\n", .{res65k});
    std.debug.print("======================================================\n", .{});
}
