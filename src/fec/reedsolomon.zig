const std = @import("std");

/// High-performance Galois Field GF(2^8) arithmetic and systematic Reed-Solomon FEC.
/// Designed for zero-allocation packet redundancy and reconstruction.
pub const GaloisField = struct {
    pub const ExpTable: [512]u8 = blk: {
        @setEvalBranchQuota(10000);
        var exp: [512]u8 = [_]u8{0} ** 512;
        var x: u16 = 1;
        var i: usize = 0;
        while (i < 255) : (i += 1) {
            exp[i] = @intCast(x);
            exp[i + 255] = @intCast(x);
            x = x << 1;
            if ((x & 0x100) != 0) {
                x ^= 0x11d; // Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
            }
        }
        break :blk exp;
    };

    pub const LogTable: [256]u8 = blk: {
        @setEvalBranchQuota(10000);
        var log: [256]u8 = [_]u8{0} ** 256;
        var i: usize = 0;
        while (i < 255) : (i += 1) {
            log[ExpTable[i]] = @intCast(i);
        }
        break :blk log;
    };

    pub inline fn add(a: u8, b: u8) u8 {
        return a ^ b;
    }

    pub inline fn mul(a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        const log_a: usize = LogTable[a];
        const log_b: usize = LogTable[b];
        return ExpTable[log_a + log_b];
    }

    pub inline fn div(a: u8, b: u8) u8 {
        if (a == 0) return 0;
        if (b == 0) unreachable;
        const log_a: usize = LogTable[a];
        const log_b: usize = LogTable[b];
        const log_res = (log_a + 255 - log_b) % 255;
        return ExpTable[log_res];
    }

    pub inline fn inv(a: u8) u8 {
        return div(1, a);
    }
};

/// Systematic Reed-Solomon encoder/decoder.
pub const ReedSolomon = struct {
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,

    pub const MAX_SHARDS: usize = 256;

    pub const DecodeError = error{
        TooManyMissingShards,
        InvalidShardSize,
        InvalidShardCount,
        SingularMatrix,
    };

    pub fn init(data_shards: usize, parity_shards: usize) error{InvalidShardCount}!ReedSolomon {
        if (data_shards == 0 or parity_shards == 0) return error.InvalidShardCount;
        if (data_shards + parity_shards > MAX_SHARDS) return error.InvalidShardCount;
        return .{
            .data_shards = data_shards,
            .parity_shards = parity_shards,
            .total_shards = data_shards + parity_shards,
        };
    }

    /// Cauchy coefficient for systematic generator matrix.
    pub inline fn cauchyCoeff(i: usize, j: usize, k: usize) u8 {
        // Cauchy matrix entry 1 / (x_i ^ y_j) where x_i and y_j are disjoint sets
        const x = @as(u8, @intCast(k + i));
        const y = @as(u8, @intCast(j));
        return GaloisField.inv(x ^ y);
    }

    /// Computes parity shards over given data shards.
    /// data_shards: array of slices, each of length shard_size.
    /// parity_shards: output array of slices, each pre-allocated to shard_size.
    pub fn encode(
        self: ReedSolomon,
        data: []const []const u8,
        parity: [][]u8,
        shard_size: usize,
    ) void {
        std.debug.assert(data.len == self.data_shards);
        std.debug.assert(parity.len == self.parity_shards);

        for (parity) |p| {
            @memset(p[0..shard_size], 0);
        }

        var p_idx: usize = 0;
        while (p_idx < self.parity_shards) : (p_idx += 1) {
            const p_buf = parity[p_idx];
            var d_idx: usize = 0;
            while (d_idx < self.data_shards) : (d_idx += 1) {
                const coeff = cauchyCoeff(p_idx, d_idx, self.data_shards);
                const d_buf = data[d_idx];

                // Vectorized multiply-add across shard bytes
                var b: usize = 0;
                while (b < shard_size) : (b += 1) {
                    p_buf[b] ^= GaloisField.mul(d_buf[b], coeff);
                }
            }
        }
    }

    /// Inverts an n x n matrix over GF(2^8) using Gauss-Jordan elimination.
    pub fn invertMatrix(
        n: usize,
        a: *[MAX_SHARDS][MAX_SHARDS]u8,
        inv: *[MAX_SHARDS][MAX_SHARDS]u8,
    ) DecodeError!void {
        var c: usize = 0;
        while (c < n) : (c += 1) {
            // Find pivot in column c from row c to n - 1
            var pivot_row: ?usize = null;
            var r: usize = c;
            while (r < n) : (r += 1) {
                if (a[r][c] != 0) {
                    pivot_row = r;
                    break;
                }
            }
            const p = pivot_row orelse return error.SingularMatrix;

            // Swap row c and row p
            if (p != c) {
                var k: usize = 0;
                while (k < n) : (k += 1) {
                    std.mem.swap(u8, &a[c][k], &a[p][k]);
                    std.mem.swap(u8, &inv[c][k], &inv[p][k]);
                }
            }

            // Scale row c so pivot element becomes 1
            const piv = a[c][c];
            if (piv != 1) {
                const piv_inv = GaloisField.inv(piv);
                var k: usize = c;
                while (k < n) : (k += 1) {
                    a[c][k] = GaloisField.mul(a[c][k], piv_inv);
                }
                k = 0;
                while (k < n) : (k += 1) {
                    inv[c][k] = GaloisField.mul(inv[c][k], piv_inv);
                }
            }

            // Eliminate column c in all other rows
            r = 0;
            while (r < n) : (r += 1) {
                if (r != c and a[r][c] != 0) {
                    const factor = a[r][c];
                    var k: usize = c;
                    while (k < n) : (k += 1) {
                        a[r][k] ^= GaloisField.mul(a[c][k], factor);
                    }
                    k = 0;
                    while (k < n) : (k += 1) {
                        inv[r][k] ^= GaloisField.mul(inv[c][k], factor);
                    }
                }
            }
        }
    }

    /// Reconstructs missing data shards using available data and parity shards.
    /// data: array of slices for data shards (length = data_shards). Missing shards will be written into data[i].
    /// data_present: boolean slice indicating which data shards are intact (true) vs lost (false).
    /// parity: array of slices for parity shards (length = parity_shards).
    /// parity_present: boolean slice indicating which parity shards are available (true) vs lost (false).
    /// shard_size: size of each shard in bytes.
    pub fn decode(
        self: ReedSolomon,
        data: [][]u8,
        data_present: []const bool,
        parity: []const []const u8,
        parity_present: []const bool,
        shard_size: usize,
    ) DecodeError!void {
        if (data.len != self.data_shards or data_present.len != self.data_shards) {
            return error.InvalidShardCount;
        }
        if (parity.len != self.parity_shards or parity_present.len != self.parity_shards) {
            return error.InvalidShardCount;
        }
        if (shard_size == 0) {
            return error.InvalidShardSize;
        }

        // Validate shard slice lengths
        for (data) |d| {
            if (d.len < shard_size) return error.InvalidShardSize;
        }
        for (parity, 0..) |p, i| {
            if (parity_present[i] and p.len < shard_size) return error.InvalidShardSize;
        }

        // Identify missing and present data shards
        var missing_data_indices: [MAX_SHARDS]usize = undefined;
        var present_data_indices: [MAX_SHARDS]usize = undefined;
        var missing_data_count: usize = 0;
        var present_data_count: usize = 0;

        for (data_present, 0..) |present, i| {
            if (!present) {
                missing_data_indices[missing_data_count] = i;
                missing_data_count += 1;
            } else {
                present_data_indices[present_data_count] = i;
                present_data_count += 1;
            }
        }

        // If no data shards are missing, all data is already intact!
        if (missing_data_count == 0) {
            return;
        }

        // Collect available parity shards
        var available_parity_indices: [MAX_SHARDS]usize = undefined;
        var available_parity_count: usize = 0;

        for (parity_present, 0..) |present, i| {
            if (present) {
                available_parity_indices[available_parity_count] = i;
                available_parity_count += 1;
            }
        }

        // Check if we have enough parity shards to reconstruct
        if (available_parity_count < missing_data_count) {
            return error.TooManyMissingShards;
        }

        const e = missing_data_count;

        // Build the e x e submatrix from Cauchy generator coefficients:
        // M[r][c] = cauchyCoeff(p_r, m_c, data_shards)
        var mat: [MAX_SHARDS][MAX_SHARDS]u8 = undefined;
        var inv_mat: [MAX_SHARDS][MAX_SHARDS]u8 = undefined;

        for (0..e) |r| {
            const p_idx = available_parity_indices[r];
            for (0..e) |c| {
                const d_idx = missing_data_indices[c];
                mat[r][c] = cauchyCoeff(p_idx, d_idx, self.data_shards);
                inv_mat[r][c] = if (r == c) 1 else 0;
            }
        }

        // Invert the submatrix using Gauss-Jordan elimination
        try invertMatrix(e, &mat, &inv_mat);

        // Reconstruct each lost data shard directly into the target buffer
        for (0..e) |c| {
            const target_shard_idx = missing_data_indices[c];
            const target_buf = data[target_shard_idx][0..shard_size];
            @memset(target_buf, 0);

            // Accumulate contributions from chosen parity shards:
            // sum_{r=0}^{e-1} inv_mat[c][r] * P_{p_r}
            for (0..e) |r| {
                const p_idx = available_parity_indices[r];
                const cp = inv_mat[c][r];
                if (cp == 0) continue;
                const p_buf = parity[p_idx];

                if (cp == 1) {
                    for (0..shard_size) |b| {
                        target_buf[b] ^= p_buf[b];
                    }
                } else {
                    for (0..shard_size) |b| {
                        target_buf[b] ^= GaloisField.mul(p_buf[b], cp);
                    }
                }
            }

            // Accumulate contributions from present data shards:
            // sum_{j in present_data} ( sum_{r=0}^{e-1} inv_mat[c][r] * C_{p_r, j} ) * D_j
            for (0..present_data_count) |p_i| {
                const j = present_data_indices[p_i];

                // Compute combined coefficient for data shard j
                var cd: u8 = 0;
                for (0..e) |r| {
                    const p_idx = available_parity_indices[r];
                    const c_coeff = cauchyCoeff(p_idx, j, self.data_shards);
                    cd ^= GaloisField.mul(inv_mat[c][r], c_coeff);
                }

                if (cd == 0) continue;
                const d_buf = data[j];

                if (cd == 1) {
                    for (0..shard_size) |b| {
                        target_buf[b] ^= d_buf[b];
                    }
                } else {
                    for (0..shard_size) |b| {
                        target_buf[b] ^= GaloisField.mul(d_buf[b], cd);
                    }
                }
            }
        }
    }

    /// Convenience helper when all shards (data + parity) are stored in a contiguous array.
    /// shards: array of slices of length total_shards (data_shards + parity_shards).
    /// shard_present: boolean slice of length total_shards.
    /// Reconstructs missing data shards, and regenerates missing parity shards if buffers are provided.
    pub fn decodeShards(
        self: ReedSolomon,
        shards: [][]u8,
        shard_present: []const bool,
        shard_size: usize,
    ) DecodeError!void {
        if (shards.len != self.total_shards or shard_present.len != self.total_shards) {
            return error.InvalidShardCount;
        }

        try self.decode(
            shards[0..self.data_shards],
            shard_present[0..self.data_shards],
            shards[self.data_shards..self.total_shards],
            shard_present[self.data_shards..self.total_shards],
            shard_size,
        );

        // Re-encode any missing parity shards
        for (0..self.parity_shards) |p_idx| {
            if (!shard_present[self.data_shards + p_idx]) {
                const p_buf = shards[self.data_shards + p_idx][0..shard_size];
                @memset(p_buf, 0);
                for (0..self.data_shards) |d_idx| {
                    const coeff = cauchyCoeff(p_idx, d_idx, self.data_shards);
                    const d_buf = shards[d_idx][0..shard_size];
                    for (0..shard_size) |b| {
                        p_buf[b] ^= GaloisField.mul(d_buf[b], coeff);
                    }
                }
            }
        }
    }
};

test "GaloisField basic math and field properties" {
    // Zero identity
    try std.testing.expectEqual(@as(u8, 0), GaloisField.mul(0, 100));
    try std.testing.expectEqual(@as(u8, 0), GaloisField.mul(100, 0));

    // Multiplicative identity
    try std.testing.expectEqual(@as(u8, 100), GaloisField.mul(1, 100));
    try std.testing.expectEqual(@as(u8, 100), GaloisField.mul(100, 1));

    // Multiplicative inverses for all elements 1..255
    var x: u16 = 1;
    while (x < 256) : (x += 1) {
        const val: u8 = @intCast(x);
        const inv = GaloisField.inv(val);
        try std.testing.expectEqual(@as(u8, 1), GaloisField.mul(val, inv));
    }

    // Division properties
    try std.testing.expectEqual(@as(u8, 0), GaloisField.div(0, 50));
    try std.testing.expectEqual(@as(u8, 50), GaloisField.div(50, 1));
    const prod = GaloisField.mul(37, 89);
    try std.testing.expectEqual(@as(u8, 37), GaloisField.div(prod, 89));
}

test "ReedSolomon encode parity verification" {
    const rs = try ReedSolomon.init(3, 2);
    const s1 = [_]u8{ 10, 20, 30 };
    const s2 = [_]u8{ 40, 50, 60 };
    const s3 = [_]u8{ 70, 80, 90 };
    const data = [_][]const u8{ &s1, &s2, &s3 };

    var p1 = [_]u8{ 0, 0, 0 };
    var p2 = [_]u8{ 0, 0, 0 };
    var parity = [_][]u8{ &p1, &p2 };

    rs.encode(&data, &parity, 3);

    // Parity must be non-zero deterministic bytes
    try std.testing.expect(p1[0] != 0 or p1[1] != 0 or p1[2] != 0);
    try std.testing.expect(p2[0] != 0 or p2[1] != 0 or p2[2] != 0);
}

test "ReedSolomon invertMatrix over GF(2^8)" {
    const n = 3;
    var mat: [ReedSolomon.MAX_SHARDS][ReedSolomon.MAX_SHARDS]u8 = undefined;
    var inv: [ReedSolomon.MAX_SHARDS][ReedSolomon.MAX_SHARDS]u8 = undefined;

    // Build 3x3 Cauchy matrix
    for (0..n) |r| {
        for (0..n) |c| {
            mat[r][c] = ReedSolomon.cauchyCoeff(r, c, 3);
            inv[r][c] = if (r == c) 1 else 0;
        }
    }

    // Copy original mat to check multiplication
    var orig: [3][3]u8 = undefined;
    for (0..n) |r| {
        for (0..n) |c| {
            orig[r][c] = mat[r][c];
        }
    }

    try ReedSolomon.invertMatrix(n, &mat, &inv);

    // Verify orig * inv == Identity
    for (0..n) |r| {
        for (0..n) |c| {
            var sum: u8 = 0;
            for (0..n) |k| {
                sum ^= GaloisField.mul(orig[r][k], inv[k][c]);
            }
            const expected: u8 = if (r == c) 1 else 0;
            try std.testing.expectEqual(expected, sum);
        }
    }
}

test "ReedSolomon decode single data shard lost" {
    const rs = try ReedSolomon.init(3, 2);
    const orig1 = [_]u8{ 11, 22, 33, 44 };
    const orig2 = [_]u8{ 55, 66, 77, 88 };
    const orig3 = [_]u8{ 99, 111, 122, 133 };

    var s1 = orig1;
    var s2 = orig2;
    var s3 = orig3;
    const enc_data = [_][]const u8{ &s1, &s2, &s3 };

    var p1 = [_]u8{ 0, 0, 0, 0 };
    var p2 = [_]u8{ 0, 0, 0, 0 };
    var parity = [_][]u8{ &p1, &p2 };

    rs.encode(&enc_data, &parity, 4);

    // Simulate loss of data shard 1 (s2 is lost/corrupted)
    @memset(&s2, 0);

    var dec_data = [_][]u8{ &s1, &s2, &s3 };
    const data_present = [_]bool{ true, false, true };
    const parity_ro = [_][]const u8{ &p1, &p2 };
    const parity_present = [_]bool{ true, true };

    try rs.decode(&dec_data, &data_present, &parity_ro, &parity_present, 4);

    // Verify shard 2 is perfectly reconstructed
    try std.testing.expectEqualSlices(u8, &orig1, &s1);
    try std.testing.expectEqualSlices(u8, &orig2, &s2);
    try std.testing.expectEqualSlices(u8, &orig3, &s3);
}

test "ReedSolomon decode multiple data shards lost" {
    const rs = try ReedSolomon.init(5, 3);
    const shard_size = 8;
    var orig: [5][shard_size]u8 = undefined;
    for (0..5) |i| {
        for (0..shard_size) |b| {
            orig[i][b] = @intCast((i * 37 + b * 13 + 7) % 256);
        }
    }

    var shards = orig;
    const enc_data = [_][]const u8{ &shards[0], &shards[1], &shards[2], &shards[3], &shards[4] };

    var p: [3][shard_size]u8 = [_][shard_size]u8{[_]u8{0} ** shard_size} ** 3;
    var parity = [_][]u8{ &p[0], &p[1], &p[2] };

    rs.encode(&enc_data, &parity, shard_size);

    // Simulate loss of data shard 0 and data shard 3 (2 shards lost out of 3 parity)
    @memset(&shards[0], 0);
    @memset(&shards[3], 0);

    var dec_data = [_][]u8{ &shards[0], &shards[1], &shards[2], &shards[3], &shards[4] };
    const data_present = [_]bool{ false, true, true, false, true };
    const parity_ro = [_][]const u8{ &p[0], &p[1], &p[2] };
    const parity_present = [_]bool{ true, true, true };

    try rs.decode(&dec_data, &data_present, &parity_ro, &parity_present, shard_size);

    for (0..5) |i| {
        try std.testing.expectEqualSlices(u8, &orig[i], &shards[i]);
    }
}

test "ReedSolomon decode all data shards lost" {
    const rs = try ReedSolomon.init(3, 3);
    const shard_size = 16;
    var orig: [3][shard_size]u8 = undefined;
    for (0..3) |i| {
        for (0..shard_size) |b| {
            orig[i][b] = @intCast((i * 47 + b * 29 + 1) % 256);
        }
    }

    var shards = orig;
    const enc_data = [_][]const u8{ &shards[0], &shards[1], &shards[2] };

    var p: [3][shard_size]u8 = [_][shard_size]u8{[_]u8{0} ** shard_size} ** 3;
    var parity = [_][]u8{ &p[0], &p[1], &p[2] };

    rs.encode(&enc_data, &parity, shard_size);

    // Wipe ALL 3 data shards
    for (0..3) |i| {
        @memset(&shards[i], 0);
    }

    var dec_data = [_][]u8{ &shards[0], &shards[1], &shards[2] };
    const data_present = [_]bool{ false, false, false };
    const parity_ro = [_][]const u8{ &p[0], &p[1], &p[2] };
    const parity_present = [_]bool{ true, true, true };

    try rs.decode(&dec_data, &data_present, &parity_ro, &parity_present, shard_size);

    for (0..3) |i| {
        try std.testing.expectEqualSlices(u8, &orig[i], &shards[i]);
    }
}

test "ReedSolomon decode with lost parity shards" {
    const rs = try ReedSolomon.init(4, 3);
    const shard_size = 16;
    var orig: [4][shard_size]u8 = undefined;
    for (0..4) |i| {
        for (0..shard_size) |b| {
            orig[i][b] = @intCast((i * 53 + b * 19 + 5) % 256);
        }
    }

    var shards = orig;
    const enc_data = [_][]const u8{ &shards[0], &shards[1], &shards[2], &shards[3] };

    var p: [3][shard_size]u8 = [_][shard_size]u8{[_]u8{0} ** shard_size} ** 3;
    var parity = [_][]u8{ &p[0], &p[1], &p[2] };

    rs.encode(&enc_data, &parity, shard_size);

    // Shard 2 is lost. Parity shard 0 and 2 are also lost.
    // Only parity shard 1 is available (1 parity available, 1 data lost -> should succeed!)
    @memset(&shards[2], 0);

    var dec_data = [_][]u8{ &shards[0], &shards[1], &shards[2], &shards[3] };
    const data_present = [_]bool{ true, true, false, true };
    const parity_ro = [_][]const u8{ &p[0], &p[1], &p[2] };
    const parity_present = [_]bool{ false, true, false };

    try rs.decode(&dec_data, &data_present, &parity_ro, &parity_present, shard_size);

    for (0..4) |i| {
        try std.testing.expectEqualSlices(u8, &orig[i], &shards[i]);
    }
}

test "ReedSolomon decode with no lost shards (no-op)" {
    const rs = try ReedSolomon.init(3, 2);
    const shard_size = 8;
    var s1 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var s2 = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    var s3 = [_]u8{ 17, 18, 19, 20, 21, 22, 23, 24 };

    var dec_data = [_][]u8{ &s1, &s2, &s3 };
    const data_present = [_]bool{ true, true, true };
    const p1 = [_]u8{0} ** shard_size;
    const p2 = [_]u8{0} ** shard_size;
    const parity_ro = [_][]const u8{ &p1, &p2 };
    const parity_present = [_]bool{ false, false };

    try rs.decode(&dec_data, &data_present, &parity_ro, &parity_present, shard_size);

    try std.testing.expectEqual(@as(u8, 1), s1[0]);
    try std.testing.expectEqual(@as(u8, 9), s2[0]);
    try std.testing.expectEqual(@as(u8, 17), s3[0]);
}

test "ReedSolomon decode error when too many shards lost" {
    const rs = try ReedSolomon.init(4, 2);
    const shard_size = 8;
    var s: [4][shard_size]u8 = [_][shard_size]u8{[_]u8{1} ** shard_size} ** 4;
    var p: [2][shard_size]u8 = [_][shard_size]u8{[_]u8{0} ** shard_size} ** 2;

    var dec_data = [_][]u8{ &s[0], &s[1], &s[2], &s[3] };
    // 3 data shards missing, but only 2 parity shards total
    const data_present = [_]bool{ true, false, false, false };
    const parity_ro = [_][]const u8{ &p[0], &p[1] };
    const parity_present = [_]bool{ true, true };

    const err = rs.decode(&dec_data, &data_present, &parity_ro, &parity_present, shard_size);
    try std.testing.expectError(error.TooManyMissingShards, err);
}

test "ReedSolomon decodeShards convenience method" {
    const rs = try ReedSolomon.init(3, 2);
    const shard_size = 10;
    var orig: [3][shard_size]u8 = undefined;
    for (0..3) |i| {
        for (0..shard_size) |b| {
            orig[i][b] = @intCast(i * 30 + b + 1);
        }
    }

    var shards: [5][shard_size]u8 = undefined;
    for (0..3) |i| shards[i] = orig[i];

    var enc_slices = [_][]const u8{ &shards[0], &shards[1], &shards[2] };
    var par_slices = [_][]u8{ &shards[3], &shards[4] };
    rs.encode(&enc_slices, &par_slices, shard_size);

    // Save copy of generated parity
    const orig_p1 = shards[3];
    const orig_p2 = shards[4];

    // Lose data shard 0 AND parity shard 1
    @memset(&shards[0], 0);
    @memset(&shards[4], 0);

    var all_slices = [_][]u8{ &shards[0], &shards[1], &shards[2], &shards[3], &shards[4] };
    const present = [_]bool{ false, true, true, true, false };

    try rs.decodeShards(&all_slices, &present, shard_size);

    // Verify data shard 0 is recovered
    try std.testing.expectEqualSlices(u8, &orig[0], &shards[0]);
    // Verify parity shard 1 is also re-encoded
    try std.testing.expectEqualSlices(u8, &orig_p1, &shards[3]);
    try std.testing.expectEqualSlices(u8, &orig_p2, &shards[4]);
}

test "ReedSolomon large shard data integrity (multi-kilobyte)" {
    const rs = try ReedSolomon.init(6, 4);
    const shard_size = 1400; // standard VPN MTU packet payload

    var orig_data: [6][shard_size]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    const rand = prng.random();

    for (0..6) |i| {
        rand.bytes(&orig_data[i]);
    }

    var shards = orig_data;
    var parities: [4][shard_size]u8 = undefined;

    var data_slices: [6][]const u8 = undefined;
    for (0..6) |i| data_slices[i] = &shards[i];

    var parity_slices: [4][]u8 = undefined;
    for (0..4) |i| parity_slices[i] = &parities[i];

    rs.encode(&data_slices, &parity_slices, shard_size);

    // Lose 3 data shards (0, 2, 5) out of 6
    @memset(&shards[0], 0);
    @memset(&shards[2], 0);
    @memset(&shards[5], 0);

    var dec_slices: [6][]u8 = undefined;
    for (0..6) |i| dec_slices[i] = &shards[i];
    const data_present = [_]bool{ false, true, false, true, true, false };

    var dec_parities: [4][]const u8 = undefined;
    for (0..4) |i| dec_parities[i] = &parities[i];
    const parity_present = [_]bool{ true, true, true, true };

    try rs.decode(&dec_slices, &data_present, &dec_parities, &parity_present, shard_size);

    for (0..6) |i| {
        try std.testing.expectEqualSlices(u8, &orig_data[i], &shards[i]);
    }
}
