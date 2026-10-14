const std = @import("std");
const AeadEngine = @import("crypto/chacha20poly1305.zig").AeadEngine;
const ReplayWindow = @import("protocol/replay.zig").ReplayWindow;
const AtomicReplayWindow = @import("protocol/replay.zig").AtomicReplayWindow;
const ReedSolomon = @import("fec/reedsolomon.zig").ReedSolomon;
const GreEncap = @import("protocol/encap.zig").GreEncap;
const SpliceProxy = @import("tcp/splice_proxy.zig").SpliceProxy;

// Global lock-free replay window instance for C API callers (thread-safe for Go goroutines)
var global_replay = AtomicReplayWindow{};
var global_splice: ?SpliceProxy = null;

/// C-ABI: Encrypts a packet using ChaCha20-Poly1305 AEAD.
/// Returns 0 on success, -1 on buffer error.
export fn backpack_zig_seal(
    key_ptr: [*]const u8,
    counter: u64,
    ad_ptr: [*]const u8,
    ad_len: usize,
    in_ptr: [*]const u8,
    in_len: usize,
    out_ptr: [*]u8,
    out_max_len: usize,
    out_len: *usize,
) c_int {
    const key: *const [32]u8 = @ptrCast(key_ptr);
    const engine = AeadEngine.init(key.*);

    const ad = ad_ptr[0..ad_len];
    const plaintext = in_ptr[0..in_len];
    const dst = out_ptr[0..out_max_len];

    const sealed_size = engine.seal(dst, counter, ad, plaintext) catch {
        return -1;
    };

    out_len.* = sealed_size;
    return 0;
}

/// C-ABI: Decrypts and authenticates a packet using ChaCha20-Poly1305 AEAD.
/// Returns 0 on success, -1 on failure (corrupt or forged packet).
export fn backpack_zig_open(
    key_ptr: [*]const u8,
    counter: u64,
    ad_ptr: [*]const u8,
    ad_len: usize,
    body_ptr: [*]const u8,
    body_len: usize,
    out_ptr: [*]u8,
    out_max_len: usize,
    out_len: *usize,
) c_int {
    const key: *const [32]u8 = @ptrCast(key_ptr);
    const engine = AeadEngine.init(key.*);

    const ad = ad_ptr[0..ad_len];
    const body = body_ptr[0..body_len];
    const dst = out_ptr[0..out_max_len];

    const plain = engine.open(dst, counter, ad, body) catch {
        return -1;
    };

    out_len.* = plain.len;
    return 0;
}

/// C-ABI: Replay window check and commit.
/// Returns 1 if packet is fresh (accepted and committed), 0 if duplicate/replayed.
export fn backpack_zig_replay_check_and_commit(counter: u64) c_int {
    return if (global_replay.checkAndCommit(counter)) 1 else 0;
}

/// C-ABI: Reset global replay window (e.g. on new session).
export fn backpack_zig_replay_reset() void {
    global_replay.reset();
}

/// C-ABI: Reed-Solomon Parity Generator.
/// Encodes `data_shards` into `parity_shards` of size `shard_size`.
export fn backpack_zig_fec_encode(
    data_shards: usize,
    parity_shards: usize,
    data_ptrs: [*]const [*]const u8,
    parity_ptrs: [*]const [*]u8,
    shard_size: usize,
) c_int {
    const rs = ReedSolomon.init(data_shards, parity_shards) catch return -1;

    var data_slices: [256][]const u8 = undefined;
    var parity_slices: [256][]u8 = undefined;

    var i: usize = 0;
    while (i < data_shards) : (i += 1) {
        data_slices[i] = data_ptrs[i][0..shard_size];
    }

    var j: usize = 0;
    while (j < parity_shards) : (j += 1) {
        parity_slices[j] = parity_ptrs[j][0..shard_size];
    }

    rs.encode(data_slices[0..data_shards], parity_slices[0..parity_shards], shard_size);
    return 0;
}

/// C-ABI: Reed-Solomon Reconstruction / Decoder.
/// Recovers lost data shards into `data_ptrs` buffers where `data_present` is false.
/// Returns 0 on success, -1 on error.
export fn backpack_zig_fec_decode(
    data_shards: usize,
    parity_shards: usize,
    data_ptrs: [*]const [*]u8,
    data_present: [*]const bool,
    parity_ptrs: [*]const [*]const u8,
    parity_present: [*]const bool,
    shard_size: usize,
) c_int {
    const rs = ReedSolomon.init(data_shards, parity_shards) catch return -1;
    if (data_shards > ReedSolomon.MAX_SHARDS or parity_shards > ReedSolomon.MAX_SHARDS) return -1;

    var data_slices: [ReedSolomon.MAX_SHARDS][]u8 = undefined;
    var parity_slices: [ReedSolomon.MAX_SHARDS][]const u8 = undefined;

    var i: usize = 0;
    while (i < data_shards) : (i += 1) {
        data_slices[i] = data_ptrs[i][0..shard_size];
    }

    var j: usize = 0;
    while (j < parity_shards) : (j += 1) {
        parity_slices[j] = parity_ptrs[j][0..shard_size];
    }

    rs.decode(
        data_slices[0..data_shards],
        data_present[0..data_shards],
        parity_slices[0..parity_shards],
        parity_present[0..parity_shards],
        shard_size,
    ) catch return -1;

    return 0;
}

/// C-ABI: Zero-copy TCP splice pipe forwarder.
/// Returns number of bytes transferred, or -1 on error.
export fn backpack_zig_splice_forward(
    src_fd: c_int,
    dst_fd: c_int,
    max_bytes: usize,
) isize {
    if (@import("builtin").os.tag != .linux) return -1;
    if (global_splice == null) {
        global_splice = SpliceProxy.init() catch return -1;
    }

    const n = global_splice.?.forwardChunk(@intCast(src_fd), @intCast(dst_fd), max_bytes) catch {
        return -1;
    };
    return @intCast(n);
}

/// C-ABI: Bidirectional zero-copy TCP splice forwarder loop.
/// Runs non-blocking bidirectional splice until EOF or stop_signal.
/// Returns 0 on clean completion, -1 on error.
export fn backpack_zig_splice_forward_bidirectional(
    sock_a: c_int,
    sock_b: c_int,
    stop_signal_ptr: *std.atomic.Value(bool),
) c_int {
    if (@import("builtin").os.tag != .linux) return -1;
    const forwardBidirectional = @import("tcp/splice_proxy.zig").forwardBidirectional;
    forwardBidirectional(@intCast(sock_a), @intCast(sock_b), stop_signal_ptr) catch {
        return -1;
    };
    return 0;
}

/// C-ABI: Sets CPU affinity of the calling thread.
/// Returns 0 on success, -1 on failure.
export fn backpack_zig_set_affinity(core_id: usize) c_int {
    const pipeline = @import("core/pipeline.zig");
    pipeline.pinCurrentThreadToCore(core_id) catch {
        return -1;
    };
    return 0;
}
