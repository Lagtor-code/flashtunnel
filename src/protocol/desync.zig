const std = @import("std");
const builtin = @import("builtin");
const checksum = @import("checksum.zig");
pub const TcpFlags = checksum.TcpFlags;

/// TCP Desync Engine for High-Performance Anti-DPI Evasion in Zig.
///
/// Implements state-of-the-art DPI evasion primitives:
/// - multidisorder: Splitting the TCP stream into multiple segments transmitted
///   out-of-order to trigger sequence gaps in DPI reassembly state machines.
/// - pos=2: Splitting specifically at byte 2 of the payload (e.g. inside the
///   TLS record header 0x16 0x03 0x01), making SNI inspection impossible.
/// - seqovl=1: Sequence overlap of 1 byte between adjacent segments, triggering
///   reassembly ambiguities that cause middlebox DPIs to fail-open while
///   the destination Linux kernel cleanly trims the overlap.
/// - urg: Setting the TCP URG flag with urgent pointer offset to confuse
///   hardware ASIC DPI stream tracking.

pub const MAX_DESYNC_CHUNKS: usize = 8;

/// Configuration options for the TCP Desync engine.
pub const DesyncConfig = struct {
    /// Split position in payload (default: 2 bytes, ideal for TLS/protocol header evasion)
    pos: usize = 2,

    /// Sequence overlap in bytes (default: 1 byte overlap at segment boundaries)
    seqovl: usize = 1,

    /// Whether to enable the TCP URG flag on desync segments
    use_urg: bool = true,

    /// Urgent pointer value when URG flag is active
    urg_ptr: u16 = 1,

    /// Whether to use multi-segment disorder (3+ chunks) or simple 2-chunk disorder
    multidisorder: bool = true,

    /// Number of total chunks when multidisorder is active (minimum: 3)
    chunk_count: usize = 3,
};

/// A planned TCP segment with exact sequence number, payload slice, and flags.
pub const PlannedSegment = struct {
    /// Relative sequence number offset from the original base sequence number
    seq_offset: u32,

    /// Slice start index within the original payload
    payload_start: usize,

    /// Length of payload in this segment
    payload_len: usize,

    /// TCP flags (ACK, PSH, URG, etc.)
    flags: u8,

    /// Urgent pointer (valid if flags has TcpFlags.URG)
    urg_ptr: u16,

    /// Transmission order index (0 = first to send, 1 = second, ...)
    transmit_order: u8,
};

/// Result of planning a multidisorder split.
pub const PlanResult = struct {
    segments: [MAX_DESYNC_CHUNKS]PlannedSegment,
    count: usize,
};

/// Plans a `multidisorder:pos=2:seqovl=1` split with URG flag support.
///
/// Example for payload of length L with pos=2, seqovl=1, chunk_count=3:
/// - Chunk 0 (Head): payload[0..2], seq = S, len = 2.
/// - Chunk 1 (Mid):  payload[1..mid], seq = S+1, len = (mid - 1) [overlaps Chunk 0 by 1 byte]
/// - Chunk 2 (Tail): payload[mid-1..L], seq = S+mid-1, len = (L - mid + 1) [overlaps Chunk 1 by 1 byte]
///
/// Transmission Order (Multi-Disorder):
/// 1. Chunk 2 (Tail) sent FIRST with URG flag (DPI sees sequence far ahead + URG, cannot inspect)
/// 2. Chunk 1 (Mid)  sent SECOND
/// 3. Chunk 0 (Head) sent THIRD (completes the sequence, Linux kernel reassembles seamlessly)
pub fn planMultiDisorder(payload_len: usize, config: DesyncConfig) error{PayloadTooShort, InvalidConfig}!PlanResult {
    if (config.pos == 0) return error.InvalidConfig;
    if (config.seqovl == 0) return error.InvalidConfig;
    if (config.seqovl >= config.pos) return error.InvalidConfig;

    // Minimum payload length: pos + seqovl + 2
    if (payload_len < config.pos + config.seqovl + 2) {
        return error.PayloadTooShort;
    }

    var result = PlanResult{
        .segments = undefined,
        .count = 0,
    };

    if (!config.multidisorder or config.chunk_count <= 2) {
        // Standard 2-chunk disorder with overlap:
        // Chunk 0 (Head): [0 .. pos] -> len = pos, seq = 0
        // Chunk 1 (Tail): [pos - seqovl .. L] -> len = L - pos + seqovl, seq = pos - seqovl
        const head_len = config.pos;
        const tail_start = config.pos - config.seqovl;
        const tail_len = payload_len - tail_start;

        // Chunk 1 (Tail) sent FIRST
        var tail_flags: u8 = TcpFlags.ACK;
        var urg_val: u16 = 0;
        if (config.use_urg) {
            tail_flags |= TcpFlags.URG;
            urg_val = config.urg_ptr;
        }

        result.segments[0] = PlannedSegment{
            .seq_offset = @as(u32, @intCast(tail_start)),
            .payload_start = tail_start,
            .payload_len = tail_len,
            .flags = tail_flags,
            .urg_ptr = urg_val,
            .transmit_order = 0, // Sent first
        };

        // Chunk 0 (Head) sent SECOND
        result.segments[1] = PlannedSegment{
            .seq_offset = 0,
            .payload_start = 0,
            .payload_len = head_len,
            .flags = TcpFlags.ACK | TcpFlags.PSH,
            .urg_ptr = 0,
            .transmit_order = 1, // Sent second
        };

        result.count = 2;
        return result;
    }

    // Multi-Disorder (3 chunks):
    // Chunk 0: Head [0 .. pos]
    // Remainder is from (pos - seqovl) to payload_len
    const head_len = config.pos;
    const remainder_start = config.pos - config.seqovl;
    const remainder_len = payload_len - remainder_start;

    const mid_point = remainder_start + (remainder_len / 2);

    // Chunk 1: Mid [remainder_start .. mid_point]
    // Chunk 2: Tail [mid_point - seqovl .. payload_len]
    const chunk0_start: usize = 0;
    const chunk0_len: usize = head_len;
    const chunk0_seq: u32 = 0;

    const chunk1_start: usize = remainder_start;
    const chunk1_len: usize = mid_point - remainder_start;
    const chunk1_seq: u32 = @as(u32, @intCast(remainder_start));

    const chunk2_start: usize = mid_point - config.seqovl;
    const chunk2_len: usize = payload_len - chunk2_start;
    const chunk2_seq: u32 = @as(u32, @intCast(chunk2_start));

    // Multi-Disorder Transmission Order:
    // Order 0: Chunk 2 (Tail) - sent first with URG flag!
    var chunk2_flags: u8 = TcpFlags.ACK;
    var chunk2_urg: u16 = 0;
    if (config.use_urg) {
        chunk2_flags |= TcpFlags.URG;
        chunk2_urg = config.urg_ptr;
    }

    result.segments[0] = PlannedSegment{
        .seq_offset = chunk2_seq,
        .payload_start = chunk2_start,
        .payload_len = chunk2_len,
        .flags = chunk2_flags,
        .urg_ptr = chunk2_urg,
        .transmit_order = 0,
    };

    // Order 1: Chunk 1 (Mid) - sent second
    result.segments[1] = PlannedSegment{
        .seq_offset = chunk1_seq,
        .payload_start = chunk1_start,
        .payload_len = chunk1_len,
        .flags = TcpFlags.ACK,
        .urg_ptr = 0,
        .transmit_order = 1,
    };

    // Order 2: Chunk 0 (Head) - sent third (final piece, triggers kernel reassembly)
    result.segments[2] = PlannedSegment{
        .seq_offset = chunk0_seq,
        .payload_start = chunk0_start,
        .payload_len = chunk0_len,
        .flags = TcpFlags.ACK | TcpFlags.PSH,
        .urg_ptr = 0,
        .transmit_order = 2,
    };

    result.count = 3;
    return result;
}

/// Simulates how the Linux kernel reassembles out-of-order, overlapping TCP segments.
/// Validates that the original payload is recovered 100% byte-for-byte without corruption.
pub fn simulateKernelReassembly(
    out_buf: []u8,
    original_payload: []const u8,
    plan: PlanResult,
) !usize {
    @memset(out_buf[0..original_payload.len], 0);
    var written = std.AutoHashMap(usize, u8).init(std.heap.page_allocator);
    defer written.deinit();

    // Process segments in their transmit order (simulating arrival at receiver)
    var step: u8 = 0;
    while (step < plan.count) : (step += 1) {
        for (plan.segments[0..plan.count]) |seg| {
            if (seg.transmit_order == step) {
                const seg_payload = original_payload[seg.payload_start .. seg.payload_start + seg.payload_len];
                var i: usize = 0;
                while (i < seg.payload_len) : (i += 1) {
                    const abs_idx = seg.seq_offset + @as(u32, @intCast(i));
                    if (abs_idx < out_buf.len) {
                        out_buf[abs_idx] = seg_payload[i];
                    }
                }
            }
        }
    }

    return original_payload.len;
}

/// Crafts a complete IPv4 + TCP raw packet for a desync segment.
pub fn craftDesyncRawPacket(
    out: []u8,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    base_seq: u32,
    base_ack: u32,
    ts_val: u32,
    ts_ecr: u32,
    seg: PlannedSegment,
    full_payload: []const u8,
) []u8 {
    const chunk_payload = full_payload[seg.payload_start .. seg.payload_start + seg.payload_len];
    const total_l4_len = checksum.PCK_TCP_TOTAL_LEN + chunk_payload.len;
    const total_packet_len = checksum.IPV4_HEADER_LEN + total_l4_len;
    std.debug.assert(out.len >= total_packet_len);

    // 1. Build TCP Header
    var tcp_buf: [1500]u8 = undefined;
    const tcp = tcp_buf[0..total_l4_len];
    std.mem.writeInt(u16, tcp[0..2], src_port, .big);
    std.mem.writeInt(u16, tcp[2..4], dst_port, .big);
    std.mem.writeInt(u32, tcp[4..8], base_seq + seg.seq_offset, .big);
    std.mem.writeInt(u32, tcp[8..12], base_ack, .big);
    tcp[12] = @as(u8, @truncate(checksum.PCK_TCP_TOTAL_LEN / 4)) << 4; // Data offset 8 (32 bytes)
    tcp[13] = seg.flags;
    std.mem.writeInt(u16, tcp[14..16], checksum.PCK_DEFAULT_WINDOW, .big);
    tcp[16] = 0; // Checksum placeholder
    tcp[17] = 0;
    std.mem.writeInt(u16, tcp[18..20], seg.urg_ptr, .big); // Urgent pointer!

    // TCP Options: NOP, NOP, Timestamps
    tcp[20] = 0x01; // NOP
    tcp[21] = 0x01; // NOP
    tcp[22] = 0x08; // Option 8 (Timestamp)
    tcp[23] = 0x0a; // Length 10
    std.mem.writeInt(u32, tcp[24..28], ts_val, .big);
    std.mem.writeInt(u32, tcp[28..32], ts_ecr, .big);

    // Copy payload
    @memcpy(tcp[checksum.PCK_TCP_TOTAL_LEN..total_l4_len], chunk_payload);

    // Compute TCP checksum with IPv4 pseudo-header
    const l4_csum = checksum.l4Checksum(src_ip, dst_ip, checksum.IPPROTO_TCP, tcp);
    std.mem.writeInt(u16, tcp[16..18], l4_csum, .big);

    // 2. Wrap into IPv4
    return checksum.buildPckIPv4(out, 0, src_ip, dst_ip, tcp);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "multidisorder plan with pos=2 seqovl=1 and URG" {
    // Typical TLS 1.3 ClientHello simulation payload (128 bytes)
    var sample_payload: [128]u8 = undefined;
    for (&sample_payload, 0..) |*b, i| {
        b.* = @as(u8, @truncate(i + 1));
    }
    // Simulate TLS ClientHello signature: 0x16, 0x03, 0x01 ...
    sample_payload[0] = 0x16; // Handshake
    sample_payload[1] = 0x03; // Major version 3
    sample_payload[2] = 0x01; // Minor version 1

    const config = DesyncConfig{
        .pos = 2,
        .seqovl = 1,
        .use_urg = true,
        .urg_ptr = 1,
        .multidisorder = true,
        .chunk_count = 3,
    };

    const plan = try planMultiDisorder(sample_payload.len, config);
    try std.testing.expectEqual(@as(usize, 3), plan.count);

    // Verify Transmission Order:
    // Order 0 must be Chunk 2 (Tail) with URG flag set
    const seg0 = plan.segments[0];
    try std.testing.expectEqual(@as(u8, 0), seg0.transmit_order);
    try std.testing.expect((seg0.flags & TcpFlags.URG) != 0);
    try std.testing.expectEqual(@as(u16, 1), seg0.urg_ptr);

    // Order 2 must be Chunk 0 (Head, pos=2, bytes 0..2)
    const seg2 = plan.segments[2];
    try std.testing.expectEqual(@as(u8, 2), seg2.transmit_order);
    try std.testing.expectEqual(@as(usize, 0), seg2.payload_start);
    try std.testing.expectEqual(@as(usize, 2), seg2.payload_len);
    try std.testing.expectEqual(@as(u32, 0), seg2.seq_offset);

    // Verify Reassembly matches original payload 100%
    var reassembled: [128]u8 = undefined;
    _ = try simulateKernelReassembly(&reassembled, &sample_payload, plan);
    try std.testing.expectEqualSlices(u8, &sample_payload, &reassembled);
}

test "standard 2-chunk disorder with pos=2 seqovl=1" {
    var payload: [64]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @as(u8, @truncate(i ^ 0xAA));

    const config = DesyncConfig{
        .pos = 2,
        .seqovl = 1,
        .use_urg = true,
        .urg_ptr = 1,
        .multidisorder = false,
    };

    const plan = try planMultiDisorder(payload.len, config);
    try std.testing.expectEqual(@as(usize, 2), plan.count);

    // Tail sent first (transmit_order 0) starting at offset pos-seqovl = 1
    try std.testing.expectEqual(@as(u8, 0), plan.segments[0].transmit_order);
    try std.testing.expectEqual(@as(usize, 1), plan.segments[0].payload_start);
    try std.testing.expectEqual(@as(u32, 1), plan.segments[0].seq_offset);

    // Head sent second (transmit_order 1) starting at offset 0, len 2
    try std.testing.expectEqual(@as(u8, 1), plan.segments[1].transmit_order);
    try std.testing.expectEqual(@as(usize, 0), plan.segments[1].payload_start);
    try std.testing.expectEqual(@as(usize, 2), plan.segments[1].payload_len);
    try std.testing.expectEqual(@as(u32, 0), plan.segments[1].seq_offset);

    // Verify Reassembly
    var reassembled: [64]u8 = undefined;
    _ = try simulateKernelReassembly(&reassembled, &payload, plan);
    try std.testing.expectEqualSlices(u8, &payload, &reassembled);
}

test "craftDesyncRawPacket validates headers and checksums" {
    const payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const config = DesyncConfig{
        .pos = 2,
        .seqovl = 1,
        .use_urg = true,
        .urg_ptr = 1,
        .multidisorder = true,
        .chunk_count = 3,
    };

    const plan = try planMultiDisorder(payload.len, config);
    const seg_tail = plan.segments[0]; // Tail chunk with URG

    var packet_buf: [256]u8 = undefined;
    const pkt = craftDesyncRawPacket(
        &packet_buf,
        [_]u8{ 10, 0, 0, 1 },
        [_]u8{ 10, 0, 0, 2 },
        54321,
        443,
        1000000,
        500000,
        12345,
        67890,
        seg_tail,
        payload,
    );

    // Verify IPv4 header length
    try std.testing.expect(pkt.len > checksum.IPV4_HEADER_LEN + checksum.PCK_TCP_TOTAL_LEN);

    // Verify IPv4 checksum
    try std.testing.expect(checksum.verify(pkt[0..checksum.IPV4_HEADER_LEN]));

    // Verify URG flag in TCP header
    const tcp = pkt[checksum.IPV4_HEADER_LEN..];
    try std.testing.expect((tcp[13] & TcpFlags.URG) != 0);

    // Verify Urgent pointer
    const urg_val = std.mem.readInt(u16, tcp[18..20], .big);
    try std.testing.expectEqual(@as(u16, 1), urg_val);
}
