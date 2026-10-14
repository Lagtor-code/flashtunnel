const std = @import("std");
const builtin = @import("builtin");

/// RFC 1071 Internet Checksum Calculator & PCK (FakeTCP) Frame Assembler.
///
/// Implements a SIMD / 64-bit vectorized Internet Checksum (RFC 1071)
/// used across IPv4, IPv6, TCP, and UDP packet processing, and provides
/// IPv4/TCP header crafting for BackPack's PCK obfuscated carrier.

// ============================================================================
// Constants & Definitions
// ============================================================================

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const PCK_ETH_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const PCK_TCP_HEADER_LEN: usize = 20;
pub const PCK_TCP_OPTIONS_LEN: usize = 12; // NOP, NOP, Timestamps (10 bytes)
pub const PCK_TCP_TOTAL_LEN: usize = PCK_TCP_HEADER_LEN + PCK_TCP_OPTIONS_LEN; // 32 bytes
pub const PCK_OVERHEAD: usize = IPV4_HEADER_LEN + PCK_TCP_TOTAL_LEN; // 52 bytes
pub const PCK_TOTAL_OVERHEAD: usize = PCK_ETH_HEADER_LEN + PCK_OVERHEAD; // 66 bytes

pub const PCK_DEFAULT_WINDOW: u16 = 65535;
pub const PCK_DSCP_EF: u8 = 46 << 2; // DSCP 46 (Expedited Forwarding), ECN 0 = 184 (0xB8)
pub const IPV4_DONT_FRAGMENT: u16 = 0x4000;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// TCP Header Flags matching RFC 793 / 3168 and BackPack carrier definitions.
pub const TcpFlags = struct {
    pub const FIN: u8 = 1 << 0;
    pub const SYN: u8 = 1 << 1;
    pub const RST: u8 = 1 << 2;
    pub const PSH: u8 = 1 << 3;
    pub const ACK: u8 = 1 << 4;
    pub const URG: u8 = 1 << 5;
    pub const ECE: u8 = 1 << 6;
    pub const CWR: u8 = 1 << 7;
};

// ============================================================================
// Vectorized RFC 1071 Internet Checksum Engine
// ============================================================================

/// Primary vectorized Internet Checksum calculator (RFC 1071).
/// Uses SIMD 256-bit (@Vector(16, u16) -> @Vector(16, u32)) vectorization on bulk
/// data, falls back to 64-bit and 16-bit word summation for tails, and returns
/// the 16-bit ones' complement in big-endian network byte order.
pub fn compute(data: []const u8) u16 {
    return computeSimd(data);
}

/// Computes the RFC 1071 checksum using SIMD vector instructions.
/// Processes 32 bytes (16 x 16-bit words) per iteration using @Vector(16, u16)
/// zero-extended into @Vector(16, u32) accumulators. Because each 32-bit lane
/// can accumulate up to 65,536 16-bit words without overflowing 2^32 - 1, no carry
/// tracking is required in the vector inner loop for standard packets (up to 64KB).
pub fn computeSimd(data: []const u8) u16 {
    if (data.len == 0) return 0xffff;

    var acc_v0: @Vector(16, u32) = @splat(0);
    var acc_v1: @Vector(16, u32) = @splat(0);
    var i: usize = 0;

    // 64-byte unrolled SIMD loop (two 32-byte vector loads)
    while (i + 64 <= data.len) : (i += 64) {
        const v0 = @as(*const align(1) @Vector(16, u16), @ptrCast(data[i..][0..32])).*;
        const v1 = @as(*const align(1) @Vector(16, u16), @ptrCast(data[i + 32 ..][0..32])).*;
        acc_v0 += v0;
        acc_v1 += v1;
    }

    // 32-byte SIMD loop
    while (i + 32 <= data.len) : (i += 32) {
        const v0 = @as(*const align(1) @Vector(16, u16), @ptrCast(data[i..][0..32])).*;
        acc_v0 += v0;
    }

    // Reduce SIMD vector accumulators
    acc_v0 += acc_v1;
    var scalar_acc: u64 = @reduce(.Add, acc_v0);

    // 16-byte residual
    if (i + 16 <= data.len) {
        const v8 = @as(*const align(1) @Vector(8, u16), @ptrCast(data[i..][0..16])).*;
        const v8_32: @Vector(8, u32) = v8;
        scalar_acc += @reduce(.Add, v8_32);
        i += 16;
    }

    // 8-byte (64-bit) residual
    if (i + 8 <= data.len) {
        const w = std.mem.readInt(u64, data[i..][0..8], .little);
        scalar_acc += (w & 0xffff) + ((w >> 16) & 0xffff) + ((w >> 32) & 0xffff) + (w >> 48);
        i += 8;
    }

    // 4-byte (32-bit) residual
    if (i + 4 <= data.len) {
        const w = std.mem.readInt(u32, data[i..][0..4], .little);
        scalar_acc += (w & 0xffff) + (w >> 16);
        i += 4;
    }

    // 2-byte (16-bit) residual
    if (i + 2 <= data.len) {
        const w = std.mem.readInt(u16, data[i..][0..2], .little);
        scalar_acc += w;
        i += 2;
    }

    // 1 trailing odd byte:
    // In RFC 1071 big-endian order, an odd byte is padded with zero on the right: (b << 8).
    // In our little-endian accumulator, byte-swapping at the end will place the low byte
    // into the high byte. Therefore, adding b directly here yields (b << 8) after @byteSwap!
    if (i < data.len) {
        scalar_acc += data[i];
    }

    // Fold 64-bit scalar accumulator into 16 bits
    return finalizeFolded(scalar_acc);
}

/// 64-bit vectorized Internet Checksum calculator.
/// Accumulates 64-bit chunks with carry overflow tracking.
pub fn compute64(data: []const u8) u16 {
    if (data.len == 0) return 0xffff;

    var sum: u64 = 0;
    var carry: u64 = 0;
    var i: usize = 0;

    // 32-byte unrolled loop (4 x 64-bit words)
    while (i + 32 <= data.len) : (i += 32) {
        inline for (0..4) |offset| {
            const w = std.mem.readInt(u64, data[i + offset * 8 ..][0..8], .little);
            const res = @addWithOverflow(sum, w);
            sum = res[0];
            carry +%= res[1];
        }
    }

    // 8-byte residual
    while (i + 8 <= data.len) : (i += 8) {
        const w = std.mem.readInt(u64, data[i..][0..8], .little);
        const res = @addWithOverflow(sum, w);
        sum = res[0];
        carry +%= res[1];
    }

    // 4-byte residual
    if (i + 4 <= data.len) {
        const w = @as(u64, std.mem.readInt(u32, data[i..][0..4], .little));
        const res = @addWithOverflow(sum, w);
        sum = res[0];
        carry +%= res[1];
        i += 4;
    }

    // 2-byte residual
    if (i + 2 <= data.len) {
        const w = @as(u64, std.mem.readInt(u16, data[i..][0..2], .little));
        const res = @addWithOverflow(sum, w);
        sum = res[0];
        carry +%= res[1];
        i += 2;
    }

    // 1 trailing odd byte
    if (i < data.len) {
        const w = @as(u64, data[i]);
        const res = @addWithOverflow(sum, w);
        sum = res[0];
        carry +%= res[1];
    }

    // Fold sum and carry (since 2^64 mod (2^16 - 1) = 1)
    var s: u64 = (sum & 0xffff_ffff) + (sum >> 32) + (carry & 0xffff_ffff) + (carry >> 32);
    while (s >> 16 != 0) {
        s = (s & 0xffff) + (s >> 16);
    }

    var res16 = @as(u16, @truncate(s));
    if (builtin.cpu.arch.endian() == .little) {
        res16 = @byteSwap(res16);
    }
    return ~res16;
}

/// Reference scalar Internet Checksum calculator matching BackPack's Go onesComplement.
/// Used for correctness verification and unit testing.
pub fn computeScalar(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        const word: u32 = (@as(u32, data[i]) << 8) | @as(u32, data[i + 1]);
        sum += word;
    }
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

/// Folds a 64-bit accumulator down to a 16-bit ones' complement sum,
/// swaps byte order if running on little-endian, and inverts bits (~).
inline fn finalizeFolded(acc: u64) u16 {
    var s = acc;
    s = (s & 0xffff_ffff) + (s >> 32);
    s = (s & 0xffff_ffff) + (s >> 32);
    while (s >> 16 != 0) {
        s = (s & 0xffff) + (s >> 16);
    }
    var res16 = @as(u16, @truncate(s));
    if (builtin.cpu.arch.endian() == .little) {
        res16 = @byteSwap(res16);
    }
    return ~res16;
}

/// Fold a 32-bit accumulator down to a 16-bit ones' complement sum.
pub inline fn fold32(sum: u32) u16 {
    var s = sum;
    while (s >> 16 != 0) {
        s = (s & 0xffff) + (s >> 16);
    }
    return @as(u16, @truncate(s));
}

/// Fold a 64-bit accumulator down to a 16-bit ones' complement sum.
pub inline fn fold64(sum: u64) u16 {
    var s = sum;
    s = (s & 0xffff_ffff) + (s >> 32);
    s = (s & 0xffff_ffff) + (s >> 32);
    while (s >> 16 != 0) {
        s = (s & 0xffff) + (s >> 16);
    }
    return @as(u16, @truncate(s));
}

/// Verifies whether the RFC 1071 checksum of a buffer containing its checksum is valid.
/// A packet with a valid checksum evaluates to 0 (or ~0xffff = 0x0000).
pub fn verify(data: []const u8) bool {
    return compute(data) == 0;
}

// ============================================================================
// L3 & L4 Pseudo-Header & Checksum Helpers
// ============================================================================

/// Calculates the 12-byte IPv4 pseudo-header sum for TCP or UDP:
///   [4-byte Src IP] + [4-byte Dst IP] + [1-byte Zero, 1-byte Proto] + [2-byte L4 Length]
pub inline fn pseudoHeaderChecksumV4(src: [4]u8, dst: [4]u8, proto: u8, l4_len: u16) u32 {
    const src_hi = (@as(u32, src[0]) << 8) | @as(u32, src[1]);
    const src_lo = (@as(u32, src[2]) << 8) | @as(u32, src[3]);
    const dst_hi = (@as(u32, dst[0]) << 8) | @as(u32, dst[1]);
    const dst_lo = (@as(u32, dst[2]) << 8) | @as(u32, dst[3]);
    const proto_word = @as(u32, proto);
    const len_word = @as(u32, l4_len);

    return src_hi + src_lo + dst_hi + dst_lo + proto_word + len_word;
}

/// Computes the 16-bit ones' complement L4 (TCP/UDP) checksum over an IPv4
/// pseudo-header and the L4 segment. The checksum field in the segment MUST be
/// zero when this is called.
pub fn l4Checksum(src: [4]u8, dst: [4]u8, proto: u8, segment: []const u8) u16 {
    var sum: u64 = pseudoHeaderChecksumV4(src, dst, proto, @as(u16, @truncate(segment.len)));

    // Accumulate segment using fast scalar / SIMD logic
    var i: usize = 0;
    while (i + 1 < segment.len) : (i += 2) {
        sum += (@as(u32, segment[i]) << 8) | @as(u32, segment[i + 1]);
    }
    if (i < segment.len) {
        sum += @as(u32, segment[i]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

/// Verifies whether the L4 checksum over an IPv4 segment is valid.
pub fn verifyL4(src: [4]u8, dst: [4]u8, proto: u8, segment: []const u8) bool {
    return l4Checksum(src, dst, proto, segment) == 0;
}

/// Computes the 16-bit IPv4 header checksum over the first 20 (or ihl * 4) bytes.
/// Assumes checksum field at offset 10..12 is zero.
pub fn ipv4HeaderChecksum(header: []const u8) u16 {
    std.debug.assert(header.len >= IPV4_HEADER_LEN);
    return compute(header[0..IPV4_HEADER_LEN]);
}

// ============================================================================
// PCK (FakeTCP) Header Crafting & Frame Assembly
// ============================================================================

/// Parameters for assembling an outgoing FakeTCP (PCK) carrier frame.
pub const PckFrameParams = struct {
    src_mac: ?[6]u8 = null,
    dst_mac: ?[6]u8 = null,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8 = TcpFlags.PSH | TcpFlags.ACK,
    ts_val: u32,
    ts_ecr: u32 = 0,
    ip_id: u16 = 0,
    payload: []const u8 = "",
};

/// Result of parsing an incoming PCK frame.
pub const PckSegment = struct {
    src_mac: ?[6]u8 = null,
    dst_mac: ?[6]u8 = null,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ts_val: u32,
    ts_ecr: u32,
    payload: []const u8,
};

/// Returns the total wire frame length for a given payload and whether Ethernet is included.
pub inline fn pckFrameLen(payload_len: usize, include_eth: bool) usize {
    const base = PCK_OVERHEAD + payload_len;
    return if (include_eth) PCK_ETH_HEADER_LEN + base else base;
}

/// Builds an IPv4 header for PCK wrapping an L4 payload into `dst`.
/// Sets DSCP 46 (EF), Don't Fragment flag, TTL 64, TCP protocol, and computes IPv4 checksum.
pub fn buildPckIPv4(dst: []u8, id: u16, src: [4]u8, dst_ip: [4]u8, l4: []const u8) []u8 {
    const total_len = IPV4_HEADER_LEN + l4.len;
    std.debug.assert(dst.len >= total_len);

    const ip = dst[0..total_len];
    ip[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    ip[1] = PCK_DSCP_EF; // DSCP 46 (EF), ECN 0
    std.mem.writeInt(u16, ip[2..4], @as(u16, @truncate(total_len)), .big);
    std.mem.writeInt(u16, ip[4..6], id, .big);
    std.mem.writeInt(u16, ip[6..8], IPV4_DONT_FRAGMENT, .big);
    ip[8] = 64; // TTL 64
    ip[9] = IPPROTO_TCP; // TCP
    ip[10] = 0; // Checksum 0 while computing
    ip[11] = 0;
    @memcpy(ip[12..16], &src);
    @memcpy(ip[16..20], &dst_ip);

    // Compute and store IPv4 header checksum
    const csum = compute(ip[0..IPV4_HEADER_LEN]);
    std.mem.writeInt(u16, ip[10..12], csum, .big);

    // Copy L4 segment
    @memcpy(ip[IPV4_HEADER_LEN..total_len], l4);
    return ip;
}

/// Builds a TCP segment with Linux-identical NOP, NOP, Timestamps options into `dst`.
/// Sets data offset 8 (32 bytes), Window 65535, specified flags, and calculates L4 checksum.
pub fn buildPckTCP(
    dst: []u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ts_val: u32,
    ts_ecr: u32,
    src: [4]u8,
    dst_ip: [4]u8,
    payload: []const u8,
) []u8 {
    const total_len = PCK_TCP_TOTAL_LEN + payload.len;
    std.debug.assert(dst.len >= total_len);

    const tcp = dst[0..total_len];
    std.mem.writeInt(u16, tcp[0..2], src_port, .big);
    std.mem.writeInt(u16, tcp[2..4], dst_port, .big);
    std.mem.writeInt(u32, tcp[4..8], seq, .big);
    std.mem.writeInt(u32, tcp[8..12], ack, .big);
    tcp[12] = @as(u8, @truncate(PCK_TCP_TOTAL_LEN / 4)) << 4; // Data offset 8 (32 bytes)
    tcp[13] = flags;
    std.mem.writeInt(u16, tcp[14..16], PCK_DEFAULT_WINDOW, .big);
    tcp[16] = 0; // Checksum 0 while computing
    tcp[17] = 0;
    tcp[18] = 0; // Urgent pointer
    tcp[19] = 0;

    // NOP, NOP, Timestamps (Option 8, length 10)
    tcp[20] = 1; // NOP
    tcp[21] = 1; // NOP
    tcp[22] = 8; // Kind: Timestamp
    tcp[23] = 10; // Length: 10
    std.mem.writeInt(u32, tcp[24..28], ts_val, .big);
    std.mem.writeInt(u32, tcp[28..32], ts_ecr, .big);

    // Copy payload
    @memcpy(tcp[PCK_TCP_TOTAL_LEN..total_len], payload);

    // Compute TCP checksum over IPv4 pseudo-header
    const csum = l4Checksum(src, dst_ip, IPPROTO_TCP, tcp);
    std.mem.writeInt(u16, tcp[16..18], csum, .big);

    return tcp;
}

/// Prepends an Ethernet header (14 bytes) to an IP frame.
pub fn buildPckEthernet(dst: []u8, dst_mac: [6]u8, src_mac: [6]u8, ip_payload: []const u8) []u8 {
    const total = PCK_ETH_HEADER_LEN + ip_payload.len;
    std.debug.assert(dst.len >= total);

    @memcpy(dst[0..6], &dst_mac);
    @memcpy(dst[6..12], &src_mac);
    std.mem.writeInt(u16, dst[12..14], ETHERTYPE_IPV4, .big);
    @memcpy(dst[PCK_ETH_HEADER_LEN..total], ip_payload);
    return dst[0..total];
}

/// Assembles a complete Ethernet + IPv4 + TCP (or raw IPv4 + TCP) frame in place into `buf`.
/// Eliminates intermediate buffer allocations.
pub fn assemblePckFrame(buf: []u8, p: PckFrameParams) []u8 {
    const has_eth = p.src_mac != null and p.dst_mac != null;
    const total = pckFrameLen(p.payload.len, has_eth);
    std.debug.assert(buf.len >= total);

    const eth_offset: usize = if (has_eth) PCK_ETH_HEADER_LEN else 0;
    const ip_offset = eth_offset;
    const tcp_offset = ip_offset + IPV4_HEADER_LEN;
    const payload_offset = tcp_offset + PCK_TCP_TOTAL_LEN;

    // 1. Ethernet (if MACs supplied)
    if (has_eth) {
        @memcpy(buf[0..6], &p.dst_mac.?);
        @memcpy(buf[6..12], &p.src_mac.?);
        std.mem.writeInt(u16, buf[12..14], ETHERTYPE_IPV4, .big);
    }

    // 2. IPv4 Header
    const ip = buf[ip_offset .. ip_offset + IPV4_HEADER_LEN];
    const ip_total_len = @as(u16, @truncate(IPV4_HEADER_LEN + PCK_TCP_TOTAL_LEN + p.payload.len));
    ip[0] = 0x45;
    ip[1] = PCK_DSCP_EF;
    std.mem.writeInt(u16, ip[2..4], ip_total_len, .big);
    std.mem.writeInt(u16, ip[4..6], p.ip_id, .big);
    std.mem.writeInt(u16, ip[6..8], IPV4_DONT_FRAGMENT, .big);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    ip[10] = 0;
    ip[11] = 0;
    @memcpy(ip[12..16], &p.src_ip);
    @memcpy(ip[16..20], &p.dst_ip);

    const ip_csum = compute(ip);
    std.mem.writeInt(u16, ip[10..12], ip_csum, .big);

    // 3. TCP Header + Options
    const tcp_seg = buf[tcp_offset .. payload_offset + p.payload.len];
    std.mem.writeInt(u16, tcp_seg[0..2], p.src_port, .big);
    std.mem.writeInt(u16, tcp_seg[2..4], p.dst_port, .big);
    std.mem.writeInt(u32, tcp_seg[4..8], p.seq, .big);
    std.mem.writeInt(u32, tcp_seg[8..12], p.ack, .big);
    tcp_seg[12] = @as(u8, @truncate(PCK_TCP_TOTAL_LEN / 4)) << 4;
    tcp_seg[13] = p.flags;
    std.mem.writeInt(u16, tcp_seg[14..16], PCK_DEFAULT_WINDOW, .big);
    tcp_seg[16] = 0;
    tcp_seg[17] = 0;
    tcp_seg[18] = 0;
    tcp_seg[19] = 0;

    // NOP, NOP, Timestamps
    tcp_seg[20] = 1;
    tcp_seg[21] = 1;
    tcp_seg[22] = 8;
    tcp_seg[23] = 10;
    std.mem.writeInt(u32, tcp_seg[24..28], p.ts_val, .big);
    std.mem.writeInt(u32, tcp_seg[28..32], p.ts_ecr, .big);

    // 4. Payload
    if (p.payload.len > 0) {
        @memcpy(buf[payload_offset .. payload_offset + p.payload.len], p.payload);
    }

    // 5. TCP Checksum
    const tcp_csum = l4Checksum(p.src_ip, p.dst_ip, IPPROTO_TCP, tcp_seg);
    std.mem.writeInt(u16, tcp_seg[16..18], tcp_csum, .big);

    return buf[0..total];
}

/// Parses a received PCK frame.
/// Verifies link length, IPv4 header, TCP protocol, destination port, and extracts TCP timestamp.
pub fn parsePckFrame(frame: []const u8, link_len: usize, want_port: ?u16) ?PckSegment {
    if (frame.len < link_len + IPV4_HEADER_LEN) return null;

    var seg = PckSegment{
        .src_ip = undefined,
        .dst_ip = undefined,
        .src_port = 0,
        .dst_port = 0,
        .seq = 0,
        .ack = 0,
        .flags = 0,
        .ts_val = 0,
        .ts_ecr = 0,
        .payload = "",
    };

    if (link_len == PCK_ETH_HEADER_LEN) {
        if (std.mem.readInt(u16, frame[12..14], .big) != ETHERTYPE_IPV4) return null;
        seg.dst_mac = frame[0..6].*;
        seg.src_mac = frame[6..12].*;
    }

    const ip = frame[link_len..];
    if (ip[0] >> 4 != 4) return null; // Must be IPv4

    const ihl = @as(usize, ip[0] & 0x0f) * 4;
    if (ihl < IPV4_HEADER_LEN or ip.len < ihl) return null;
    if (ip[9] != IPPROTO_TCP) return null; // Must be TCP

    // Fragment offset check: must not be a fragment
    if (std.mem.readInt(u16, ip[6..8], .big) & 0x1fff != 0) return null;

    const total_ip_len = std.mem.readInt(u16, ip[2..4], .big);
    if (total_ip_len < ihl or total_ip_len > ip.len) return null;

    const tcp = ip[ihl..total_ip_len];
    if (tcp.len < PCK_TCP_HEADER_LEN) return null;

    const dst_port = std.mem.readInt(u16, tcp[2..4], .big);
    if (want_port) |wp| {
        if (dst_port != wp) return null;
    }

    const data_offset = (@as(usize, tcp[12] >> 4)) * 4;
    if (data_offset < PCK_TCP_HEADER_LEN or data_offset > tcp.len) return null;

    seg.src_ip = ip[12..16].*;
    seg.dst_ip = ip[16..20].*;
    seg.src_port = std.mem.readInt(u16, tcp[0..2], .big);
    seg.dst_port = dst_port;
    seg.seq = std.mem.readInt(u32, tcp[4..8], .big);
    seg.ack = std.mem.readInt(u32, tcp[8..12], .big);
    seg.flags = tcp[13];

    // Extract TCP timestamps
    if (data_offset > PCK_TCP_HEADER_LEN) {
        const ts = extractTcpTimestamp(tcp[PCK_TCP_HEADER_LEN..data_offset]);
        seg.ts_val = ts.ts_val;
        seg.ts_ecr = ts.ts_ecr;
    }

    seg.payload = tcp[data_offset..];
    return seg;
}

/// Parses TCP options to extract timestamp (TSval, TSecr).
pub fn extractTcpTimestamp(opts: []const u8) struct { ts_val: u32, ts_ecr: u32 } {
    var i: usize = 0;
    while (i < opts.len) {
        switch (opts[i]) {
            0 => break, // End of options
            1 => { // NOP
                i += 1;
                continue;
            },
            else => {},
        }
        if (i + 1 >= opts.len) break;
        const opt_len = opts[i + 1];
        if (opt_len < 2 or i + opt_len > opts.len) break;

        if (opts[i] == 8 and opt_len == 10) {
            const ts_val = std.mem.readInt(u32, opts[i + 2 .. i + 6][0..4], .big);
            const ts_ecr = std.mem.readInt(u32, opts[i + 6 .. i + 10][0..4], .big);
            return .{ .ts_val = ts_val, .ts_ecr = ts_ecr };
        }
        i += opt_len;
    }
    return .{ .ts_val = 0, .ts_ecr = 0 };
}

// ============================================================================
// Unit Tests
// ============================================================================

test "RFC 1071 Official Example Test Vector" {
    // RFC 1071 Section 3 numerical example:
    // Input: 00 01 f2 03 f4 f5 f6 f7
    // Expected 16-bit 1's complement sum = 0xddf2, checksum = 0x220d
    const rfc_vector = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    const csum_simd = computeSimd(&rfc_vector);
    const csum_64 = compute64(&rfc_vector);
    const csum_scalar = computeScalar(&rfc_vector);

    try std.testing.expectEqual(@as(u16, 0x220d), csum_simd);
    try std.testing.expectEqual(@as(u16, 0x220d), csum_64);
    try std.testing.expectEqual(@as(u16, 0x220d), csum_scalar);

    // Verification check: computing checksum over data + checksum evaluates to 0
    var packet_with_csum: [10]u8 = undefined;
    @memcpy(packet_with_csum[0..8], &rfc_vector);
    std.mem.writeInt(u16, packet_with_csum[8..10], csum_simd, .big);
    try std.testing.expect(verify(&packet_with_csum));
}

test "SIMD vs 64-bit vs Scalar Cross-Validation Across Varied Lengths" {
    // Generate pseudo-random bytes and verify SIMD, 64-bit, and Scalar match on all sizes
    var buffer: [2048]u8 = undefined;
    for (&buffer, 0..) |*b, idx| {
        b.* = @as(u8, @truncate((idx *% 37) +% 19));
    }

    const test_sizes = [_]usize{
        0,    1,    2,    3,    4,    5,    7,    8,    9,
        15,   16,   17,   20,   31,   32,   33,   63,   64,
        65,   100,  127,  128,  129,  255,  256,  512,  1000,
        1460, 1500, 2048,
    };

    for (test_sizes) |sz| {
        const slice = buffer[0..sz];
        const res_simd = computeSimd(slice);
        const res_64 = compute64(slice);
        const res_scalar = computeScalar(slice);

        try std.testing.expectEqual(res_scalar, res_simd);
        try std.testing.expectEqual(res_scalar, res_64);
    }
}

test "BackPack Go pckframe Test Vector & Checksums" {
    // Match testSrc and testDst from Go pckframe_test.go:
    // testSrc = 203.0.113.10, testDst = 198.51.100.20
    const src_ip = [4]u8{ 203, 0, 113, 10 };
    const dst_ip = [4]u8{ 198, 51, 100, 20 };
    const payload = "some tunnel bytes";

    var buf: [256]u8 = undefined;
    const frame = assemblePckFrame(&buf, .{
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = 40000,
        .dst_port = 443,
        .seq = 7,
        .ack = 9,
        .flags = TcpFlags.PSH | TcpFlags.ACK,
        .ts_val = 111111,
        .ts_ecr = 222222,
        .ip_id = 1234,
        .payload = payload,
    });

    try std.testing.expectEqual(PCK_OVERHEAD + payload.len, frame.len);

    // 1. Verify IPv4 Header checksum evaluates to 0
    const ip_hdr = frame[0..IPV4_HEADER_LEN];
    try std.testing.expectEqual(@as(u16, 0), compute(ip_hdr));

    // 2. Verify DSCP 46 EF and DF bit
    try std.testing.expectEqual(@as(u8, 46), ip_hdr[1] >> 2);
    try std.testing.expect(std.mem.readInt(u16, ip_hdr[6..8], .big) & IPV4_DONT_FRAGMENT != 0);

    // 3. Verify TCP checksum over IPv4 pseudo-header evaluates to 0
    const tcp_seg = frame[IPV4_HEADER_LEN..frame.len];
    try std.testing.expectEqual(@as(u16, 0), l4Checksum(src_ip, dst_ip, IPPROTO_TCP, tcp_seg));

    // 4. Verify TCP options contain correct timestamps
    const seg = parsePckFrame(frame, 0, 443).?;
    try std.testing.expectEqual(@as(u16, 40000), seg.src_port);
    try std.testing.expectEqual(@as(u16, 443), seg.dst_port);
    try std.testing.expectEqual(@as(u32, 7), seg.seq);
    try std.testing.expectEqual(@as(u32, 9), seg.ack);
    try std.testing.expectEqual(@as(u32, 111111), seg.ts_val);
    try std.testing.expectEqual(@as(u32, 222222), seg.ts_ecr);
    try std.testing.expectEqualSlices(u8, payload, seg.payload);
}

test "Ethernet Framing & Port Rejection" {
    const src_ip = [4]u8{ 10, 0, 0, 1 };
    const dst_ip = [4]u8{ 10, 0, 0, 2 };
    const src_mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const dst_mac = [6]u8{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };

    var buf: [256]u8 = undefined;
    const frame = assemblePckFrame(&buf, .{
        .src_mac = src_mac,
        .dst_mac = dst_mac,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = 5555,
        .dst_port = 8443,
        .seq = 100,
        .ack = 200,
        .ts_val = 9999,
        .payload = "data-payload",
    });

    try std.testing.expectEqual(PCK_TOTAL_OVERHEAD + 12, frame.len);

    // Successful parse with correct port
    const seg = parsePckFrame(frame, PCK_ETH_HEADER_LEN, 8443).?;
    try std.testing.expectEqualSlices(u8, &src_mac, &seg.src_mac.?);
    try std.testing.expectEqualSlices(u8, &dst_mac, &seg.dst_mac.?);
    try std.testing.expectEqualSlices(u8, "data-payload", seg.payload);

    // Reject segment for mismatched port
    try std.testing.expect(parsePckFrame(frame, PCK_ETH_HEADER_LEN, 9999) == null);
}

test "Unaligned Pointers and Boundary Values" {
    var raw_memory: [256]u8 align(64) = undefined;
    for (&raw_memory, 0..) |*b, idx| {
        b.* = @as(u8, @truncate(idx *% 13 +% 7));
    }

    // Test non-aligned slice offsets: 1, 3, 5, 7
    const offsets = [_]usize{ 1, 2, 3, 5, 7, 9, 11, 13, 15 };
    for (offsets) |off| {
        const slice = raw_memory[off .. off + 127];
        const c_simd = computeSimd(slice);
        const c_64 = compute64(slice);
        const c_scalar = computeScalar(slice);

        try std.testing.expectEqual(c_scalar, c_simd);
        try std.testing.expectEqual(c_scalar, c_64);
    }

    // All-zeroes buffer
    const zero_buf = [_]u8{0} ** 64;
    try std.testing.expectEqual(@as(u16, 0xffff), compute(&zero_buf));

    // All-0xFF buffer
    const ff_buf = [_]u8{0xff} ** 64;
    try std.testing.expectEqual(computeScalar(&ff_buf), compute(&ff_buf));
}

test "Checksum Corruption Detection" {
    const src_ip = [4]u8{ 192, 0, 2, 1 };
    const dst_ip = [4]u8{ 192, 0, 2, 2 };
    var buf: [256]u8 = undefined;

    const frame = assemblePckFrame(&buf, .{
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = 12345,
        .dst_port = 80,
        .seq = 1,
        .ack = 1,
        .ts_val = 500,
        .payload = "critical payload",
    });

    // Valid check
    const ip_hdr = frame[0..IPV4_HEADER_LEN];
    try std.testing.expect(verify(ip_hdr));

    const tcp_seg = frame[IPV4_HEADER_LEN..frame.len];
    try std.testing.expect(verifyL4(src_ip, dst_ip, IPPROTO_TCP, tcp_seg));

    // Corrupt one bit in payload
    frame[frame.len - 1] ^= 0x01;
    try std.testing.expect(!verifyL4(src_ip, dst_ip, IPPROTO_TCP, tcp_seg));
}

