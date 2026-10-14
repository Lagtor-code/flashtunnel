const std = @import("std");
pub const checksum = @import("checksum.zig");

/// RFC 2784 / RFC 2890 GRE Encapsulation matching BackPack encap.go.
pub const GreEncap = struct {
    key: u32 = 0,
    keyed: bool = false,

    pub const ETHER_IPV4: u16 = 0x0800;
    pub const ETHER_IPV6: u16 = 0x86DD;
    pub const GRE_KEY_PRESENT: u16 = 0x2000;

    pub fn init(key: u32) GreEncap {
        return .{
            .key = key,
            .keyed = key != 0,
        };
    }

    pub inline fn overhead(self: GreEncap) usize {
        return if (self.keyed) 8 else 4;
    }

    pub fn wrap(self: GreEncap, dst: []u8, pkt: []const u8) error{ EmptyPacket, BadIPVersion, BufferTooSmall }!usize {
        if (pkt.len == 0) return error.EmptyPacket;

        const version = pkt[0] >> 4;
        const proto: u16 = switch (version) {
            4 => ETHER_IPV4,
            6 => ETHER_IPV6,
            else => return error.BadIPVersion,
        };

        const oh = self.overhead();
        if (dst.len < oh + pkt.len) return error.BufferTooSmall;

        if (self.keyed) {
            std.mem.writeInt(u16, dst[0..2], GRE_KEY_PRESENT, .big);
            std.mem.writeInt(u16, dst[2..4], proto, .big);
            std.mem.writeInt(u32, dst[4..8], self.key, .big);
            @memcpy(dst[8 .. 8 + pkt.len], pkt);
            return 8 + pkt.len;
        } else {
            std.mem.writeInt(u16, dst[0..2], 0, .big);
            std.mem.writeInt(u16, dst[2..4], proto, .big);
            @memcpy(dst[4 .. 4 + pkt.len], pkt);
            return 4 + pkt.len;
        }
    }

    pub fn unwrap(self: GreEncap, frame: []const u8) error{ ShortGRE, GREFlags, GREProto, GREKeyMissing, GREKeyWrong }![]const u8 {
        const oh = self.overhead();
        if (frame.len < oh) return error.ShortGRE;

        const flags = std.mem.readInt(u16, frame[0..2], .big);
        const proto = std.mem.readInt(u16, frame[2..4], .big);

        if (proto != ETHER_IPV4 and proto != ETHER_IPV6) {
            return error.GREProto;
        }

        if (self.keyed) {
            if ((flags & GRE_KEY_PRESENT) == 0) return error.GREKeyMissing;
            if (flags != GRE_KEY_PRESENT) return error.GREFlags;
            const gotKey = std.mem.readInt(u32, frame[4..8], .big);
            if (gotKey != self.key) return error.GREKeyWrong;
            return frame[8..];
        } else {
            if (flags != 0) return error.GREFlags;
            return frame[4..];
        }
    }
};

/// FakeTCP (PCK) Obfuscated Carrier Encapsulation matching BackPack's network carrier.
///
/// Encapsulates inner payloads (such as encrypted KCP/Wire datagrams) into
/// legitimate-looking IPv4 + TCP frames with real timestamps, window scaling,
/// DSCP 46 EF markings, Don't-Fragment bit, and RFC 1071 hardware-valid checksums.
pub const PckEncap = struct {
    src_ip: [4]u8,
    dst_ip: [4]u8,
    src_port: u16,
    dst_port: u16,
    seq: u32 = 1,
    ack: u32 = 1,
    ts_val: u32 = 100000,
    ts_ecr: u32 = 0,
    flags: u8 = checksum.TcpFlags.PSH | checksum.TcpFlags.ACK,
    ip_id: u16 = 1,
    include_ethernet: bool = false,
    src_mac: [6]u8 = [_]u8{0} ** 6,
    dst_mac: [6]u8 = [_]u8{0} ** 6,

    pub const IPV4_HEADER_LEN: usize = checksum.IPV4_HEADER_LEN;
    pub const TCP_HEADER_LEN: usize = checksum.PCK_TCP_TOTAL_LEN;
    pub const OVERHEAD_IP_TCP: usize = checksum.PCK_OVERHEAD; // 52 bytes
    pub const OVERHEAD_ETH: usize = checksum.PCK_ETH_HEADER_LEN; // 14 bytes
    pub const TOTAL_OVERHEAD: usize = checksum.PCK_TOTAL_OVERHEAD; // 66 bytes

    pub fn init(src_ip: [4]u8, dst_ip: [4]u8, src_port: u16, dst_port: u16) PckEncap {
        return .{
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
        };
    }

    pub inline fn overhead(self: PckEncap) usize {
        return if (self.include_ethernet) TOTAL_OVERHEAD else OVERHEAD_IP_TCP;
    }

    pub fn wrap(self: *PckEncap, dst: []u8, pkt: []const u8) error{ EmptyPacket, BufferTooSmall }!usize {
        if (pkt.len == 0) return error.EmptyPacket;
        const oh = self.overhead();
        if (dst.len < oh + pkt.len) return error.BufferTooSmall;

        const frame = checksum.assemblePckFrame(dst, .{
            .src_mac = if (self.include_ethernet) self.src_mac else null,
            .dst_mac = if (self.include_ethernet) self.dst_mac else null,
            .src_ip = self.src_ip,
            .dst_ip = self.dst_ip,
            .src_port = self.src_port,
            .dst_port = self.dst_port,
            .seq = self.seq,
            .ack = self.ack,
            .flags = self.flags,
            .ts_val = self.ts_val,
            .ts_ecr = self.ts_ecr,
            .ip_id = self.ip_id,
            .payload = pkt,
        });

        // Advance state: track sequence bytes, increment IP ID and timestamp clock
        self.seq +%= @as(u32, @truncate(pkt.len));
        self.ip_id +%= 1;
        self.ts_val +%= 1;

        return frame.len;
    }

    pub fn unwrap(self: *PckEncap, frame: []const u8) error{ ShortPacket, BadFrame, PortMismatch, ChecksumError }![]const u8 {
        const link_len = if (self.include_ethernet) OVERHEAD_ETH else 0;
        if (frame.len < link_len + IPV4_HEADER_LEN) return error.ShortPacket;

        // Parse segment; accepts traffic addressed to either our local port or configured peer port
        const seg = checksum.parsePckFrame(frame, link_len, null) orelse return error.BadFrame;
        if (seg.dst_port != self.src_port and seg.dst_port != self.dst_port) {
            return error.PortMismatch;
        }

        // Verify IPv4 header checksum
        const ip_slice = frame[link_len..];
        const ihl = @as(usize, ip_slice[0] & 0x0f) * 4;
        if (checksum.compute(ip_slice[0..ihl]) != 0) {
            return error.ChecksumError;
        }

        // Verify TCP checksum over IPv4 pseudo-header
        const total_len = std.mem.readInt(u16, ip_slice[2..4], .big);
        const tcp_slice = ip_slice[ihl..total_len];
        if (checksum.l4Checksum(seg.src_ip, seg.dst_ip, checksum.IPPROTO_TCP, tcp_slice) != 0) {
            return error.ChecksumError;
        }

        // Update state: learn/echo peer's timestamp, advance ACK
        if (seg.ts_val != 0) {
            self.ts_ecr = seg.ts_val;
        }
        self.ack = seg.seq +% @as(u32, @truncate(seg.payload.len));

        return seg.payload;
    }
};

test "GreEncap keyed and unkeyed" {
    // IPv4 fake packet
    const pkt = [_]u8{ 0x45, 0x00, 0x00, 0x14 } ++ [_]u8{0} ** 16;
    var buf: [64]u8 = undefined;

    // Keyed
    const keyed = GreEncap.init(1337);
    const sz1 = try keyed.wrap(&buf, &pkt);
    try std.testing.expectEqual(8 + pkt.len, sz1);
    const inner1 = try keyed.unwrap(buf[0..sz1]);
    try std.testing.expectEqualSlices(u8, &pkt, inner1);

    // Unkeyed
    const unkeyed = GreEncap.init(0);
    const sz2 = try unkeyed.wrap(&buf, &pkt);
    try std.testing.expectEqual(4 + pkt.len, sz2);
    const inner2 = try unkeyed.unwrap(buf[0..sz2]);
    try std.testing.expectEqualSlices(u8, &pkt, inner2);
}

test "PckEncap wrap, unwrap and state progression" {
    const src_ip = [4]u8{ 192, 168, 1, 100 };
    const dst_ip = [4]u8{ 10, 0, 0, 1 };
    var pck = PckEncap.init(src_ip, dst_ip, 50000, 443);

    const payload = "TUNNEL_ENCRYPTED_PACKET_PAYLOAD";
    var buf: [256]u8 = undefined;

    // First packet
    const len1 = try pck.wrap(&buf, payload);
    try std.testing.expectEqual(PckEncap.OVERHEAD_IP_TCP + payload.len, len1);

    const unwrapped1 = try pck.unwrap(buf[0..len1]);
    try std.testing.expectEqualSlices(u8, payload, unwrapped1);

    // Verify sequence number and IP ID advanced
    try std.testing.expectEqual(@as(u32, 1) + payload.len, pck.seq);
    try std.testing.expectEqual(@as(u16, 2), pck.ip_id);

    // Second packet
    const payload2 = "ANOTHER_PACKET";
    const len2 = try pck.wrap(&buf, payload2);
    const unwrapped2 = try pck.unwrap(buf[0..len2]);
    try std.testing.expectEqualSlices(u8, payload2, unwrapped2);

    try std.testing.expectEqual(@as(u32, 1) + payload.len + payload2.len, pck.seq);
    try std.testing.expectEqual(@as(u16, 3), pck.ip_id);
}

test "PckEncap with Ethernet Framing" {
    const src_ip = [4]u8{ 172, 16, 0, 5 };
    const dst_ip = [4]u8{ 172, 16, 0, 1 };
    var pck = PckEncap.init(src_ip, dst_ip, 12345, 8080);
    pck.include_ethernet = true;
    pck.src_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    pck.dst_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

    const payload = "ETHERNET_FRAMED_PAYLOAD";
    var buf: [256]u8 = undefined;

    const sz = try pck.wrap(&buf, payload);
    try std.testing.expectEqual(PckEncap.TOTAL_OVERHEAD + payload.len, sz);

    const unwrapped = try pck.unwrap(buf[0..sz]);
    try std.testing.expectEqualSlices(u8, payload, unwrapped);
}
