const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

/// UDP Generic Segmentation Offload (GSO) and Generic Receive Offload (GRO) manager.
///
/// Transmit path (GSO):
/// Allows sending up to 64KB super-packets which the Linux kernel / NIC hardware
/// automatically splits into MTU-sized segments, saving immense CPU overhead and
/// reducing kernel protocol stack passes by up to 80%.
///
/// Receive path (GRO):
/// Linux kernel / NIC hardware aggregates incoming datagrams into a coalesced super-packet
/// (up to 64KB) with ancillary control data (UDP_GRO) specifying the segment size.
/// GsoManager provides zero-copy unpacking into MTU-sized datagram slices.
pub const GsoManager = struct {
    pub const IPPROTO_UDP: u32 = 17;
    pub const SOL_UDP: u32 = 17;
    pub const UDP_SEGMENT: u32 = 103;
    pub const UDP_GRO: u32 = 104;
    pub const MAX_SEGMENTS: usize = 64;
    pub const MAX_GSO_SIZE: usize = 65535;
    pub const MAX_GRO_SIZE: usize = 65535;

    pub const Cmsghdr = extern struct {
        len: usize,
        level: i32,
        type: i32,
    };

    pub const GsoRun = struct {
        count: usize,
        segment_size: usize,
    };

    // -------------------------------------------------------------------------
    // GSO (Transmit Offload) Batching
    // -------------------------------------------------------------------------

    /// Scans a batch of buffers and finds the longest contiguous run of packets
    /// that can be sent as a single GSO write.
    ///
    /// Every segment in the run must be identical in length (segment_size),
    /// except the final segment which may be smaller (the remainder).
    pub fn findGsoRun(bufs: []const []const u8) GsoRun {
        if (bufs.len == 0) return .{ .count = 0, .segment_size = 0 };

        const segment_size = bufs[0].len;
        if (segment_size == 0 or segment_size > MAX_GSO_SIZE) return .{ .count = 0, .segment_size = 0 };

        var count: usize = 1;
        var total_bytes: usize = segment_size;

        while (count < bufs.len and count < MAX_SEGMENTS) : (count += 1) {
            const next_len = bufs[count].len;
            if (next_len == 0 or next_len > segment_size) break;
            if (total_bytes + next_len > MAX_GSO_SIZE) break;

            total_bytes += next_len;
            if (next_len < segment_size) {
                // A shorter packet can only be the last segment of this GSO run
                count += 1;
                break;
            }
        }

        return .{ .count = count, .segment_size = segment_size };
    }

    /// Checks if a discovered run qualifies for GSO offload (at least 2 segments).
    pub inline fn isGsoEligible(run: GsoRun) bool {
        return run.count > 1 and run.segment_size > 0;
    }

    /// Coalesces a slice of packet buffers into a single contiguous GSO super-packet payload.
    /// Returns the total bytes written into `dst`.
    pub fn coalesce(bufs: []const []const u8, dst: []u8) !usize {
        var total: usize = 0;
        for (bufs) |b| {
            total += b.len;
        }
        if (total > MAX_GSO_SIZE) return error.SuperpacketTooLarge;
        if (dst.len < total) return error.BufferTooSmall;

        var offset: usize = 0;
        for (bufs) |b| {
            @memcpy(dst[offset .. offset + b.len], b);
            offset += b.len;
        }
        return total;
    }

    /// Result of preparing a GSO batch for transmission.
    pub const GsoSendBatch = struct {
        count: usize,
        segment_size: usize,
        payload_len: usize,
        cmsg_len: usize,
        is_gso: bool,
    };

    /// High-level helper: inspects `bufs`, coalesces the longest qualifying GSO run into `dst_payload`,
    /// and formats the `UDP_SEGMENT` cmsg in `cmsg_buf`.
    pub fn prepareGsoBatch(
        bufs: []const []const u8,
        dst_payload: []u8,
        cmsg_buf: []u8,
    ) !GsoSendBatch {
        const run = findGsoRun(bufs);
        if (run.count == 0) {
            return .{
                .count = 0,
                .segment_size = 0,
                .payload_len = 0,
                .cmsg_len = 0,
                .is_gso = false,
            };
        }

        const payload_len = try coalesce(bufs[0..run.count], dst_payload);
        var cmsg_len: usize = 0;
        const is_gso = isGsoEligible(run);

        if (is_gso) {
            cmsg_len = try buildCmsg(cmsg_buf, @intCast(run.segment_size));
        }

        return .{
            .count = run.count,
            .segment_size = run.segment_size,
            .payload_len = payload_len,
            .cmsg_len = cmsg_len,
            .is_gso = is_gso,
        };
    }

    // -------------------------------------------------------------------------
    // Control Message (cmsg) Formatting & Parsing
    // -------------------------------------------------------------------------

    /// Formats the UDP_SEGMENT cmsg control block into provided buffer.
    pub fn buildCmsg(cmsg_buf: []u8, segment_size: u16) !usize {
        return buildTypedCmsg(cmsg_buf, UDP_SEGMENT, segment_size);
    }

    /// Formats the UDP_GRO cmsg control block into provided buffer.
    pub fn buildGroCmsg(cmsg_buf: []u8, segment_size: u16) !usize {
        return buildTypedCmsg(cmsg_buf, UDP_GRO, segment_size);
    }

    fn buildTypedCmsg(cmsg_buf: []u8, cmsg_type: u32, segment_size: u16) !usize {
        const header_size = @sizeOf(Cmsghdr);
        const total_size = header_size + @sizeOf(u16);
        if (cmsg_buf.len < total_size) return error.BufferTooSmall;

        @memset(cmsg_buf[0..total_size], 0);

        if (@intFromPtr(cmsg_buf.ptr) % @alignOf(Cmsghdr) == 0) {
            const hdr: *Cmsghdr = @ptrCast(@alignCast(cmsg_buf.ptr));
            hdr.len = total_size;
            hdr.level = @intCast(IPPROTO_UDP);
            hdr.type = @intCast(cmsg_type);
        } else {
            std.mem.writeInt(usize, cmsg_buf[0..@sizeOf(usize)], total_size, native_endian);
            std.mem.writeInt(i32, cmsg_buf[@sizeOf(usize) .. @sizeOf(usize) + 4], @intCast(IPPROTO_UDP), native_endian);
            std.mem.writeInt(i32, cmsg_buf[@sizeOf(usize) + 4 .. @sizeOf(usize) + 8], @intCast(cmsg_type), native_endian);
        }

        std.mem.writeInt(u16, cmsg_buf[header_size..total_size], segment_size, native_endian);
        return total_size;
    }

    /// Parses a control message buffer to extract a 16-bit payload value for a matching cmsg level and type.
    pub fn parseCmsg(cmsg_buf: []const u8, cmsg_type: u32) ?u16 {
        const header_size = @sizeOf(Cmsghdr);
        const min_size = header_size + @sizeOf(u16);
        var offset: usize = 0;

        while (offset + header_size <= cmsg_buf.len) {
            const hdr_ptr = cmsg_buf[offset..];
            const hdr_len = std.mem.readInt(usize, hdr_ptr[0..@sizeOf(usize)], native_endian);
            const hdr_level = std.mem.readInt(i32, hdr_ptr[@sizeOf(usize) .. @sizeOf(usize) + 4], native_endian);
            const hdr_t = std.mem.readInt(i32, hdr_ptr[@sizeOf(usize) + 4 .. @sizeOf(usize) + 8], native_endian);

            if (hdr_len < min_size or offset + hdr_len > cmsg_buf.len) break;

            if (hdr_level == @as(i32, @intCast(IPPROTO_UDP)) and hdr_t == @as(i32, @intCast(cmsg_type))) {
                const data_offset = offset + header_size;
                if (data_offset + @sizeOf(u16) <= cmsg_buf.len) {
                    return std.mem.readInt(u16, cmsg_buf[data_offset..][0..2], native_endian);
                }
            }

            const align_mask: usize = @sizeOf(usize) - 1;
            const aligned_len = (hdr_len + align_mask) & ~align_mask;
            if (aligned_len == 0) break;
            offset += aligned_len;
        }

        return null;
    }

    /// Extracts UDP_GRO segment size from received cmsg buffer.
    pub inline fn parseGroCmsg(cmsg_buf: []const u8) ?u16 {
        return parseCmsg(cmsg_buf, UDP_GRO);
    }

    /// Extracts UDP_SEGMENT segment size from cmsg buffer.
    pub inline fn parseSegmentCmsg(cmsg_buf: []const u8) ?u16 {
        return parseCmsg(cmsg_buf, UDP_SEGMENT);
    }

    // -------------------------------------------------------------------------
    // GRO (Receive Offload) Slicing & Parsing
    // -------------------------------------------------------------------------

    /// Calculates the number of segments in a coalesced packet of length `total_len` with `segment_size`.
    pub fn getSegmentCount(total_len: usize, segment_size: u16) usize {
        if (total_len == 0) return 0;
        if (segment_size == 0 or segment_size >= total_len) return 1;
        return (total_len + segment_size - 1) / segment_size;
    }

    /// Unpacks a received coalesced super-packet (up to 64KB) into individual MTU-sized datagram slices.
    /// Each slice in `out_slices` points directly into `coalesced_buf` (zero allocation).
    ///
    /// - If `coalesced_buf.len == 0`, returns 0.
    /// - If `segment_size == 0` or `segment_size >= coalesced_buf.len`, the packet is treated as a single datagram.
    /// - Returns `error.SuperpacketTooLarge` if `coalesced_buf.len > MAX_GRO_SIZE`.
    /// - Returns `error.BufferTooSmall` if `out_slices.len` is insufficient to hold all segments.
    pub fn unpackGro(
        coalesced_buf: []const u8,
        segment_size: u16,
        out_slices: [][]const u8,
    ) !usize {
        if (coalesced_buf.len == 0) return 0;
        if (coalesced_buf.len > MAX_GRO_SIZE) return error.SuperpacketTooLarge;

        if (segment_size == 0 or segment_size >= coalesced_buf.len) {
            if (out_slices.len < 1) return error.BufferTooSmall;
            out_slices[0] = coalesced_buf;
            return 1;
        }

        const required = (coalesced_buf.len + segment_size - 1) / segment_size;
        if (out_slices.len < required) return error.BufferTooSmall;

        var offset: usize = 0;
        var i: usize = 0;
        while (offset < coalesced_buf.len) : (i += 1) {
            const end = @min(offset + segment_size, coalesced_buf.len);
            out_slices[i] = coalesced_buf[offset..end];
            offset = end;
        }

        return i;
    }

    /// Streaming zero-allocation iterator over GRO super-packet segments.
    pub const GroIterator = struct {
        buffer: []const u8,
        segment_size: usize,
        offset: usize = 0,

        pub fn init(buffer: []const u8, segment_size: u16) GroIterator {
            const seg: usize = if (segment_size == 0 or segment_size >= buffer.len)
                buffer.len
            else
                segment_size;
            return .{
                .buffer = buffer,
                .segment_size = seg,
                .offset = 0,
            };
        }

        pub fn next(self: *GroIterator) ?[]const u8 {
            if (self.offset >= self.buffer.len) return null;
            if (self.segment_size == 0) return null;

            const end = @min(self.offset + self.segment_size, self.buffer.len);
            const slice = self.buffer[self.offset..end];
            self.offset = end;
            return slice;
        }

        pub fn reset(self: *GroIterator) void {
            self.offset = 0;
        }

        pub fn count(self: GroIterator) usize {
            if (self.buffer.len == 0) return 0;
            if (self.segment_size == 0 or self.segment_size >= self.buffer.len) return 1;
            return (self.buffer.len + self.segment_size - 1) / self.segment_size;
        }
    };

    /// Dedicated GRO parser namespace.
    pub const GroParser = struct {
        pub const unpack = unpackGro;
        pub const segmentCount = getSegmentCount;
        pub const iterator = GroIterator.init;
    };

    // -------------------------------------------------------------------------
    // Socket Option Configuration Helpers (setsockopt)
    // -------------------------------------------------------------------------

    /// Configures the UDP_GRO socket option.
    /// When enabled on Linux, incoming datagrams from the same stream are coalesced.
    pub fn setUdpGro(fd: std.posix.socket_t, enabled: bool) !void {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }
        const val: c_int = if (enabled) 1 else 0;
        try std.posix.setsockopt(fd, @intCast(IPPROTO_UDP), UDP_GRO, std.mem.asBytes(&val));
    }

    /// Enables UDP_GRO on the given socket.
    pub inline fn enableGro(fd: std.posix.socket_t) !void {
        return setUdpGro(fd, true);
    }

    /// Disables UDP_GRO on the given socket.
    pub inline fn disableGro(fd: std.posix.socket_t) !void {
        return setUdpGro(fd, false);
    }

    /// Configures the default UDP_SEGMENT socket option.
    /// Sets the kernel default segment size for all subsequent writes on this socket.
    pub fn setUdpSegment(fd: std.posix.socket_t, segment_size: u16) !void {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }
        const val: c_int = @intCast(segment_size);
        try std.posix.setsockopt(fd, @intCast(IPPROTO_UDP), UDP_SEGMENT, std.mem.asBytes(&val));
    }

    /// Disables default UDP_SEGMENT on the given socket (sets segment size to 0).
    pub inline fn disableSegment(fd: std.posix.socket_t) !void {
        return setUdpSegment(fd, 0);
    }
};

// =============================================================================
// Unit Tests
// =============================================================================

test "findGsoRun identical packets" {
    const p1 = [_]u8{1} ** 1400;
    const p2 = [_]u8{2} ** 1400;
    const p3 = [_]u8{3} ** 1400;
    const bufs = [_][]const u8{ &p1, &p2, &p3 };

    const run = GsoManager.findGsoRun(&bufs);
    try std.testing.expectEqual(@as(usize, 3), run.count);
    try std.testing.expectEqual(@as(usize, 1400), run.segment_size);
    try std.testing.expect(GsoManager.isGsoEligible(run));
}

test "findGsoRun with smaller trailing packet" {
    const p1 = [_]u8{1} ** 1400;
    const p2 = [_]u8{2} ** 1400;
    const p3 = [_]u8{3} ** 600; // Smaller final packet
    const p4 = [_]u8{4} ** 1400; // Next run starts here
    const bufs = [_][]const u8{ &p1, &p2, &p3, &p4 };

    const run = GsoManager.findGsoRun(&bufs);
    try std.testing.expectEqual(@as(usize, 3), run.count);
    try std.testing.expectEqual(@as(usize, 1400), run.segment_size);

    // Subsequent run starts at index 3
    const run2 = GsoManager.findGsoRun(bufs[run.count..]);
    try std.testing.expectEqual(@as(usize, 1), run2.count);
    try std.testing.expectEqual(@as(usize, 1400), run2.segment_size);
    try std.testing.expect(!GsoManager.isGsoEligible(run2));
}

test "findGsoRun empty and limits" {
    const empty_bufs = [_][]const u8{};
    try std.testing.expectEqual(@as(usize, 0), GsoManager.findGsoRun(&empty_bufs).count);

    const zero_len = [_]u8{};
    const bufs_zero = [_][]const u8{&zero_len};
    try std.testing.expectEqual(@as(usize, 0), GsoManager.findGsoRun(&bufs_zero).count);
}

test "coalesce GSO batch into super-packet" {
    const p1 = [_]u8{0xAA} ** 1000;
    const p2 = [_]u8{0xBB} ** 1000;
    const p3 = [_]u8{0xCC} ** 500;
    const bufs = [_][]const u8{ &p1, &p2, &p3 };

    var out_buf: [3000]u8 = undefined;
    const total = try GsoManager.coalesce(&bufs, &out_buf);
    try std.testing.expectEqual(@as(usize, 2500), total);

    try std.testing.expectEqualSlices(u8, &p1, out_buf[0..1000]);
    try std.testing.expectEqualSlices(u8, &p2, out_buf[1000..2000]);
    try std.testing.expectEqualSlices(u8, &p3, out_buf[2000..2500]);

    // Buffer too small error test
    var small_buf: [100]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, GsoManager.coalesce(&bufs, &small_buf));
}

test "prepareGsoBatch end-to-end" {
    const p1 = [_]u8{0x11} ** 1200;
    const p2 = [_]u8{0x22} ** 1200;
    const p3 = [_]u8{0x33} ** 400;
    const bufs = [_][]const u8{ &p1, &p2, &p3 };

    var payload: [4000]u8 = undefined;
    var cmsg: [64]u8 = undefined;

    const batch = try GsoManager.prepareGsoBatch(&bufs, &payload, &cmsg);
    try std.testing.expectEqual(@as(usize, 3), batch.count);
    try std.testing.expectEqual(@as(usize, 1200), batch.segment_size);
    try std.testing.expectEqual(@as(usize, 2800), batch.payload_len);
    try std.testing.expect(batch.is_gso);
    try std.testing.expect(batch.cmsg_len > 0);

    // Verify cmsg holds the exact segment size
    const parsed_seg = GsoManager.parseSegmentCmsg(cmsg[0..batch.cmsg_len]);
    try std.testing.expectEqual(@as(?u16, 1200), parsed_seg);
}

test "cmsg UDP_SEGMENT and UDP_GRO build and parse" {
    var cmsg_buf: [128]u8 = undefined;

    // UDP_SEGMENT
    const seg_len = try GsoManager.buildCmsg(&cmsg_buf, 1420);
    try std.testing.expectEqual(@as(?u16, 1420), GsoManager.parseSegmentCmsg(cmsg_buf[0..seg_len]));
    try std.testing.expectEqual(@as(?u16, null), GsoManager.parseGroCmsg(cmsg_buf[0..seg_len]));

    // UDP_GRO
    const gro_len = try GsoManager.buildGroCmsg(&cmsg_buf, 1380);
    try std.testing.expectEqual(@as(?u16, 1380), GsoManager.parseGroCmsg(cmsg_buf[0..gro_len]));
    try std.testing.expectEqual(@as(?u16, null), GsoManager.parseSegmentCmsg(cmsg_buf[0..gro_len]));
}

test "unpackGro standard multi-segment packet" {
    // 3400 byte super-packet = 1400 + 1400 + 600
    var superpacket: [3400]u8 = undefined;
    @memset(superpacket[0..1400], 0x11);
    @memset(superpacket[1400..2800], 0x22);
    @memset(superpacket[2800..3400], 0x33);

    var slices: [16][]const u8 = undefined;
    const count = try GsoManager.unpackGro(&superpacket, 1400, &slices);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqual(@as(usize, 1400), slices[0].len);
    try std.testing.expectEqual(@as(usize, 1400), slices[1].len);
    try std.testing.expectEqual(@as(usize, 600), slices[2].len);

    try std.testing.expectEqual(@as(u8, 0x11), slices[0][0]);
    try std.testing.expectEqual(@as(u8, 0x22), slices[1][0]);
    try std.testing.expectEqual(@as(u8, 0x33), slices[2][0]);

    // Zero-copy verification: pointers point directly into superpacket
    try std.testing.expectEqual(@intFromPtr(&superpacket[0]), @intFromPtr(slices[0].ptr));
    try std.testing.expectEqual(@intFromPtr(&superpacket[1400]), @intFromPtr(slices[1].ptr));
    try std.testing.expectEqual(@intFromPtr(&superpacket[2800]), @intFromPtr(slices[2].ptr));
}

test "unpackGro exact multiple and single packet" {
    // Exact multiple: 2800 bytes with 1400 segment size = 2 segments
    var superpacket: [2800]u8 = undefined;
    @memset(&superpacket, 0x55);

    var slices: [8][]const u8 = undefined;
    const count = try GsoManager.unpackGro(&superpacket, 1400, &slices);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(usize, 1400), slices[0].len);
    try std.testing.expectEqual(@as(usize, 1400), slices[1].len);

    // Single packet (segment_size >= packet len or segment_size == 0)
    var single: [500]u8 = undefined;
    const count_single = try GsoManager.unpackGro(&single, 1400, &slices);
    try std.testing.expectEqual(@as(usize, 1), count_single);
    try std.testing.expectEqual(@as(usize, 500), slices[0].len);

    const count_zero_seg = try GsoManager.unpackGro(&single, 0, &slices);
    try std.testing.expectEqual(@as(usize, 1), count_zero_seg);
    try std.testing.expectEqual(@as(usize, 500), slices[0].len);

    // Empty packet
    const count_empty = try GsoManager.unpackGro(&[_]u8{}, 1400, &slices);
    try std.testing.expectEqual(@as(usize, 0), count_empty);
}

test "unpackGro 64KB max superpacket" {
    // Test unpacking up to MAX_GRO_SIZE (65535 bytes) with MTU 1400
    // 65535 / 1400 = 46 segments of 1400 + 1 segment of 1135 = 47 segments
    var large_super: [GsoManager.MAX_GRO_SIZE]u8 = undefined;
    @memset(&large_super, 0x77);

    var slices: [GsoManager.MAX_SEGMENTS][]const u8 = undefined;
    const count = try GsoManager.unpackGro(&large_super, 1400, &slices);

    try std.testing.expectEqual(@as(usize, 47), count);
    for (slices[0..46]) |s| {
        try std.testing.expectEqual(@as(usize, 1400), s.len);
    }
    try std.testing.expectEqual(@as(usize, 1135), slices[46].len);

    // Total reconstructed bytes must equal 65535
    var total_reconstructed: usize = 0;
    for (slices[0..count]) |s| {
        total_reconstructed += s.len;
    }
    try std.testing.expectEqual(@as(usize, GsoManager.MAX_GRO_SIZE), total_reconstructed);

    // Exceeding 64KB must return SuperpacketTooLarge
    var too_large: [GsoManager.MAX_GRO_SIZE + 1]u8 = undefined;
    try std.testing.expectError(error.SuperpacketTooLarge, GsoManager.unpackGro(&too_large, 1400, &slices));
}

test "GroIterator streaming iteration" {
    var packet: [2500]u8 = undefined;
    @memset(packet[0..1000], 1);
    @memset(packet[1000..2000], 2);
    @memset(packet[2000..2500], 3);

    var iter = GsoManager.GroIterator.init(&packet, 1000);
    try std.testing.expectEqual(@as(usize, 3), iter.count());

    const s1 = iter.next().?;
    try std.testing.expectEqual(@as(usize, 1000), s1.len);
    try std.testing.expectEqual(@as(u8, 1), s1[0]);

    const s2 = iter.next().?;
    try std.testing.expectEqual(@as(usize, 1000), s2.len);
    try std.testing.expectEqual(@as(u8, 2), s2[0]);

    const s3 = iter.next().?;
    try std.testing.expectEqual(@as(usize, 500), s3.len);
    try std.testing.expectEqual(@as(u8, 3), s3[0]);

    try std.testing.expect(iter.next() == null);

    // Test reset
    iter.reset();
    try std.testing.expect(iter.next() != null);
}

test "socket option setsockopt guards" {
    // If not running on Linux, verifying that error.UnsupportedPlatform is cleanly returned
    if (builtin.os.tag != .linux) {
        const dummy_fd: std.posix.socket_t = if (builtin.os.tag == .windows)
            std.os.windows.ws2_32.INVALID_SOCKET
        else
            -1;
        try std.testing.expectError(error.UnsupportedPlatform, GsoManager.setUdpGro(dummy_fd, true));
        try std.testing.expectError(error.UnsupportedPlatform, GsoManager.setUdpSegment(dummy_fd, 1400));
    }
}
