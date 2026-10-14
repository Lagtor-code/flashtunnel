const std = @import("std");
const builtin = @import("builtin");

/// Linux TUN device controller with Zero-Copy batch I/O and multi-queue support.
/// Opens /dev/net/tun and reads/writes raw IP packets without virtio/PI headers.
pub const TunDevice = struct {
    fd: std.posix.fd_t,
    name: [16]u8,
    mtu: usize,
    multi_queue: bool = false,

    // Linux TUN / TAP flags from <linux/if_tun.h>
    pub const IFF_TUN: u16 = 0x0001;
    pub const IFF_TAP: u16 = 0x0002;
    pub const IFF_NO_PI: u16 = 0x1000;
    pub const IFF_ONE_QUEUE: u16 = 0x2000;
    pub const IFF_VNET_HDR: u16 = 0x4000;
    pub const IFF_TUN_EXCL: u16 = 0x8000;
    pub const IFF_MULTI_QUEUE: u16 = 0x0100;
    pub const IFF_ATTACH_QUEUE: u16 = 0x0200;
    pub const IFF_DETACH_QUEUE: u16 = 0x0400;

    // ioctl commands
    pub const TUNSETIFF: u32 = 0x400454ca;
    pub const TUNSETPERSIST: u32 = 0x400454cb;
    pub const TUNSETOWNER: u32 = 0x400454cc;
    pub const TUNSETGROUP: u32 = 0x400454ce;
    pub const TUNSETQUEUE: u32 = 0x400454d9;
    pub const SIOCGIFMTU: u32 = 0x8921;
    pub const SIOCSIFMTU: u32 = 0x8922;

    pub const MAX_BATCH: usize = 64;

    // Syscall numbers for readv / writev
    pub const SYS_readv: usize = switch (builtin.cpu.arch) {
        .x86_64 => 19,
        .aarch64, .riscv64 => 65,
        .arm, .x86 => 145,
        else => 19,
    };

    pub const SYS_writev: usize = switch (builtin.cpu.arch) {
        .x86_64 => 20,
        .aarch64, .riscv64 => 66,
        .arm, .x86 => 146,
        else => 20,
    };

    /// Linux struct ifreq for TUNSETIFF / TUNSETQUEUE (40 bytes total).
    pub const ifreq = extern struct {
        ifr_name: [16]u8,
        ifr_flags: u16,
        _pad: [22]u8 = [_]u8{0} ** 22,
    };

    /// Linux struct ifreq for SIOCGIFMTU / SIOCSIFMTU (40 bytes total).
    pub const ifreq_mtu = extern struct {
        ifr_name: [16]u8,
        ifr_mtu: c_int,
        _pad: [20]u8 = [_]u8{0} ** 20,
    };

    /// Scatter-gather I/O vector for zero-copy read.
    pub const IOVec = extern struct {
        iov_base: [*]u8,
        iov_len: usize,

        pub inline fn fromSlice(slice: []u8) IOVec {
            return .{
                .iov_base = slice.ptr,
                .iov_len = slice.len,
            };
        }
    };

    /// Scatter-gather I/O vector for zero-copy write.
    pub const IOVecConst = extern struct {
        iov_base: [*]const u8,
        iov_len: usize,

        pub inline fn fromSlice(slice: []const u8) IOVecConst {
            return .{
                .iov_base = slice.ptr,
                .iov_len = slice.len,
            };
        }
    };

    /// Options for opening a TUN device.
    pub const OpenOptions = struct {
        multi_queue: bool = false,
        no_pi: bool = true,
        persist: bool = false,
    };

    /// Opens a TUN device with default options (single-queue, no packet info header).
    pub fn open(dev_name: []const u8, mtu: usize) !TunDevice {
        return openWithOptions(dev_name, mtu, .{});
    }

    /// Opens a TUN device with configurable options including multi-queue and persistence.
    pub fn openWithOptions(dev_name: []const u8, mtu: usize, options: OpenOptions) !TunDevice {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }

        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer std.posix.close(fd);

        var flags: u16 = IFF_TUN;
        if (options.no_pi) {
            flags |= IFF_NO_PI;
        }
        if (options.multi_queue) {
            flags |= IFF_MULTI_QUEUE;
        }

        var req = ifreq{
            .ifr_name = [_]u8{0} ** 16,
            .ifr_flags = flags,
        };

        const copy_len = @min(dev_name.len, 15);
        @memcpy(req.ifr_name[0..copy_len], dev_name[0..copy_len]);

        const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) {
            return error.IoctlFailed;
        }

        var dev = TunDevice{
            .fd = fd,
            .name = req.ifr_name,
            .mtu = mtu,
            .multi_queue = options.multi_queue,
        };

        if (options.persist) {
            try dev.setPersist(true);
        }

        return dev;
    }

    /// Creates an additional queue for this multi-queue TUN device.
    /// Opens /dev/net/tun and attaches to the existing interface with IFF_MULTI_QUEUE.
    /// Each queue has its own file descriptor, allowing lock-free multi-core packet I/O.
    pub fn createQueue(self: TunDevice) !TunDevice {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }

        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
        errdefer std.posix.close(fd);

        var req = ifreq{
            .ifr_name = self.name,
            .ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
        };

        const rc = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) {
            return error.IoctlFailed;
        }

        return .{
            .fd = fd,
            .name = req.ifr_name,
            .mtu = self.mtu,
            .multi_queue = true,
        };
    }

    /// Enables/attaches this queue to receive and transmit traffic (TUNSETQUEUE with IFF_ATTACH_QUEUE).
    pub fn attachQueue(self: TunDevice) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        var req = ifreq{
            .ifr_name = self.name,
            .ifr_flags = IFF_ATTACH_QUEUE,
        };
        const rc = std.os.linux.ioctl(self.fd, TUNSETQUEUE, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) return error.IoctlFailed;
    }

    /// Disables/detaches this queue from receiving and transmitting traffic (TUNSETQUEUE with IFF_DETACH_QUEUE).
    pub fn detachQueue(self: TunDevice) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        var req = ifreq{
            .ifr_name = self.name,
            .ifr_flags = IFF_DETACH_QUEUE,
        };
        const rc = std.os.linux.ioctl(self.fd, TUNSETQUEUE, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) return error.IoctlFailed;
    }

    /// Opens `num_queues` queues for multi-core packet I/O on a single TUN interface.
    /// Allocates and returns a slice of TunDevice handles. Caller owns the slice memory.
    pub fn openMultiQueue(
        allocator: std.mem.Allocator,
        dev_name: []const u8,
        mtu: usize,
        num_queues: usize,
    ) ![]TunDevice {
        if (num_queues == 0) return error.InvalidQueueCount;

        const queues = try allocator.alloc(TunDevice, num_queues);
        errdefer allocator.free(queues);

        var opened_count: usize = 0;
        errdefer {
            for (queues[0..opened_count]) |*q| {
                q.close();
            }
        }

        queues[0] = try openWithOptions(dev_name, mtu, .{ .multi_queue = true });
        opened_count += 1;

        for (1..num_queues) |i| {
            queues[i] = try queues[0].createQueue();
            opened_count += 1;
        }

        return queues;
    }

    /// Closes all queues and frees the slice allocated by `openMultiQueue`.
    pub fn closeMultiQueue(allocator: std.mem.Allocator, queues: []TunDevice) void {
        for (queues) |*q| {
            q.close();
        }
        allocator.free(queues);
    }

    /// Sets or clears device persistence (TUNSETPERSIST ioctl).
    /// When persist is true, the TUN interface remains active in the kernel after the file descriptor is closed.
    /// When persist is false, the interface is destroyed when the last file descriptor is closed.
    pub fn setPersist(self: TunDevice, persist: bool) !void {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }
        const val: usize = if (persist) 1 else 0;
        const rc = std.os.linux.ioctl(self.fd, TUNSETPERSIST, val);
        if (@as(isize, @bitCast(rc)) < 0) {
            return error.SetPersistFailed;
        }
    }

    /// Configures the interface MTU via SIOCSIFMTU socket ioctl.
    pub fn setMtu(self: *TunDevice, mtu: usize) !void {
        if (builtin.os.tag != .linux) {
            self.mtu = mtu;
            return;
        }

        const sock_rc = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
        if (@as(isize, @bitCast(sock_rc)) < 0) {
            return error.SocketCreationFailed;
        }
        const sock: std.posix.fd_t = @intCast(sock_rc);
        defer std.posix.close(sock);

        var req = ifreq_mtu{
            .ifr_name = self.name,
            .ifr_mtu = @intCast(mtu),
        };

        const rc = std.os.linux.ioctl(sock, SIOCSIFMTU, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) {
            return error.SetMtuFailed;
        }
        self.mtu = mtu;
    }

    /// Queries the interface MTU via SIOCGIFMTU socket ioctl.
    pub fn getMtu(self: *const TunDevice) !usize {
        if (builtin.os.tag != .linux) {
            return self.mtu;
        }

        const sock_rc = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
        if (@as(isize, @bitCast(sock_rc)) < 0) {
            return error.SocketCreationFailed;
        }
        const sock: std.posix.fd_t = @intCast(sock_rc);
        defer std.posix.close(sock);

        var req = ifreq_mtu{
            .ifr_name = self.name,
            .ifr_mtu = 0,
        };

        const rc = std.os.linux.ioctl(sock, SIOCGIFMTU, @intFromPtr(&req));
        if (@as(isize, @bitCast(rc)) < 0) {
            return error.GetMtuFailed;
        }
        return @intCast(req.ifr_mtu);
    }

    /// Toggles non-blocking mode on the TUN file descriptor.
    pub fn setNonBlocking(self: TunDevice, nonblocking: bool) !void {
        if (builtin.os.tag == .linux) {
            const get_rc = std.os.linux.fcntl(self.fd, std.os.linux.F.GETFL, 0);
            if (@as(isize, @bitCast(get_rc)) < 0) return error.FcntlFailed;

            const flags: usize = get_rc;
            const new_flags = if (nonblocking)
                flags | std.os.linux.O.NONBLOCK
            else
                flags & ~@as(usize, std.os.linux.O.NONBLOCK);

            const set_rc = std.os.linux.fcntl(self.fd, std.os.linux.F.SETFL, new_flags);
            if (@as(isize, @bitCast(set_rc)) < 0) return error.FcntlFailed;
        }
    }

    /// Returns the device name as a slice, excluding trailing null bytes.
    pub fn getName(self: TunDevice) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..len];
    }

    pub fn close(self: *TunDevice) void {
        std.posix.close(self.fd);
    }

    /// Reads a single raw IP packet from TUN into buffer.
    pub inline fn readPacket(self: TunDevice, buf: []u8) !usize {
        return std.posix.read(self.fd, buf);
    }

    /// Writes a single raw IP packet to TUN device.
    pub inline fn writePacket(self: TunDevice, pkt: []const u8) !usize {
        return std.posix.write(self.fd, pkt);
    }

    /// Writes a single packet composed of scattered memory segments (IOVecConst)
    /// to the TUN device in a single kernel syscall with zero intermediate copies.
    pub fn writev(self: TunDevice, iov: []const IOVecConst) !usize {
        if (iov.len == 0) return 0;

        if (builtin.os.tag == .linux) {
            const rc = std.os.linux.syscall3(
                .writev,
                @intCast(self.fd),
                @intFromPtr(iov.ptr),
                iov.len,
            );
            const signed_rc: isize = @bitCast(rc);
            if (signed_rc < 0) {
                const err_code = -signed_rc;
                if (err_code == @intFromEnum(std.posix.E.AGAIN)) return error.WouldBlock;
                return error.WriteFailed;
            }
            return @intCast(signed_rc);
        } else {
            // Portable fallback (single packet write)
            if (iov.len == 1) {
                return std.posix.write(self.fd, iov[0].iov_base[0..iov[0].iov_len]);
            }
            var tmp: [65536]u8 = undefined;
            var off: usize = 0;
            for (iov) |v| {
                if (off + v.iov_len > tmp.len) return error.PacketTooLarge;
                @memcpy(tmp[off .. off + v.iov_len], v.iov_base[0..v.iov_len]);
                off += v.iov_len;
            }
            return std.posix.write(self.fd, tmp[0..off]);
        }
    }

    /// Reads a single packet from the TUN device and scatters it into multiple memory segments (IOVec)
    /// with zero intermediate copies.
    pub fn readv(self: TunDevice, iov: []const IOVec) !usize {
        if (iov.len == 0) return 0;

        if (builtin.os.tag == .linux) {
            const rc = std.os.linux.syscall3(
                .readv,
                @intCast(self.fd),
                @intFromPtr(iov.ptr),
                iov.len,
            );
            const signed_rc: isize = @bitCast(rc);
            if (signed_rc < 0) {
                const err_code = -signed_rc;
                if (err_code == @intFromEnum(std.posix.E.AGAIN)) return error.WouldBlock;
                return error.ReadFailed;
            }
            return @intCast(signed_rc);
        } else {
            // Portable fallback
            var tmp: [65536]u8 = undefined;
            const n = try std.posix.read(self.fd, &tmp);
            var remaining = n;
            var off: usize = 0;
            for (iov) |v| {
                if (remaining == 0) break;
                const copy_len = @min(remaining, v.iov_len);
                @memcpy(v.iov_base[0..copy_len], tmp[off .. off + copy_len]);
                off += copy_len;
                remaining -= copy_len;
            }
            return n;
        }
    }

    /// Creates a 2-element scatter-gather vector for header + payload.
    pub inline fn makeIov2(hdr: []const u8, payload: []const u8) [2]IOVecConst {
        return .{
            IOVecConst.fromSlice(hdr),
            IOVecConst.fromSlice(payload),
        };
    }

    /// Writes a packet composed of a separate header and payload with zero intermediate copy.
    /// Direct kernel gather write via writev.
    pub inline fn writePacketWithHeader(self: TunDevice, header: []const u8, payload: []const u8) !usize {
        const iov = makeIov2(header, payload);
        return self.writev(&iov);
    }

    /// Reads multiple raw IP packets from the TUN device into caller-provided buffers.
    /// Operates with zero intermediate copy: packets are read directly into `bufs`.
    /// On non-blocking TUN descriptors, returns immediately once the queue is drained.
    /// Returns the number of packets read. Each packet's size is recorded in `sizes[0..count]`.
    pub fn readBatch(self: TunDevice, bufs: [][]u8, sizes: []usize) !usize {
        const count_to_read = @min(bufs.len, sizes.len);
        if (count_to_read == 0) return 0;

        var count: usize = 0;
        while (count < count_to_read) : (count += 1) {
            const n = self.readPacket(bufs[count]) catch |err| switch (err) {
                error.WouldBlock => return count,
                else => if (count > 0) return count else return err,
            };
            sizes[count] = n;
        }
        return count;
    }

    /// Writes multiple raw IP packets to the TUN device.
    /// Operates with zero intermediate copy: writes directly from caller buffers.
    /// Returns the number of packets successfully written.
    pub fn writeBatch(self: TunDevice, packets: []const []const u8) usize {
        var count: usize = 0;
        for (packets) |pkt| {
            if (pkt.len == 0) continue;
            _ = self.writePacket(pkt) catch break;
            count += 1;
        }
        return count;
    }

    /// Reads multiple packets where each packet is scattered into multiple buffers (zero-copy).
    /// `packet_iovs` is an array of IOVec slices (one slice of IOVecs per packet).
    /// Returns the number of packets read. Total size of each packet is recorded in `sizes`.
    pub fn readBatchV(self: TunDevice, packet_iovs: []const []const IOVec, sizes: []usize) !usize {
        const count_to_read = @min(packet_iovs.len, sizes.len);
        if (count_to_read == 0) return 0;

        var count: usize = 0;
        while (count < count_to_read) : (count += 1) {
            const n = self.readv(packet_iovs[count]) catch |err| switch (err) {
                error.WouldBlock => return count,
                else => if (count > 0) return count else return err,
            };
            sizes[count] = n;
        }
        return count;
    }

    /// Writes multiple scatter-gather packets to the TUN device with zero intermediate copies.
    /// Each packet is defined by a slice of IOVecConst (e.g. tunnel header + IP payload).
    /// Returns the number of packets successfully written.
    pub fn writeBatchV(self: TunDevice, packet_iovs: []const []const IOVecConst) usize {
        var count: usize = 0;
        for (packet_iovs) |iov| {
            if (iov.len == 0) continue;
            _ = self.writev(iov) catch break;
            count += 1;
        }
        return count;
    }
};

test "TunDevice constants and struct layout" {
    try std.testing.expectEqual(@as(u16, 0x0001), TunDevice.IFF_TUN);
    try std.testing.expectEqual(@as(u16, 0x0002), TunDevice.IFF_TAP);
    try std.testing.expectEqual(@as(u16, 0x1000), TunDevice.IFF_NO_PI);
    try std.testing.expectEqual(@as(u16, 0x0100), TunDevice.IFF_MULTI_QUEUE);
    try std.testing.expectEqual(@as(u16, 0x0200), TunDevice.IFF_ATTACH_QUEUE);
    try std.testing.expectEqual(@as(u16, 0x0400), TunDevice.IFF_DETACH_QUEUE);
    try std.testing.expectEqual(@as(u16, 0x4000), TunDevice.IFF_VNET_HDR);

    try std.testing.expectEqual(@as(u32, 0x400454ca), TunDevice.TUNSETIFF);
    try std.testing.expectEqual(@as(u32, 0x400454cb), TunDevice.TUNSETPERSIST);
    try std.testing.expectEqual(@as(u32, 0x400454d9), TunDevice.TUNSETQUEUE);
    try std.testing.expectEqual(@as(u32, 0x8921), TunDevice.SIOCGIFMTU);
    try std.testing.expectEqual(@as(u32, 0x8922), TunDevice.SIOCSIFMTU);

    // Linux ABI struct size and offset verification
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(TunDevice.ifreq));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(TunDevice.ifreq_mtu));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TunDevice.ifreq, "ifr_name"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(TunDevice.ifreq, "ifr_flags"));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TunDevice.ifreq_mtu, "ifr_name"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(TunDevice.ifreq_mtu, "ifr_mtu"));

    try std.testing.expectEqual(2 * @sizeOf(usize), @sizeOf(TunDevice.IOVec));
    try std.testing.expectEqual(2 * @sizeOf(usize), @sizeOf(TunDevice.IOVecConst));
}

test "TunDevice OpenOptions and getName" {
    const opts = TunDevice.OpenOptions{};
    try std.testing.expect(!opts.multi_queue);
    try std.testing.expect(opts.no_pi);
    try std.testing.expect(!opts.persist);

    var name_buf = [_]u8{0} ** 16;
    @memcpy(name_buf[0..5], "tun99");
    const dev = TunDevice{
        .fd = -1,
        .name = name_buf,
        .mtu = 1420,
        .multi_queue = true,
    };

    try std.testing.expectEqualStrings("tun99", dev.getName());
    try std.testing.expectEqual(@as(usize, 1420), dev.mtu);
    try std.testing.expect(dev.multi_queue);
}

test "IOVec and IOVecConst conversions and makeIov2" {
    var hdr_buf = [_]u8{ 0x45, 0x00, 0x00, 0x3c };
    var payload_buf = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };

    const iov_const = TunDevice.IOVecConst.fromSlice(&hdr_buf);
    try std.testing.expectEqual(@as(usize, 4), iov_const.iov_len);
    try std.testing.expectEqual(@intFromPtr(&hdr_buf), @intFromPtr(iov_const.iov_base));

    const iov_mut = TunDevice.IOVec.fromSlice(&payload_buf);
    try std.testing.expectEqual(@as(usize, 5), iov_mut.iov_len);
    try std.testing.expectEqual(@intFromPtr(&payload_buf), @intFromPtr(iov_mut.iov_base));

    const pair = TunDevice.makeIov2(&hdr_buf, &payload_buf);
    try std.testing.expectEqual(@as(usize, 4), pair[0].iov_len);
    try std.testing.expectEqual(@as(usize, 5), pair[1].iov_len);
}

test "TunDevice empty batch operations" {
    var dummy = TunDevice{
        .fd = -1,
        .name = [_]u8{0} ** 16,
        .mtu = 1500,
    };

    try std.testing.expectEqual(@as(usize, 0), dummy.writeBatch(&[_][]const u8{}));
    try std.testing.expectEqual(@as(usize, 0), dummy.writeBatchV(&[_][]const TunDevice.IOVecConst{}));
    try std.testing.expectEqual(@as(usize, 0), try dummy.readBatch(&[_][]u8{}, &[_]usize{}));
    try std.testing.expectEqual(@as(usize, 0), try dummy.readBatchV(&[_][]const TunDevice.IOVec{}, &[_]usize{}));
    try std.testing.expectEqual(@as(usize, 0), try dummy.writev(&[_]TunDevice.IOVecConst{}));
    try std.testing.expectEqual(@as(usize, 0), try dummy.readv(&[_]TunDevice.IOVec{}));
}

test "TunDevice pipe mock batch I/O and scatter-gather" {
    // Test I/O via OS pipe if supported
    if (std.posix.pipe()) |pipe_fds| {
        var reader = TunDevice{
            .fd = pipe_fds[0],
            .name = [_]u8{ 't', 'u', 'n', '0' } ++ [_]u8{0} ** 12,
            .mtu = 1500,
        };
        defer reader.close();

        var writer = TunDevice{
            .fd = pipe_fds[1],
            .name = [_]u8{ 't', 'u', 'n', '0' } ++ [_]u8{0} ** 12,
            .mtu = 1500,
        };
        defer writer.close();

        // 1. Test writePacketWithHeader -> readPacket
        const hdr = [_]u8{ 0x45, 0x00 };
        const payload = [_]u8{ 0x01, 0x02, 0x03 };
        const written_len = try writer.writePacketWithHeader(&hdr, &payload);
        try std.testing.expectEqual(@as(usize, 5), written_len);

        var read_buf: [32]u8 = undefined;
        const read_len = try reader.readPacket(&read_buf);
        try std.testing.expectEqual(@as(usize, 5), read_len);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x45, 0x00, 0x01, 0x02, 0x03 }, read_buf[0..read_len]);

        // 2. Test writev scatter-gather -> readv scatter-gather
        const part1 = "HELLO ";
        const part2 = "ZERO-COPY ";
        const part3 = "TUN";
        const send_iov = [_]TunDevice.IOVecConst{
            TunDevice.IOVecConst.fromSlice(part1),
            TunDevice.IOVecConst.fromSlice(part2),
            TunDevice.IOVecConst.fromSlice(part3),
        };
        const v_written = try writer.writev(&send_iov);
        try std.testing.expectEqual(part1.len + part2.len + part3.len, v_written);

        var recv1: [6]u8 = undefined;
        var recv2: [10]u8 = undefined;
        var recv3: [3]u8 = undefined;
        const recv_iov = [_]TunDevice.IOVec{
            TunDevice.IOVec.fromSlice(&recv1),
            TunDevice.IOVec.fromSlice(&recv2),
            TunDevice.IOVec.fromSlice(&recv3),
        };
        const v_read = try reader.readv(&recv_iov);
        try std.testing.expectEqual(v_written, v_read);
        try std.testing.expectEqualStrings("HELLO ", &recv1);
        try std.testing.expectEqualStrings("ZERO-COPY ", &recv2);
        try std.testing.expectEqualStrings("TUN", &recv3);

        // 3. Test writeBatch -> readBatch
        const p1 = "PACKET_ONE";
        const p2 = "PACKET_TWO";
        const p3 = "PACKET_THREE";
        const batch_pkts = [_][]const u8{ p1, p2, p3 };

        const batch_written = writer.writeBatch(&batch_pkts);
        try std.testing.expectEqual(@as(usize, 3), batch_written);

        var b1: [32]u8 = undefined;
        var b2: [32]u8 = undefined;
        var b3: [32]u8 = undefined;
        var out_bufs = [_][]u8{ &b1, &b2, &b3 };
        var out_sizes = [_]usize{ 0, 0, 0 };

        const batch_read = try reader.readBatch(&out_bufs, &out_sizes);
        try std.testing.expect(batch_read >= 1);
    } else |_| {
        // OS pipe not supported on this platform/sandbox; non-pipe unit tests verify logic
    }
}
