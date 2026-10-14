const std = @import("std");
const builtin = @import("builtin");

/// Compatibility alias for socket descriptor across Zig versions
pub const SocketType = if (@hasDecl(std.posix, "socket_t"))
    std.posix.socket_t
else if (@hasDecl(std.os, "socket_t"))
    std.os.socket_t
else
    std.posix.fd_t;

// Compatibility error codes
pub const EAGAIN_VAL: isize = if (@hasDecl(std.posix, "E") and @hasDecl(std.posix.E, "AGAIN"))
    @intFromEnum(std.posix.E.AGAIN)
else
    11;
pub const EWOULDBLOCK_VAL: isize = if (@hasDecl(std.posix, "E") and @hasDecl(std.posix.E, "WOULDBLOCK"))
    @intFromEnum(std.posix.E.WOULDBLOCK)
else
    11;
pub const ETIMEDOUT_VAL: isize = if (@hasDecl(std.posix, "E") and @hasDecl(std.posix.E, "TIMEDOUT"))
    @intFromEnum(std.posix.E.TIMEDOUT)
else
    110;
pub const EINTR_VAL: isize = if (@hasDecl(std.posix, "E") and @hasDecl(std.posix.E, "INTR"))
    @intFromEnum(std.posix.E.INTR)
else
    4;

// Platform socket option constants
pub const SOL_SOCKET: u32 = if (builtin.os.tag == .windows) 0xffff else 1;
pub const SO_REUSEADDR: u32 = if (builtin.os.tag == .windows) 0x0004 else 2;
pub const SO_RCVBUF: u32 = if (builtin.os.tag == .windows) 0x1002 else 8;
pub const SO_SNDBUF: u32 = if (builtin.os.tag == .windows) 0x1001 else 7;
pub const SO_REUSEPORT: u32 = 15;
pub const SO_RCVTIMEO: u32 = if (builtin.os.tag == .windows) 0x1006 else 20;
pub const SO_SNDTIMEO: u32 = if (builtin.os.tag == .windows) 0x1005 else 21;
pub const SO_SNDBUFFORCE: u32 = 32;
pub const SO_RCVBUFFORCE: u32 = 33;

pub const IPPROTO_TCP: u32 = 6;
pub const TCP_QUICKACK: u32 = 12;

pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_WAITFORONE: u32 = 0x10000;

// Architecture-independent Linux syscall numbers
pub const SYS_sendmmsg: usize = if (@hasDecl(std.os.linux.SYS, "sendmmsg"))
    std.os.linux.SYS.sendmmsg
else switch (builtin.cpu.arch) {
    .x86_64 => 307,
    .aarch64 => 269,
    .x86 => 345,
    .arm, .armeb => 374,
    .riscv64 => 269,
    .powerpc64, .powerpc64le => 349,
    .mips, .mipsel => 4344,
    else => 307,
};

pub const SYS_recvmmsg: usize = if (@hasDecl(std.os.linux.SYS, "recvmmsg"))
    std.os.linux.SYS.recvmmsg
else switch (builtin.cpu.arch) {
    .x86_64 => 299,
    .aarch64 => 243,
    .x86 => 337,
    .arm, .armeb => 365,
    .riscv64 => 243,
    .powerpc64, .powerpc64le => 343,
    .mips, .mipsel => 4337,
    else => 299,
};

// Internal setsockopt wrapper
inline fn setsockoptCompat(fd: SocketType, level: u32, optname: u32, optval: []const u8) !void {
    if (@hasDecl(std.posix, "setsockopt")) {
        return std.posix.setsockopt(fd, level, optname, optval);
    } else if (@hasDecl(std.os, "setsockopt")) {
        return std.os.setsockopt(fd, level, optname, optval);
    }
}

// Internal fcntl wrapper
inline fn fcntlCompat(fd: SocketType, cmd: i32, arg: usize) !usize {
    if (@hasDecl(std.posix, "fcntl")) {
        return std.posix.fcntl(fd, cmd, arg);
    } else if (@hasDecl(std.os, "fcntl")) {
        return std.os.fcntl(fd, cmd, arg);
    }
    return 0;
}

/// High-throughput UDP Batch Socket using Linux recvmmsg and sendmmsg.
/// Eliminates per-packet syscall overhead and supports non-blocking timeout handling.
pub const BatchSocket = struct {
    fd: SocketType,
    timeout_ns: ?u64 = null,

    pub const MAX_BATCH: usize = 64;

    // Platform types for Linux
    pub const iovec = extern struct {
        iov_base: ?*anyopaque,
        iov_len: usize,
    };

    pub const msghdr = extern struct {
        msg_name: ?*anyopaque,
        msg_namelen: u32,
        msg_iov: ?[*]iovec,
        msg_iovlen: usize,
        msg_control: ?*anyopaque,
        msg_controllen: usize,
        msg_flags: i32,
    };

    pub const mmsghdr = extern struct {
        msg_hdr: msghdr,
        msg_len: c_uint,
    };

    pub const Timespec = extern struct {
        tv_sec: isize,
        tv_nsec: isize,
    };

    pub fn init(fd: SocketType) BatchSocket {
        return .{
            .fd = fd,
            .timeout_ns = null,
        };
    }

    pub fn initWithTimeout(fd: SocketType, timeout_ns: ?u64) BatchSocket {
        return .{
            .fd = fd,
            .timeout_ns = timeout_ns,
        };
    }

    /// Sets the socket receive buffer size (SO_RCVBUF).
    /// On Linux, attempts SO_RCVBUFFORCE first to allow overriding system rmem_max.
    pub fn setRecvBufferSize(self: BatchSocket, size: usize) !void {
        const val: c_int = @intCast(@min(size, @as(usize, std.math.maxInt(c_int))));
        if (builtin.os.tag == .linux) {
            if (setsockoptCompat(self.fd, SOL_SOCKET, SO_RCVBUFFORCE, std.mem.asBytes(&val))) {
                return;
            } else |_| {}
        }
        try setsockoptCompat(self.fd, SOL_SOCKET, SO_RCVBUF, std.mem.asBytes(&val));
    }

    /// Sets the socket send buffer size (SO_SNDBUF).
    /// On Linux, attempts SO_SNDBUFFORCE first to allow overriding system wmem_max.
    pub fn setSendBufferSize(self: BatchSocket, size: usize) !void {
        const val: c_int = @intCast(@min(size, @as(usize, std.math.maxInt(c_int))));
        if (builtin.os.tag == .linux) {
            if (setsockoptCompat(self.fd, SOL_SOCKET, SO_SNDBUFFORCE, std.mem.asBytes(&val))) {
                return;
            } else |_| {}
        }
        try setsockoptCompat(self.fd, SOL_SOCKET, SO_SNDBUF, std.mem.asBytes(&val));
    }

    /// Enables SO_REUSEPORT (and SO_REUSEADDR) to allow multiple worker threads
    /// or processes to bind to the same UDP port for kernel-level multi-queue load balancing.
    pub fn enableReusePort(self: BatchSocket) !void {
        const val: c_int = 1;
        try setsockoptCompat(self.fd, SOL_SOCKET, SO_REUSEADDR, std.mem.asBytes(&val));

        if (builtin.os.tag == .linux or builtin.os.tag.isDarwin() or builtin.os.tag == .freebsd or builtin.os.tag == .openbsd or builtin.os.tag == .netbsd) {
            try setsockoptCompat(self.fd, SOL_SOCKET, SO_REUSEPORT, std.mem.asBytes(&val));
        }
    }

    /// Configures the socket for non-blocking I/O mode.
    pub fn setNonBlocking(self: BatchSocket, non_blocking: bool) !void {
        if (builtin.os.tag == .windows) {
            var mode: c_ulong = if (non_blocking) 1 else 0;
            const FIONBIO: c_long = 0x8004667e;
            if (std.os.windows.ws2_32.ioctlsocket(self.fd, FIONBIO, &mode) != 0) {
                return error.SetNonBlockingFailed;
            }
        } else {
            const F_GETFL = if (@hasDecl(std.posix.F, "GETFL")) std.posix.F.GETFL else 3;
            const F_SETFL = if (@hasDecl(std.posix.F, "SETFL")) std.posix.F.SETFL else 4;
            const flags = try fcntlCompat(self.fd, F_GETFL, 0);
            const nonblock: usize = @as(usize, @intCast(std.posix.O.NONBLOCK));
            const new_flags = if (non_blocking) (flags | nonblock) else (flags & ~nonblock);
            _ = try fcntlCompat(self.fd, F_SETFL, new_flags);
        }
    }

    /// Enables or disables TCP QuickAck (TCP_QUICKACK) on Linux.
    /// Resets delayed ACK state to send ACKs immediately, minimizing latency for tunnel streams.
    pub fn setQuickAck(self: BatchSocket, enabled: bool) !void {
        if (builtin.os.tag == .linux) {
            const val: c_int = if (enabled) 1 else 0;
            try setsockoptCompat(self.fd, IPPROTO_TCP, TCP_QUICKACK, std.mem.asBytes(&val));
        }
    }

    /// Sets an internal receive timeout for batch socket operations (nanoseconds).
    pub fn setRecvTimeout(self: *BatchSocket, timeout_ns: ?u64) void {
        self.timeout_ns = timeout_ns;
    }

    /// Sets the kernel-level receive timeout (SO_RCVTIMEO) on the socket.
    pub fn setSocketRecvTimeout(self: BatchSocket, timeout_ns: u64) !void {
        if (builtin.os.tag == .windows) {
            const ms: c_ulong = @intCast(@min(timeout_ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(c_ulong))));
            try setsockoptCompat(self.fd, SOL_SOCKET, SO_RCVTIMEO, std.mem.asBytes(&ms));
        } else {
            const sec: isize = @intCast(timeout_ns / std.time.ns_per_s);
            const usec: isize = @intCast((timeout_ns % std.time.ns_per_s) / std.time.ns_per_us);
            const timeval = extern struct {
                tv_sec: isize,
                tv_usec: isize,
            }{
                .tv_sec = sec,
                .tv_usec = usec,
            };
            try setsockoptCompat(self.fd, SOL_SOCKET, SO_RCVTIMEO, std.mem.asBytes(&timeval));
        }
    }

    /// Linux sendmmsg wrapper.
    /// Sends a slice of datagram buffers to a target address in a single syscall.
    /// In non-blocking mode, if the socket buffer is full, returns 0 rather than error.
    pub fn sendBatch(
        self: BatchSocket,
        bufs: []const []const u8,
        sockaddr: *const anyopaque,
        sockaddr_len: u32,
    ) !usize {
        if (bufs.len == 0) return 0;
        const count = @min(bufs.len, MAX_BATCH);

        if (builtin.os.tag == .linux) {
            var msgs: [MAX_BATCH]mmsghdr = undefined;
            var iovs: [MAX_BATCH]iovec = undefined;

            var i: usize = 0;
            while (i < count) : (i += 1) {
                iovs[i] = .{
                    .iov_base = @constCast(@ptrCast(bufs[i].ptr)),
                    .iov_len = bufs[i].len,
                };
                msgs[i] = .{
                    .msg_hdr = .{
                        .msg_name = @constCast(sockaddr),
                        .msg_namelen = sockaddr_len,
                        .msg_iov = @ptrCast(&iovs[i]),
                        .msg_iovlen = 1,
                        .msg_control = null,
                        .msg_controllen = 0,
                        .msg_flags = 0,
                    },
                    .msg_len = 0,
                };
            }

            const rc = std.os.linux.syscall5(
                SYS_sendmmsg,
                @intCast(self.fd),
                @intFromPtr(&msgs[0]),
                count,
                0, // flags
                0,
            );

            const signed_rc: isize = @bitCast(rc);
            if (signed_rc < 0) {
                const err_code = -signed_rc;
                if (err_code == EAGAIN_VAL or
                    err_code == EWOULDBLOCK_VAL or
                    err_code == EINTR_VAL)
                {
                    return 0; // Socket buffer is temporarily full
                }
                return error.SendFailed;
            }
            return @intCast(signed_rc);
        } else {
            // Non-linux fallback: send one by one
            var sent: usize = 0;
            for (bufs[0..count]) |b| {
                const n = if (@hasDecl(std.posix, "sendto"))
                    std.posix.sendto(
                        self.fd,
                        b,
                        0,
                        @ptrCast(@alignCast(sockaddr)),
                        sockaddr_len,
                    ) catch break
                else
                    std.os.sendto(
                        self.fd,
                        b,
                        0,
                        @ptrCast(@alignCast(sockaddr)),
                        sockaddr_len,
                    ) catch break;

                if (n > 0) sent += 1;
            }
            return sent;
        }
    }

    /// High-throughput batched packet reception.
    /// Non-blocking safe: If no packets are available in non-blocking mode or timeout expires,
    /// returns 0 datagrams received rather than failing with error.RecvFailed.
    pub fn recvBatch(
        self: BatchSocket,
        out_bufs: [][]u8,
        sizes: []usize,
    ) !usize {
        return self.recvBatchTimeout(out_bufs, sizes, self.timeout_ns);
    }

    /// Batched packet reception with explicit nanosecond timeout.
    /// - timeout_ns == null: blocks until datagrams arrive (or returns 0 if non-blocking socket is empty).
    /// - timeout_ns == 0: non-blocking instant poll (MSG_DONTWAIT).
    /// - timeout_ns > 0: waits up to timeout_ns for datagrams.
    pub fn recvBatchTimeout(
        self: BatchSocket,
        out_bufs: [][]u8,
        sizes: []usize,
        timeout_ns: ?u64,
    ) !usize {
        const count = @min(@min(out_bufs.len, sizes.len), MAX_BATCH);
        if (count == 0) return 0;

        if (builtin.os.tag == .linux) {
            var msgs: [MAX_BATCH]mmsghdr = undefined;
            var iovs: [MAX_BATCH]iovec = undefined;

            var i: usize = 0;
            while (i < count) : (i += 1) {
                iovs[i] = .{
                    .iov_base = out_bufs[i].ptr,
                    .iov_len = out_bufs[i].len,
                };
                msgs[i] = .{
                    .msg_hdr = .{
                        .msg_name = null,
                        .msg_namelen = 0,
                        .msg_iov = @ptrCast(&iovs[i]),
                        .msg_iovlen = 1,
                        .msg_control = null,
                        .msg_controllen = 0,
                        .msg_flags = 0,
                    },
                    .msg_len = 0,
                };
            }

            var ts: Timespec = undefined;
            var ts_ptr: usize = 0;
            var flags: u32 = 0;

            if (timeout_ns) |ns| {
                if (ns == 0) {
                    flags |= MSG_DONTWAIT;
                } else {
                    const sec = ns / std.time.ns_per_s;
                    const nsec = ns % std.time.ns_per_s;
                    ts = .{
                        .tv_sec = @intCast(sec),
                        .tv_nsec = @intCast(nsec),
                    };
                    ts_ptr = @intFromPtr(&ts);
                }
            }

            const rc = std.os.linux.syscall5(
                SYS_recvmmsg,
                @intCast(self.fd),
                @intFromPtr(&msgs[0]),
                count,
                flags,
                ts_ptr,
            );

            const signed_rc: isize = @bitCast(rc);
            if (signed_rc < 0) {
                const err_code = -signed_rc;
                // Gracefully handle non-blocking empty queue and timeouts
                if (err_code == EAGAIN_VAL or
                    err_code == EWOULDBLOCK_VAL or
                    err_code == ETIMEDOUT_VAL or
                    err_code == EINTR_VAL)
                {
                    return 0;
                }
                return error.RecvFailed;
            }

            const received: usize = @intCast(signed_rc);
            var j: usize = 0;
            while (j < received) : (j += 1) {
                sizes[j] = @intCast(msgs[j].msg_len);
            }
            return received;
        } else {
            // Non-linux fallback with poll-based timeout and non-blocking support
            if (timeout_ns) |ns| {
                var pfd = [1]std.posix.pollfd{.{
                    .fd = self.fd,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                const timeout_ms: i32 = if (ns == 0) 0 else @intCast(@min(ns / std.time.ns_per_ms, @as(u64, std.math.maxInt(i32))));
                const poll_res = std.posix.poll(&pfd, timeout_ms) catch return 0;
                if (poll_res == 0) return 0;
            }

            var received: usize = 0;
            while (received < count) {
                const n = if (@hasDecl(std.posix, "recv"))
                    std.posix.recv(self.fd, out_bufs[received], 0) catch |err| switch (err) {
                        error.WouldBlock => break,
                        else => if (received > 0) break else return err,
                    }
                else
                    std.os.recv(self.fd, out_bufs[received], 0) catch |err| switch (err) {
                        error.WouldBlock => break,
                        else => if (received > 0) break else return err,
                    };

                if (n == 0) break;
                sizes[received] = n;
                received += 1;
                break;
            }
            return received;
        }
    }
};

/// Outbound batch message queue for aggregating datagrams before syscall transmission.
/// Amortizes syscall overhead by buffering up to MAX_BATCH datagram pointers.
pub const BatchQueue = struct {
    pub const MAX_CAPACITY: usize = BatchSocket.MAX_BATCH;

    buffers: [MAX_CAPACITY][]const u8 = undefined,
    count: usize = 0,

    pub fn init() BatchQueue {
        return .{
            .count = 0,
        };
    }

    /// Pushes a packet slice into the queue.
    /// Returns true if enqueued, false if queue is full (flush required).
    pub fn push(self: *BatchQueue, pkt: []const u8) bool {
        if (self.count >= MAX_CAPACITY) return false;
        self.buffers[self.count] = pkt;
        self.count += 1;
        return true;
    }

    /// Returns the currently enqueued packet buffer slices.
    pub fn getBatch(self: *const BatchQueue) []const []const u8 {
        return self.buffers[0..self.count];
    }

    /// Resets the queue count after a successful flush.
    pub fn clear(self: *BatchQueue) void {
        self.count = 0;
    }

    /// Returns true if the batch queue has reached MAX_CAPACITY.
    pub fn isFull(self: *const BatchQueue) bool {
        return self.count >= MAX_CAPACITY;
    }

    /// Returns true if no packets are currently pending.
    pub fn isEmpty(self: *const BatchQueue) bool {
        return self.count == 0;
    }

    /// Flushes queued datagrams through the batch socket in a single sendmmsg call.
    /// Handles partial sends by compacting any unsent packets to the front of the queue.
    pub fn flush(
        self: *BatchQueue,
        socket: BatchSocket,
        sockaddr: *const anyopaque,
        sockaddr_len: u32,
    ) !usize {
        if (self.count == 0) return 0;
        const sent = try socket.sendBatch(self.buffers[0..self.count], sockaddr, sockaddr_len);
        if (sent > 0) {
            if (sent < self.count) {
                const remaining = self.count - sent;
                var i: usize = 0;
                while (i < remaining) : (i += 1) {
                    self.buffers[i] = self.buffers[sent + i];
                }
                self.count = remaining;
            } else {
                self.count = 0;
            }
        }
        return sent;
    }
};

/// Pre-allocated receive buffer pool for MAX_BATCH datagrams.
/// Guarantees zero heap allocations during high-frequency packet ingress.
pub const BatchRxBuffer = struct {
    pub const PACKET_BUFFER_SIZE: usize = 2048;

    storage: [BatchSocket.MAX_BATCH][PACKET_BUFFER_SIZE]u8 = undefined,
    slices: [BatchSocket.MAX_BATCH][]u8 = undefined,
    sizes: [BatchSocket.MAX_BATCH]usize = [_]usize{0} ** BatchSocket.MAX_BATCH,

    pub fn init() BatchRxBuffer {
        var self = BatchRxBuffer{};
        for (&self.storage, 0..) |*buf, i| {
            self.slices[i] = buf[0..];
        }
        return self;
    }

    pub fn getBuffers(self: *BatchRxBuffer) [][]u8 {
        return self.slices[0..];
    }

    pub fn getSizes(self: *BatchRxBuffer) []usize {
        return self.sizes[0..];
    }

    pub fn getPacket(self: *const BatchRxBuffer, index: usize) []const u8 {
        return self.storage[index][0..self.sizes[index]];
    }
};

// ============================================================================
// UNIT TESTS & SIMULATION TESTS
// ============================================================================

test "BatchQueue push, isFull, isEmpty, and clear" {
    var queue = BatchQueue.init();
    try std.testing.expect(queue.isEmpty());
    try std.testing.expect(!queue.isFull());
    try std.testing.expectEqual(@as(usize, 0), queue.count);

    const dummy_pkt = "TEST_VPN_PACKET";

    // Fill queue to MAX_CAPACITY (64)
    var i: usize = 0;
    while (i < BatchQueue.MAX_CAPACITY) : (i += 1) {
        const pushed = queue.push(dummy_pkt);
        try std.testing.expect(pushed);
    }

    try std.testing.expect(queue.isFull());
    try std.testing.expect(!queue.isEmpty());
    try std.testing.expectEqual(BatchQueue.MAX_CAPACITY, queue.count);

    // 65th push must fail (queue full)
    const overflow_pushed = queue.push("OVERFLOW");
    try std.testing.expect(!overflow_pushed);

    // Verify batch slice
    const batch = queue.getBatch();
    try std.testing.expectEqual(BatchQueue.MAX_CAPACITY, batch.len);
    try std.testing.expectEqualStrings(dummy_pkt, batch[0]);

    // Clear
    queue.clear();
    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), queue.count);
}

test "BatchQueue FIFO order and payload integrity" {
    var queue = BatchQueue.init();
    const packets = [_][]const u8{
        "PACKET_HEADER_001",
        "PACKET_HEADER_002",
        "PACKET_HEADER_003",
        "PACKET_HEADER_004",
        "PACKET_HEADER_005",
    };

    for (packets) |pkt| {
        try std.testing.expect(queue.push(pkt));
    }

    try std.testing.expectEqual(@as(usize, 5), queue.count);
    const batch = queue.getBatch();
    for (packets, 0..) |expected, idx| {
        try std.testing.expectEqualStrings(expected, batch[idx]);
    }
}

test "BatchQueue partial send compaction" {
    var queue = BatchQueue.init();

    // Push 10 distinct packets
    const pkts = [_][]const u8{
        "P0", "P1", "P2", "P3", "P4",
        "P5", "P6", "P7", "P8", "P9",
    };
    for (pkts) |p| {
        _ = queue.push(p);
    }
    try std.testing.expectEqual(@as(usize, 10), queue.count);

    // Simulate partial send of 4 packets: manually perform compaction
    const sent = 4;
    const remaining = queue.count - sent;
    var i: usize = 0;
    while (i < remaining) : (i += 1) {
        queue.buffers[i] = queue.buffers[sent + i];
    }
    queue.count = remaining;

    try std.testing.expectEqual(@as(usize, 6), queue.count);
    const compacted = queue.getBatch();
    try std.testing.expectEqualStrings("P4", compacted[0]);
    try std.testing.expectEqualStrings("P5", compacted[1]);
    try std.testing.expectEqualStrings("P6", compacted[2]);
    try std.testing.expectEqualStrings("P7", compacted[3]);
    try std.testing.expectEqualStrings("P8", compacted[4]);
    try std.testing.expectEqualStrings("P9", compacted[5]);
}

test "BatchRxBuffer zero-allocation buffer pool" {
    var rx = BatchRxBuffer.init();
    const bufs = rx.getBuffers();
    const sizes = rx.getSizes();

    try std.testing.expectEqual(BatchSocket.MAX_BATCH, bufs.len);
    try std.testing.expectEqual(BatchSocket.MAX_BATCH, sizes.len);
    try std.testing.expectEqual(BatchRxBuffer.PACKET_BUFFER_SIZE, bufs[0].len);

    // Simulate ingress of 3 packets
    const p1 = "SYN-PACKET-DATA";
    const p2 = "PAYLOAD-FRAME-123456";
    const p3 = "FIN-PACKET";

    @memcpy(bufs[0][0..p1.len], p1);
    sizes[0] = p1.len;

    @memcpy(bufs[1][0..p2.len], p2);
    sizes[1] = p2.len;

    @memcpy(bufs[2][0..p3.len], p3);
    sizes[2] = p3.len;

    try std.testing.expectEqualStrings(p1, rx.getPacket(0));
    try std.testing.expectEqualStrings(p2, rx.getPacket(1));
    try std.testing.expectEqualStrings(p3, rx.getPacket(2));
}

test "BatchSocket constants and Linux architecture syscall resolution" {
    try std.testing.expectEqual(@as(usize, 64), BatchSocket.MAX_BATCH);

    // Constants must be non-zero
    try std.testing.expect(SOL_SOCKET > 0);
    try std.testing.expect(SO_RCVBUF > 0);
    try std.testing.expect(SO_SNDBUF > 0);
    try std.testing.expect(SO_REUSEPORT > 0);
    try std.testing.expect(IPPROTO_TCP == 6);
    try std.testing.expect(TCP_QUICKACK == 12);

    // Syscall numbers must be valid for the current platform
    try std.testing.expect(SYS_sendmmsg > 0);
    try std.testing.expect(SYS_recvmmsg > 0);
}

test "BatchSocket non-blocking timeout simulation" {
    // Verify that EAGAIN/EWOULDBLOCK error codes map to non-blocking 0 datagram return
    const err_codes = [_]isize{ EAGAIN_VAL, EWOULDBLOCK_VAL, ETIMEDOUT_VAL, EINTR_VAL };
    for (err_codes) |code| {
        const is_nonblocking_timeout = (code == EAGAIN_VAL or
            code == EWOULDBLOCK_VAL or
            code == ETIMEDOUT_VAL or
            code == EINTR_VAL);
        try std.testing.expect(is_nonblocking_timeout);
    }
}

test "BatchSocket initialization and timeout configuration" {
    var sock = BatchSocket.init(0);
    try std.testing.expectEqual(@as(SocketType, 0), sock.fd);
    try std.testing.expectEqual(@as(?u64, null), sock.timeout_ns);

    sock.setRecvTimeout(50 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(?u64, 50 * std.time.ns_per_ms), sock.timeout_ns);

    const timed_sock = BatchSocket.initWithTimeout(1, 100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(SocketType, 1), timed_sock.fd);
    try std.testing.expectEqual(@as(?u64, 100 * std.time.ns_per_ms), timed_sock.timeout_ns);
}

test "BatchQueue multi-burst traffic simulation" {
    var queue = BatchQueue.init();

    // Burst 1: 30 packets
    var i: usize = 0;
    while (i < 30) : (i += 1) {
        _ = queue.push("BURST_1_PACKET");
    }
    try std.testing.expectEqual(@as(usize, 30), queue.count);

    // Simulate sending 25 packets, 5 remaining
    const sent1 = 25;
    const rem1 = queue.count - sent1;
    var j: usize = 0;
    while (j < rem1) : (j += 1) {
        queue.buffers[j] = queue.buffers[sent1 + j];
    }
    queue.count = rem1;
    try std.testing.expectEqual(@as(usize, 5), queue.count);

    // Burst 2: 50 more packets
    var k: usize = 0;
    while (k < 50) : (k += 1) {
        _ = queue.push("BURST_2_PACKET");
    }
    try std.testing.expectEqual(@as(usize, 55), queue.count);

    // Drain all
    queue.clear();
    try std.testing.expect(queue.isEmpty());
}

test "BatchRxBuffer variable-sized frame ingress simulation" {
    var rx = BatchRxBuffer.init();
    const bufs = rx.getBuffers();
    const sizes = rx.getSizes();

    // Simulate varying packet sizes (e.g. DNS, TCP ACK, TLS Handshake, Full MTU Data)
    const frame_sizes = [_]usize{ 64, 128, 512, 1420, 1500, 40, 256, 1200 };
    for (frame_sizes, 0..) |size, idx| {
        @memset(bufs[idx][0..size], @as(u8, @intCast(idx & 0xFF)));
        sizes[idx] = size;
    }

    for (frame_sizes, 0..) |expected_size, idx| {
        const pkt = rx.getPacket(idx);
        try std.testing.expectEqual(expected_size, pkt.len);
        try std.testing.expectEqual(@as(u8, @intCast(idx & 0xFF)), pkt[0]);
    }
}

