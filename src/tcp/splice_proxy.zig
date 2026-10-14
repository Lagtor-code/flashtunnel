const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

pub const fd_t = std.posix.fd_t;

/// Statistics collected during bidirectional zero-copy forwarding.
pub const ForwardStats = struct {
    bytes_a_to_b: u64 = 0,
    bytes_b_to_a: u64 = 0,
    iterations: u64 = 0,
    eagain_events: u64 = 0,
    a_eof: bool = false,
    b_eof: bool = false,
};

/// Adaptive backoff helper for non-blocking I/O polling.
/// Provides microsecond-level latency under active traffic while
/// backing off to thread sleep (capped at max_sleep_ns) when idle.
pub const Backoff = struct {
    consecutive_idle: u32 = 0,
    min_sleep_ns: u64 = 50_000, // 50 us
    max_sleep_ns: u64 = 1_000_000, // 1 ms
    current_sleep_ns: u64 = 50_000,

    pub fn reset(self: *Backoff) void {
        self.consecutive_idle = 0;
        self.current_sleep_ns = self.min_sleep_ns;
    }

    pub fn wait(self: *Backoff) void {
        self.consecutive_idle += 1;
        if (self.consecutive_idle <= 3) {
            // Light idle: yield timeslice without kernel sleep overhead
            std.Thread.yield() catch {};
        } else {
            // Prolonged idle: progressive exponential sleep
            std.time.sleep(self.current_sleep_ns);
            self.current_sleep_ns = @min(self.current_sleep_ns * 2, self.max_sleep_ns);
        }
    }
};

/// Directional stream state tracking in-kernel pipe buffering and graceful half-close.
const Direction = struct {
    src_sock: fd_t,
    dst_sock: fd_t,
    pipe: *SpliceProxy,
    buffered: usize = 0,
    eof: bool = false,
    closed: bool = false,
    bytes_transferred: u64 = 0,

    fn step(self: *Direction) !bool {
        if (self.closed) return false;
        var made_progress = false;

        // 1. Drain pending bytes already in the kernel pipe into dst_sock
        if (self.buffered > 0) {
            const n_out = SpliceProxy.splice(
                self.pipe.pipe_read,
                null,
                self.dst_sock,
                null,
                self.buffered,
                SpliceProxy.SPLICE_F_NONBLOCK | SpliceProxy.SPLICE_F_MOVE,
            );
            if (n_out > 0) {
                const written: usize = @intCast(n_out);
                assert(written <= self.buffered);
                self.buffered -= written;
                self.bytes_transferred += written;
                made_progress = true;
            } else if (n_out < 0) {
                const err = -n_out;
                if (err == @intFromEnum(std.posix.E.PIPE) or err == @intFromEnum(std.posix.E.CONNRESET)) {
                    self.closed = true;
                    return made_progress;
                } else if (err != @intFromEnum(std.posix.E.AGAIN) and err != @intFromEnum(std.posix.E.INTR)) {
                    return error.SpliceOutFailed;
                }
            }
        }

        // 2. Read from src_sock into pipe if pipe buffer has capacity
        if (!self.eof and self.buffered < SpliceProxy.PIPE_BUFFER_LIMIT) {
            const avail = SpliceProxy.PIPE_BUFFER_LIMIT - self.buffered;
            const to_read = @min(avail, SpliceProxy.DEFAULT_CHUNK_SIZE);
            const n_in = SpliceProxy.splice(
                self.src_sock,
                null,
                self.pipe.pipe_write,
                null,
                to_read,
                SpliceProxy.SPLICE_F_NONBLOCK | SpliceProxy.SPLICE_F_MOVE,
            );
            if (n_in > 0) {
                const read_bytes: usize = @intCast(n_in);
                self.buffered += read_bytes;
                made_progress = true;

                // Opportunistic flush: attempt to push out to dst_sock immediately
                const n_out = SpliceProxy.splice(
                    self.pipe.pipe_read,
                    null,
                    self.dst_sock,
                    null,
                    self.buffered,
                    SpliceProxy.SPLICE_F_NONBLOCK | SpliceProxy.SPLICE_F_MOVE,
                );
                if (n_out > 0) {
                    const written: usize = @intCast(n_out);
                    assert(written <= self.buffered);
                    self.buffered -= written;
                    self.bytes_transferred += written;
                } else if (n_out < 0) {
                    const err = -n_out;
                    if (err == @intFromEnum(std.posix.E.PIPE) or err == @intFromEnum(std.posix.E.CONNRESET)) {
                        self.closed = true;
                        return made_progress;
                    } else if (err != @intFromEnum(std.posix.E.AGAIN) and err != @intFromEnum(std.posix.E.INTR)) {
                        return error.SpliceOutFailed;
                    }
                }
            } else if (n_in == 0) {
                // EOF detected: remote peer finished sending
                self.eof = true;
                made_progress = true;
            } else {
                const err = -n_in;
                if (err == @intFromEnum(std.posix.E.CONNRESET) or err == @intFromEnum(std.posix.E.PIPE)) {
                    self.eof = true;
                    made_progress = true;
                } else if (err != @intFromEnum(std.posix.E.AGAIN) and err != @intFromEnum(std.posix.E.INTR)) {
                    return error.SpliceInFailed;
                }
            }
        }

        // 3. Graceful half-close: if source hit EOF and all buffered pipe data is drained,
        // send FIN to dst_sock to signal completion in this direction without closing return path.
        if (self.eof and self.buffered == 0) {
            self.closed = true;
            shutdownSocketSend(self.dst_sock);
            made_progress = true;
        }

        return made_progress;
    }

    fn drain(self: *Direction) void {
        var retries: usize = 0;
        while (self.buffered > 0 and retries < 10) : (retries += 1) {
            const n_out = SpliceProxy.splice(
                self.pipe.pipe_read,
                null,
                self.dst_sock,
                null,
                self.buffered,
                SpliceProxy.SPLICE_F_NONBLOCK | SpliceProxy.SPLICE_F_MOVE,
            );
            if (n_out > 0) {
                const written: usize = @intCast(n_out);
                if (written <= self.buffered) {
                    self.buffered -= written;
                    self.bytes_transferred += written;
                } else {
                    self.bytes_transferred += self.buffered;
                    self.buffered = 0;
                }
            } else {
                break;
            }
        }
    }
};

fn shutdownSocketSend(fd: fd_t) void {
    if (builtin.os.tag == .linux) {
        if (@hasDecl(std.posix, "shutdown")) {
            _ = std.posix.shutdown(fd, .send) catch {};
        } else {
            const SHUT_WR: usize = 1;
            const SYS_shutdown: usize = if (@hasDecl(std.os.linux, "SYS") and @hasDecl(std.os.linux.SYS, "shutdown"))
                @intFromEnum(std.os.linux.SYS.shutdown)
            else switch (builtin.cpu.arch) {
                .x86_64 => 48,
                .aarch64, .aarch64_be, .aarch64_32 => 73,
                .riscv64, .riscv32 => 73,
                .arm, .armeb => 293,
                else => 48,
            };
            _ = std.os.linux.syscall2(SYS_shutdown, @intCast(fd), SHUT_WR);
        }
    }
}

/// Kernel Zero-Copy TCP Proxy using Linux splice() system calls.
/// Forwards TCP bytes socket-to-socket through an in-kernel pipe without user-space buffer copying.
pub const SpliceProxy = struct {
    pipe_read: fd_t,
    pipe_write: fd_t,

    pub const SPLICE_F_MOVE: u32 = 0x01;
    pub const SPLICE_F_NONBLOCK: u32 = 0x02;
    pub const SPLICE_F_MORE: u32 = 0x04;

    pub const DEFAULT_CHUNK_SIZE: usize = 65536;
    pub const PIPE_BUFFER_LIMIT: usize = 65536;

    pub const SYS_splice: usize = if (builtin.os.tag == .linux and @hasDecl(std.os.linux, "SYS") and @hasDecl(std.os.linux.SYS, "splice"))
        @intFromEnum(std.os.linux.SYS.splice)
    else switch (builtin.cpu.arch) {
        .x86_64 => 275,
        .aarch64, .aarch64_be, .aarch64_32 => 76,
        .riscv64, .riscv32 => 76,
        .arm, .armeb => 340,
        else => 275,
    };

    pub fn init() !SpliceProxy {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }

        var pipe_fds: [2]std.posix.fd_t = undefined;
        // Create non-blocking kernel pipe
        const rc = std.os.linux.pipe2(&pipe_fds, .{ .NONBLOCK = true });
        if (@as(isize, @bitCast(rc)) < 0) {
            return error.PipeCreationFailed;
        }

        return .{
            .pipe_read = pipe_fds[0],
            .pipe_write = pipe_fds[1],
        };
    }

    pub fn deinit(self: *SpliceProxy) void {
        if (builtin.os.tag == .linux) {
            if (self.pipe_read >= 0) {
                std.posix.close(self.pipe_read);
                self.pipe_read = -1;
            }
            if (self.pipe_write >= 0) {
                std.posix.close(self.pipe_write);
                self.pipe_write = -1;
            }
        }
    }

    pub inline fn splice(
        fd_in: fd_t,
        off_in: ?*usize,
        fd_out: fd_t,
        off_out: ?*usize,
        len: usize,
        flags: u32,
    ) isize {
        if (builtin.os.tag == .linux) {
            const rc = std.os.linux.syscall6(
                .splice,
                @intCast(fd_in),
                @intFromPtr(off_in),
                @intCast(fd_out),
                @intFromPtr(off_out),
                len,
                flags,
            );
            return @bitCast(rc);
        } else {
            return -@as(isize, @intFromEnum(std.posix.E.NOSYS));
        }
    }

    /// Pumps data directly from src_sock to dst_sock via kernel pipe.
    /// Returns number of bytes transferred.
    pub fn forwardChunk(
        self: SpliceProxy,
        src_sock: fd_t,
        dst_sock: fd_t,
        max_bytes: usize,
    ) !usize {
        assert(src_sock != dst_sock);
        if (builtin.os.tag == .linux) {
            assert(src_sock >= 0);
            assert(dst_sock >= 0);
            assert(self.pipe_read >= 0);
            assert(self.pipe_write >= 0);
        }

        // Step 1: Splice from source socket into kernel pipe write end
        const n_in = splice(
            src_sock,
            null,
            self.pipe_write,
            null,
            max_bytes,
            SPLICE_F_NONBLOCK | SPLICE_F_MOVE,
        );

        if (n_in <= 0) {
            if (n_in == 0) return 0; // EOF
            const err_code = -n_in;
            if (err_code == @intFromEnum(std.posix.E.AGAIN) or err_code == @intFromEnum(std.posix.E.INTR)) return 0;
            return error.SpliceInFailed;
        }

        const bytes_in: usize = @intCast(n_in);

        // Step 2: Splice from kernel pipe read end into destination socket
        var bytes_out: usize = 0;
        var retries: usize = 0;
        const max_retries: usize = 1000;
        while (bytes_out < bytes_in) {
            const n_out = splice(
                self.pipe_read,
                null,
                dst_sock,
                null,
                bytes_in - bytes_out,
                SPLICE_F_NONBLOCK | SPLICE_F_MOVE,
            );

            if (n_out <= 0) {
                const err_code = -n_out;
                if (err_code == @intFromEnum(std.posix.E.AGAIN)) {
                    retries += 1;
                    if (retries > max_retries) return error.SpliceOutBlocked;
                    std.Thread.yield() catch {};
                    continue;
                }
                if (err_code == @intFromEnum(std.posix.E.INTR)) continue;
                return error.SpliceOutFailed;
            }
            bytes_out += @intCast(n_out);
        }

        return bytes_out;
    }

    pub const forwardBidirectional = @This().forwardBidirectionalFn;
    pub const forwardBidirectionalWithStats = @This().forwardBidirectionalWithStatsFn;

    fn forwardBidirectionalFn(
        sock_a: fd_t,
        sock_b: fd_t,
        stop_signal: *std.atomic.Value(bool),
    ) !void {
        var stats = ForwardStats{};
        return forwardBidirectionalWithStatsFn(sock_a, sock_b, stop_signal, &stats);
    }

    fn forwardBidirectionalWithStatsFn(
        sock_a: fd_t,
        sock_b: fd_t,
        stop_signal: *std.atomic.Value(bool),
        stats: *ForwardStats,
    ) !void {
        // Pre-condition safety assertions
        if (builtin.os.tag == .linux) {
            if (sock_a < 0 or sock_b < 0) return error.InvalidSocket;
        }
        if (sock_a == sock_b) return error.SameSocket;
        assert(sock_a != sock_b);

        if (builtin.os.tag != .linux) {
            return error.UnsupportedPlatform;
        }

        // Two independent pipes for bidirectional data streams:
        // pipe_ab: sock_a -> sock_b
        // pipe_ba: sock_b -> sock_a
        var pipe_ab = try SpliceProxy.init();
        defer pipe_ab.deinit();

        var pipe_ba = try SpliceProxy.init();
        defer pipe_ba.deinit();

        assert(pipe_ab.pipe_read != pipe_ab.pipe_write);
        assert(pipe_ba.pipe_read != pipe_ba.pipe_write);
        if (builtin.os.tag == .linux) {
            assert(pipe_ab.pipe_read >= 0 and pipe_ab.pipe_write >= 0);
            assert(pipe_ba.pipe_read >= 0 and pipe_ba.pipe_write >= 0);
        }

        var dir_ab = Direction{
            .src_sock = sock_a,
            .dst_sock = sock_b,
            .pipe = &pipe_ab,
        };

        var dir_ba = Direction{
            .src_sock = sock_b,
            .dst_sock = sock_a,
            .pipe = &pipe_ba,
        };

        var backoff = Backoff{};

        // Main bidirectional forwarding event loop
        while (true) {
            stats.iterations += 1;

            // 1. External stop signal check
            if (stop_signal.load(.acquire)) {
                dir_ab.drain();
                dir_ba.drain();
                break;
            }

            // 2. Both streams completed and drained
            if (dir_ab.closed and dir_ba.closed) {
                break;
            }

            var activity = false;

            // 3. Process direction A -> B
            if (!dir_ab.closed) {
                const act = try dir_ab.step();
                if (act) activity = true;
            }

            // 4. Process direction B -> A
            if (!dir_ba.closed) {
                const act = try dir_ba.step();
                if (act) activity = true;
            }

            // 5. Activity check and adaptive EAGAIN backoff
            if (activity) {
                backoff.reset();
            } else {
                stats.eagain_events += 1;
                backoff.wait();
            }
        }

        // Record metrics
        stats.bytes_a_to_b = dir_ab.bytes_transferred;
        stats.bytes_b_to_a = dir_ba.bytes_transferred;
        stats.a_eof = dir_ab.eof;
        stats.b_eof = dir_ba.eof;
    }
};

/// Bidirectional zero-copy TCP forwarding using two kernel pipes and non-blocking splice().
pub const forwardBidirectional = SpliceProxy.forwardBidirectional;

/// Bidirectional forwarding with detailed metrics recording.
pub const forwardBidirectionalWithStats = SpliceProxy.forwardBidirectionalWithStats;

// ============================================================================
// Unit Tests
// ============================================================================

test "SpliceProxy constants and layout" {
    try std.testing.expectEqual(@as(u32, 0x01), SpliceProxy.SPLICE_F_MOVE);
    try std.testing.expectEqual(@as(u32, 0x02), SpliceProxy.SPLICE_F_NONBLOCK);
    try std.testing.expectEqual(@as(u32, 0x04), SpliceProxy.SPLICE_F_MORE);
    try std.testing.expect(SpliceProxy.PIPE_BUFFER_LIMIT > 0);
    try std.testing.expect(SpliceProxy.DEFAULT_CHUNK_SIZE > 0);
    try std.testing.expect(SpliceProxy.SYS_splice > 0);
}

test "Backoff progressive delay and reset" {
    var b = Backoff{};
    try std.testing.expectEqual(@as(u32, 0), b.consecutive_idle);
    try std.testing.expectEqual(@as(u64, 50_000), b.current_sleep_ns);

    // First 3 steps should yield without increasing current_sleep_ns
    b.wait();
    b.wait();
    b.wait();
    try std.testing.expectEqual(@as(u32, 3), b.consecutive_idle);
    try std.testing.expectEqual(@as(u64, 50_000), b.current_sleep_ns);

    // 4th step should start progressive sleep
    b.wait();
    try std.testing.expectEqual(@as(u32, 4), b.consecutive_idle);
    try std.testing.expect(b.current_sleep_ns > 50_000);

    // Reset should restore initial idle count and min sleep
    b.reset();
    try std.testing.expectEqual(@as(u32, 0), b.consecutive_idle);
    try std.testing.expectEqual(@as(u64, 50_000), b.current_sleep_ns);
}

test "ForwardStats tracking defaults" {
    const stats = ForwardStats{};
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_a_to_b);
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_b_to_a);
    try std.testing.expectEqual(@as(u64, 0), stats.iterations);
    try std.testing.expectEqual(@as(u64, 0), stats.eagain_events);
    try std.testing.expect(!stats.a_eof);
    try std.testing.expect(!stats.b_eof);
}

test "forwardBidirectional input safety checks" {
    var stop = std.atomic.Value(bool).init(false);

    if (builtin.os.tag == .linux) {
        try std.testing.expectError(error.SameSocket, forwardBidirectional(10, 10, &stop));
        try std.testing.expectError(error.InvalidSocket, forwardBidirectional(-1, 5, &stop));
        try std.testing.expectError(error.InvalidSocket, forwardBidirectional(5, -1, &stop));
    } else {
        var dummy1: u8 = 0;
        var dummy2: u8 = 0;
        const h1: fd_t = &dummy1;
        const h2: fd_t = &dummy2;
        try std.testing.expectError(error.SameSocket, forwardBidirectional(h1, h1, &stop));
        try std.testing.expectError(error.UnsupportedPlatform, forwardBidirectional(h1, h2, &stop));
    }
}

test "SpliceProxy platform check on non-Linux" {
    if (builtin.os.tag != .linux) {
        try std.testing.expectError(error.UnsupportedPlatform, SpliceProxy.init());
        var stop = std.atomic.Value(bool).init(false);
        var dummy1: u8 = 0;
        var dummy2: u8 = 0;
        const fd_a: fd_t = &dummy1;
        const fd_b: fd_t = &dummy2;
        try std.testing.expectError(error.UnsupportedPlatform, forwardBidirectional(fd_a, fd_b, &stop));
    }
}

test "SpliceProxy Linux pipe creation and stop signal" {
    if (builtin.os.tag == .linux) {
        var proxy = try SpliceProxy.init();
        defer proxy.deinit();

        try std.testing.expect(proxy.pipe_read >= 0);
        try std.testing.expect(proxy.pipe_write >= 0);
        try std.testing.expect(proxy.pipe_read != proxy.pipe_write);

        // Test bidirectional forwarding loop exit via stop_signal
        var stop = std.atomic.Value(bool).init(true); // already stopped
        var stats = ForwardStats{};
        try forwardBidirectionalWithStats(proxy.pipe_read, proxy.pipe_write, &stop, &stats);
        try std.testing.expect(stats.iterations >= 1);
    }
}

test "SpliceProxy Linux socketpair bidirectional transfer and EOF" {
    if (builtin.os.tag == .linux) {
        // Create two UNIX domain socket pairs:
        // pair_a: [0]=client_a, [1]=proxy_sock_a
        // pair_b: [0]=client_b, [1]=proxy_sock_b
        var pair_a: [2]std.posix.fd_t = undefined;
        var pair_b: [2]std.posix.fd_t = undefined;

        const rc_a = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair_a);
        if (@as(isize, @bitCast(rc_a)) != 0) return;
        defer std.posix.close(pair_a[0]);
        defer std.posix.close(pair_a[1]);

        const rc_b = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &pair_b);
        if (@as(isize, @bitCast(rc_b)) != 0) return;
        defer std.posix.close(pair_b[0]);
        defer std.posix.close(pair_b[1]);

        const client_a = pair_a[0];
        const proxy_a = pair_a[1];
        const client_b = pair_b[0];
        const proxy_b = pair_b[1];

        // Send data client_a -> proxy_a
        const msg = "HELLO_KERNEL_SPLICE";
        _ = try std.posix.write(client_a, msg);

        var stop = std.atomic.Value(bool).init(false);
        var stats = ForwardStats{};

        const ThreadContext = struct {
            p_a: fd_t,
            p_b: fd_t,
            stop_sig: *std.atomic.Value(bool),
            st: *ForwardStats,
            fn run(ctx: @This()) void {
                _ = forwardBidirectionalWithStats(ctx.p_a, ctx.p_b, ctx.stop_sig, ctx.st) catch {};
            }
        };

        const thread = try std.Thread.spawn(.{}, ThreadContext.run, .{ThreadContext{
            .p_a = proxy_a,
            .p_b = proxy_b,
            .stop_sig = &stop,
            .st = &stats,
        }});

        // Read from client_b
        var recv_buf: [64]u8 = undefined;
        var total_read: usize = 0;
        var attempts: usize = 0;
        while (total_read < msg.len and attempts < 100) : (attempts += 1) {
            const n = std.posix.read(client_b, recv_buf[total_read..]) catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(1_000_000);
                    continue;
                }
                return err;
            };
            if (n == 0) break;
            total_read += n;
        }

        try std.testing.expectEqualStrings(msg, recv_buf[0..total_read]);

        // Stop proxy thread
        stop.store(true, .release);
        thread.join();
        try std.testing.expect(stats.bytes_a_to_b >= msg.len);
    }
}
