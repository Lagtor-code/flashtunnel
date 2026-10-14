const std = @import("std");
const builtin = @import("builtin");

const SpscQueue = @import("ring_buffer.zig").SpscQueue;
const wire = @import("../protocol/wire.zig");
const replay = @import("../protocol/replay.zig");
const encap = @import("../protocol/encap.zig");
const crypto = @import("../crypto/chacha20poly1305.zig");
const tun = @import("../tun/tun_device.zig");
const batch_socket = @import("../net/batch_socket.zig");

const AeadEngine = crypto.AeadEngine;
const ReplayWindow = replay.ReplayWindow;
const GreEncap = encap.GreEncap;
const TunDevice = tun.TunDevice;
const BatchSocket = batch_socket.BatchSocket;

// ============================================================================
// CPU Affinity & NUMA Helpers
// ============================================================================

/// CPU bitset supporting up to 1024 cores (matching Linux cpu_set_t, 128 bytes).
pub const CpuSet = struct {
    pub const MAX_CPUS: usize = 1024;
    pub const WORDS: usize = MAX_CPUS / 64; // 16 words of 64-bit mask

    mask: [WORDS]u64 = [_]u64{0} ** WORDS,

    pub fn init() CpuSet {
        return .{};
    }

    /// Sets the bit corresponding to CPU core `cpu`.
    pub fn set(self: *CpuSet, cpu: usize) void {
        if (cpu < MAX_CPUS) {
            const word = cpu / 64;
            const bit = @as(u64, 1) << @intCast(cpu % 64);
            self.mask[word] |= bit;
        }
    }

    /// Clears the bit corresponding to CPU core `cpu`.
    pub fn clear(self: *CpuSet, cpu: usize) void {
        if (cpu < MAX_CPUS) {
            const word = cpu / 64;
            const bit = @as(u64, 1) << @intCast(cpu % 64);
            self.mask[word] &= ~bit;
        }
    }

    /// Checks if the bit corresponding to CPU core `cpu` is set.
    pub fn isSet(self: CpuSet, cpu: usize) bool {
        if (cpu < MAX_CPUS) {
            const word = cpu / 64;
            const bit = @as(u64, 1) << @intCast(cpu % 64);
            return (self.mask[word] & bit) != 0;
        }
        return false;
    }

    /// Sets a contiguous range of CPU cores [start, end).
    pub fn setRange(self: *CpuSet, start: usize, end: usize) void {
        var cpu = start;
        while (cpu < end and cpu < MAX_CPUS) : (cpu += 1) {
            self.set(cpu);
        }
    }

    /// Clears all CPU bits.
    pub fn zero(self: *CpuSet) void {
        @memset(&self.mask, 0);
    }

    /// Returns the total number of CPU cores enabled in this mask.
    pub fn count(self: CpuSet) usize {
        var total: usize = 0;
        for (self.mask) |w| {
            total += @popCount(w);
        }
        return total;
    }
};

/// Direct C/POSIX bindings for environments linked with libc.
pub const affinity_c = struct {
    pub extern "c" fn sched_setaffinity(pid: c_int, cpusetsize: usize, mask: *const anyopaque) c_int;
    pub extern "c" fn sched_getaffinity(pid: c_int, cpusetsize: usize, mask: *anyopaque) c_int;
    pub extern "c" fn pthread_setaffinity_np(thread: usize, cpusetsize: usize, cpuset: *const anyopaque) c_int;
    pub extern "c" fn pthread_getaffinity_np(thread: usize, cpusetsize: usize, cpuset: *anyopaque) c_int;
};

// Windows thread affinity API bindings when running on Windows
const windows_api = if (builtin.os.tag == .windows) struct {
    pub const HANDLE = std.os.windows.HANDLE;
    pub const DWORD_PTR = std.os.windows.DWORD_PTR;
    pub const WINAPI = std.os.windows.WINAPI;

    pub extern "kernel32" fn SetThreadAffinityMask(
        hThread: HANDLE,
        dwThreadAffinityMask: DWORD_PTR,
    ) callconv(WINAPI) DWORD_PTR;

    pub extern "kernel32" fn GetCurrentThread() callconv(WINAPI) HANDLE;
} else struct {};

fn getSchedSetaffinitySyscall() usize {
    if (builtin.os.tag == .linux) {
        if (@hasDecl(std.os.linux.SYS, "sched_setaffinity")) {
            return @intFromEnum(std.os.linux.SYS.sched_setaffinity);
        }
        return 203; // Linux x86_64 fallback
    }
    return 0;
}

fn getSchedGetaffinitySyscall() usize {
    if (builtin.os.tag == .linux) {
        if (@hasDecl(std.os.linux.SYS, "sched_getaffinity")) {
            return @intFromEnum(std.os.linux.SYS.sched_getaffinity);
        }
        return 204; // Linux x86_64 fallback
    }
    return 0;
}

/// Linux sched_setaffinity wrapper.
/// Sets the CPU affinity mask for thread/process with given pid (0 = calling thread).
pub fn schedSetAffinity(pid: i32, cpuset: *const CpuSet) !void {
    if (builtin.os.tag == .linux) {
        if (builtin.link_libc) {
            const rc = affinity_c.sched_setaffinity(pid, @sizeOf(CpuSet), @ptrCast(&cpuset.mask[0]));
            if (rc != 0) return error.SetAffinityFailed;
            return;
        } else {
            const rc = std.os.linux.syscall3(
                .sched_setaffinity,
                @intCast(pid),
                @sizeOf(CpuSet),
                @intFromPtr(&cpuset.mask[0]),
            );
            if (@as(isize, @bitCast(rc)) < 0) {
                return error.SetAffinityFailed;
            }
            return;
        }
    } else if (builtin.os.tag == .windows) {
        if (pid == 0) {
            const mask: usize = @intCast(cpuset.mask[0]);
            if (mask != 0) {
                const current_thread = windows_api.GetCurrentThread();
                const res = windows_api.SetThreadAffinityMask(current_thread, mask);
                if (res == 0) return error.SetAffinityFailed;
            }
        }
        return;
    }
    // Graceful no-op on other platforms
}

/// Linux sched_getaffinity wrapper.
/// Retrieves the CPU affinity mask for thread/process with given pid (0 = calling thread).
pub fn schedGetAffinity(pid: i32) !CpuSet {
    var cpuset = CpuSet.init();
    if (builtin.os.tag == .linux) {
        if (builtin.link_libc) {
            const rc = affinity_c.sched_getaffinity(pid, @sizeOf(CpuSet), @ptrCast(&cpuset.mask[0]));
            if (rc != 0) return error.GetAffinityFailed;
            return cpuset;
        } else {
            const rc = std.os.linux.syscall3(
                .sched_getaffinity,
                @intCast(pid),
                @sizeOf(CpuSet),
                @intFromPtr(&cpuset.mask[0]),
            );
            if (@as(isize, @bitCast(rc)) < 0) {
                return error.GetAffinityFailed;
            }
            return cpuset;
        }
    }
    // Default fallback: core 0 enabled
    cpuset.set(0);
    return cpuset;
}

/// Linux pthread_setaffinity_np wrapper.
/// Sets the CPU affinity mask for a specific pthread.
pub fn pthreadSetAffinity(pthread: usize, cpuset: *const CpuSet) !void {
    if (builtin.os.tag == .linux and builtin.link_libc) {
        const rc = affinity_c.pthread_setaffinity_np(pthread, @sizeOf(CpuSet), @ptrCast(&cpuset.mask[0]));
        if (rc != 0) return error.SetAffinityFailed;
    } else {
        return schedSetAffinity(0, cpuset);
    }
}

/// Pins the calling thread to a single specific CPU core.
pub fn pinCurrentThreadToCore(core_id: usize) !void {
    var cpuset = CpuSet.init();
    cpuset.set(core_id);
    return schedSetAffinity(0, &cpuset);
}

/// Pins the calling thread to a bitset mask of CPU cores.
pub fn pinCurrentThreadToMask(cpuset: *const CpuSet) !void {
    return schedSetAffinity(0, cpuset);
}

/// Retrieves the current thread's CPU core affinity mask.
pub fn getCurrentThreadAffinity() !CpuSet {
    return schedGetAffinity(0);
}

/// Pins the calling thread to all CPU cores belonging to a NUMA node.
pub fn pinToNumaNode(node_id: usize, cores_per_node: usize) !void {
    var cpuset = CpuSet.init();
    const start_core = node_id * cores_per_node;
    const end_core = start_core + cores_per_node;
    cpuset.setRange(start_core, end_core);
    return schedSetAffinity(0, &cpuset);
}

// ============================================================================
// Multi-Stage Lock-Free Pipeline Architecture
// ============================================================================

pub const MAX_PACKET_SIZE: usize = 2048;
pub const MAX_WORKERS: usize = 16;
pub const QUEUE_CAPACITY: usize = 256;

/// High-performance packet descriptor passing through the pipeline.
pub const Packet = struct {
    data: [MAX_PACKET_SIZE]u8 = undefined,
    len: usize = 0,
    session: u32 = 0,
    counter: u64 = 0,
    kind: u8 = wire.Header.TYPE_DATA,

    pub inline fn slice(self: *const Packet) []const u8 {
        return self.data[0..self.len];
    }

    pub inline fn mutSlice(self: *Packet) []u8 {
        return self.data[0..self.len];
    }

    pub fn setPayload(self: *Packet, bytes: []const u8) void {
        const copy_len = @min(bytes.len, MAX_PACKET_SIZE);
        @memcpy(self.data[0..copy_len], bytes[0..copy_len]);
        self.len = copy_len;
    }

    pub fn initFromSlice(bytes: []const u8, session: u32, counter: u64, kind: u8) Packet {
        var pkt = Packet{
            .len = @min(bytes.len, MAX_PACKET_SIZE),
            .session = session,
            .counter = counter,
            .kind = kind,
        };
        @memcpy(pkt.data[0..pkt.len], bytes[0..pkt.len]);
        return pkt;
    }
};

pub const PacketQueue = SpscQueue(Packet, QUEUE_CAPACITY);

/// Configuration for NUMA-orchestrated packet pipeline.
pub const PipelineConfig = struct {
    num_workers: usize = 4,
    rx_core: usize = 0,
    worker_cores: [MAX_WORKERS]usize = [_]usize{ 1, 2, 3, 4 } ++ [_]usize{0} ** (MAX_WORKERS - 4),
    tx_core: usize = 5,
    key: [32]u8 = [_]u8{0x5A} ** 32,
    numa_node: usize = 0,
    enable_affinity: bool = true,
    gre_key: ?u32 = null,
};

/// Telemetry snapshot across all pipeline stages.
pub const PipelineStats = struct {
    rx_packets: usize = 0,
    rx_bytes: usize = 0,
    rx_dropped: usize = 0,

    decrypt_packets: usize = 0,
    decrypt_bytes: usize = 0,
    replay_drops: usize = 0,
    auth_fail_drops: usize = 0,
    tx_queue_full_drops: usize = 0,

    tx_packets: usize = 0,
    tx_bytes: usize = 0,
    tx_dropped: usize = 0,
};

/// Stage 2 Worker State: strictly thread-local resources for zero cache line contention.
pub const WorkerState = struct {
    id: usize = 0,
    core_id: usize = 0,
    crypto_engine: AeadEngine,
    replay_window: ReplayWindow = .{},
    gre: ?GreEncap = null,

    // Cache-aligned atomic metrics per worker thread
    decrypted_packets: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    decrypted_bytes: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    replay_drops: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    auth_fail_drops: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    tx_queue_full_drops: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

/// Stage 1 & Stage 3 atomic metrics
pub const PipelineAtomicStats = struct {
    rx_packets: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    rx_bytes: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    rx_dropped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    tx_packets: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    tx_bytes: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    tx_dropped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

/// High-throughput lock-free packet processing pipeline:
/// Stage 1: NIC batch rx (session-consistent steering)
/// Stage 2: Decrypt & Anti-replay worker threads
/// Stage 3: TUN tx (round-robin drain to TUN egress)
pub const Pipeline = struct {
    config: PipelineConfig,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // SPSC Queues connecting Stage 1 (NIC RX) -> Stage 2 (Worker [0..N-1])
    rx_to_worker: [MAX_WORKERS]PacketQueue = undefined,

    // SPSC Queues connecting Stage 2 (Worker [0..N-1]) -> Stage 3 (TUN TX)
    worker_to_tx: [MAX_WORKERS]PacketQueue = undefined,

    // Optional egress queue for userspace draining / unit testing / Go bridge
    egress_queue: PacketQueue = undefined,

    // Per-worker state (crypto + replay window)
    workers: [MAX_WORKERS]WorkerState = undefined,

    // Pipeline I/O handles (optional)
    socket: ?BatchSocket = null,
    tun_device: ?TunDevice = null,

    // Thread handles
    rx_thread: ?std.Thread = null,
    worker_threads: [MAX_WORKERS]?std.Thread = [_]?std.Thread{null} ** MAX_WORKERS,
    tx_thread: ?std.Thread = null,

    // Atomic telemetry
    stats: PipelineAtomicStats = .{},

    /// In-place initialization avoiding large stack copies.
    pub fn initInto(self: *Pipeline, config: PipelineConfig) void {
        self.config = config;
        self.running = std.atomic.Value(bool).init(false);
        self.socket = null;
        self.tun_device = null;
        self.rx_thread = null;
        self.tx_thread = null;
        self.stats = .{};
        self.egress_queue = PacketQueue.init();

        var i: usize = 0;
        while (i < MAX_WORKERS) : (i += 1) {
            self.rx_to_worker[i] = PacketQueue.init();
            self.worker_to_tx[i] = PacketQueue.init();
            self.worker_threads[i] = null;

            const core = if (i < config.num_workers) config.worker_cores[i] else 0;
            self.workers[i] = .{
                .id = i,
                .core_id = core,
                .crypto_engine = AeadEngine.init(config.key),
                .replay_window = .{},
                .gre = if (config.gre_key) |k| GreEncap.init(k) else null,
            };
        }
    }

    /// Heap allocator constructor.
    pub fn create(allocator: std.mem.Allocator, config: PipelineConfig) !*Pipeline {
        const self = try allocator.create(Pipeline);
        self.initInto(config);
        return self;
    }

    /// Cleans up and frees pipeline resources.
    pub fn destroy(self: *Pipeline, allocator: std.mem.Allocator) void {
        self.stop();
        allocator.destroy(self);
    }

    // ========================================================================
    // Stage 1: NIC Batch RX & Flow Steering
    // ========================================================================

    /// Consistent flow steering: maps session ID to Stage 2 worker.
    /// Ensures all packets for the same session hit the same worker (cache locality & replay window order).
    pub inline fn steerSession(self: *const Pipeline, session: u32) usize {
        const num = if (self.config.num_workers > 0) self.config.num_workers else 1;
        return @intCast(session % num);
    }

    /// Ingests a single raw datagram from the network into Stage 1.
    /// Parses wire header, selects worker via flow steering, and pushes to SPSC queue.
    pub fn ingestRawPacket(self: *Pipeline, raw: []const u8) bool {
        if (raw.len < wire.Header.DATA_OVERHEAD) {
            _ = self.stats.rx_dropped.fetchAdd(1, .monotonic);
            return false;
        }

        const parsed = wire.Header.parse(raw) catch {
            _ = self.stats.rx_dropped.fetchAdd(1, .monotonic);
            return false;
        };

        const worker_idx = self.steerSession(parsed.header.session);
        var pkt = Packet{
            .len = @min(raw.len, MAX_PACKET_SIZE),
            .session = parsed.header.session,
            .counter = parsed.header.counter,
            .kind = parsed.header.kind,
        };
        @memcpy(pkt.data[0..pkt.len], raw[0..pkt.len]);

        if (!self.rx_to_worker[worker_idx].push(pkt)) {
            _ = self.stats.rx_dropped.fetchAdd(1, .monotonic);
            return false;
        }

        _ = self.stats.rx_packets.fetchAdd(1, .monotonic);
        _ = self.stats.rx_bytes.fetchAdd(pkt.len, .monotonic);
        return true;
    }

    /// Ingests a batch of raw datagrams (e.g. from recvmmsg) into Stage 1.
    pub fn ingestRawBatch(self: *Pipeline, batch: []const []const u8) usize {
        var accepted: usize = 0;
        for (batch) |raw| {
            if (self.ingestRawPacket(raw)) {
                accepted += 1;
            }
        }
        return accepted;
    }

    // ========================================================================
    // Stage 2: Decrypt & Anti-replay Worker Execution
    // ========================================================================

    /// Executes one iteration of work for worker `worker_id`.
    /// Returns true if a packet was processed, false if queue was empty.
    pub fn stepWorker(self: *Pipeline, worker_id: usize) bool {
        if (worker_id >= self.config.num_workers) return false;

        const maybe_pkt = self.rx_to_worker[worker_id].pop();
        if (maybe_pkt == null) return false;

        const pkt = maybe_pkt.?;
        var worker = &self.workers[worker_id];

        if (pkt.kind == wire.Header.TYPE_DATA) {
            // 1. Anti-Replay Check
            if (!worker.replay_window.accept(pkt.counter)) {
                _ = worker.replay_drops.fetchAdd(1, .monotonic);
                return true; // Dropped replayed packet
            }

            // 2. ChaCha20-Poly1305 AEAD Authentication & Decryption
            if (pkt.len < wire.Header.DATA_OVERHEAD) {
                _ = worker.auth_fail_drops.fetchAdd(1, .monotonic);
                return true;
            }

            const ad = pkt.data[0..wire.Header.LEN];
            const body = pkt.data[wire.Header.LEN..pkt.len];

            var plain_buf: [MAX_PACKET_SIZE]u8 = undefined;
            const plain = worker.crypto_engine.open(
                &plain_buf,
                pkt.counter,
                ad,
                body,
            ) catch {
                _ = worker.auth_fail_drops.fetchAdd(1, .monotonic);
                return true; // Dropped forged/corrupt packet
            };

            // 3. Commit authenticated counter to replay window
            worker.replay_window.commit(pkt.counter);

            // 4. Optional GRE Decapsulation
            const payload = if (worker.gre) |gre|
                gre.unwrap(plain) catch plain
            else
                plain;

            // 5. Push decrypted packet to Stage 3 (TUN TX)
            const tx_pkt = Packet.initFromSlice(payload, pkt.session, pkt.counter, pkt.kind);
            if (!self.worker_to_tx[worker_id].push(tx_pkt)) {
                _ = worker.tx_queue_full_drops.fetchAdd(1, .monotonic);
            } else {
                _ = worker.decrypted_packets.fetchAdd(1, .monotonic);
                _ = worker.decrypted_bytes.fetchAdd(payload.len, .monotonic);
            }
        } else {
            // Non-data control packets pass through directly
            _ = self.worker_to_tx[worker_id].push(pkt);
        }

        return true;
    }

    /// Steps all worker threads once (convenience for single-threaded / test execution).
    pub fn stepAllWorkers(self: *Pipeline) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.config.num_workers) : (i += 1) {
            if (self.stepWorker(i)) {
                count += 1;
            }
        }
        return count;
    }

    // ========================================================================
    // Stage 3: TUN TX Egress
    // ========================================================================

    /// Polls/drains one batch of packets from Stage 2 workers to TUN egress.
    /// Returns true if at least one packet was forwarded, false if all queues were empty.
    pub fn stepTx(self: *Pipeline) bool {
        var worked = false;
        var w: usize = 0;
        while (w < self.config.num_workers) : (w += 1) {
            while (self.worker_to_tx[w].pop()) |plain_pkt| {
                worked = true;

                // If a physical TUN device is attached, transmit packet
                if (self.tun_device) |*dev| {
                    _ = dev.writePacket(plain_pkt.slice()) catch {};
                }

                // Also enqueue into egress queue for userspace consumers / tests
                _ = self.egress_queue.push(plain_pkt);

                _ = self.stats.tx_packets.fetchAdd(1, .monotonic);
                _ = self.stats.tx_bytes.fetchAdd(plain_pkt.len, .monotonic);
            }
        }
        return worked;
    }

    /// Pops a single decrypted packet from Stage 3 egress.
    pub fn popTx(self: *Pipeline) ?Packet {
        return self.egress_queue.pop();
    }

    /// Drains decrypted packets into an output slice.
    pub fn drainTx(self: *Pipeline, out: []Packet) usize {
        var count: usize = 0;
        while (count < out.len) {
            if (self.popTx()) |pkt| {
                out[count] = pkt;
                count += 1;
            } else {
                break;
            }
        }
        return count;
    }

    // ========================================================================
    // Thread Orchestration & Background Execution
    // ========================================================================

    fn workerThreadRun(self: *Pipeline, worker_id: usize) void {
        const core = self.config.worker_cores[worker_id];
        if (self.config.enable_affinity) {
            pinCurrentThreadToCore(core) catch {};
        }

        var idle_count: usize = 0;
        while (self.running.load(.monotonic)) {
            const worked = self.stepWorker(worker_id);
            if (!worked) {
                idle_count += 1;
                if (idle_count < 64) {
                    std.atomic.spinLoopHint();
                } else if (idle_count < 512) {
                    std.Thread.yield() catch {};
                } else {
                    std.time.sleep(25 * std.time.ns_per_us);
                }
            } else {
                idle_count = 0;
            }
        }

        // Drain on exit
        while (self.stepWorker(worker_id)) {}
    }

    fn txThreadRun(self: *Pipeline) void {
        if (self.config.enable_affinity) {
            pinCurrentThreadToCore(self.config.tx_core) catch {};
        }

        var idle_count: usize = 0;
        while (self.running.load(.monotonic)) {
            const worked = self.stepTx();
            if (!worked) {
                idle_count += 1;
                if (idle_count < 64) {
                    std.atomic.spinLoopHint();
                } else if (idle_count < 512) {
                    std.Thread.yield() catch {};
                } else {
                    std.time.sleep(25 * std.time.ns_per_us);
                }
            } else {
                idle_count = 0;
            }
        }

        // Drain on exit
        while (self.stepTx()) {}
    }

    /// Starts all pipeline background threads (Stage 2 workers and Stage 3 TX).
    pub fn start(self: *Pipeline) !void {
        if (self.running.load(.monotonic)) return;
        self.running.store(true, .release);

        // 1. Start Stage 3 (TUN TX)
        self.tx_thread = try std.Thread.spawn(.{}, txThreadRun, .{self});

        // 2. Start Stage 2 (Workers)
        var i: usize = 0;
        while (i < self.config.num_workers) : (i += 1) {
            self.worker_threads[i] = try std.Thread.spawn(.{}, workerThreadRun, .{ self, i });
        }
    }

    /// Gracefully stops all background threads and joins them.
    pub fn stop(self: *Pipeline) void {
        if (!self.running.load(.monotonic)) return;
        self.running.store(false, .release);

        // Join RX thread if present
        if (self.rx_thread) |th| {
            th.join();
            self.rx_thread = null;
        }

        // Join Stage 2 worker threads
        var i: usize = 0;
        while (i < self.config.num_workers) : (i += 1) {
            if (self.worker_threads[i]) |th| {
                th.join();
                self.worker_threads[i] = null;
            }
        }

        // Join Stage 3 TX thread
        if (self.tx_thread) |th| {
            th.join();
            self.tx_thread = null;
        }
    }

    /// Retrieves an aggregated telemetry snapshot across all stages and workers.
    pub fn getStats(self: *const Pipeline) PipelineStats {
        var decrypt_pkts: usize = 0;
        var decrypt_bts: usize = 0;
        var replay_drps: usize = 0;
        var auth_drps: usize = 0;
        var tx_q_full: usize = 0;

        var i: usize = 0;
        while (i < self.config.num_workers) : (i += 1) {
            decrypt_pkts += self.workers[i].decrypted_packets.load(.monotonic);
            decrypt_bts += self.workers[i].decrypted_bytes.load(.monotonic);
            replay_drps += self.workers[i].replay_drops.load(.monotonic);
            auth_drps += self.workers[i].auth_fail_drops.load(.monotonic);
            tx_q_full += self.workers[i].tx_queue_full_drops.load(.monotonic);
        }

        return .{
            .rx_packets = self.stats.rx_packets.load(.monotonic),
            .rx_bytes = self.stats.rx_bytes.load(.monotonic),
            .rx_dropped = self.stats.rx_dropped.load(.monotonic),
            .decrypt_packets = decrypt_pkts,
            .decrypt_bytes = decrypt_bts,
            .replay_drops = replay_drps,
            .auth_fail_drops = auth_drps,
            .tx_queue_full_drops = tx_q_full,
            .tx_packets = self.stats.tx_packets.load(.monotonic),
            .tx_bytes = self.stats.tx_bytes.load(.monotonic),
            .tx_dropped = self.stats.tx_dropped.load(.monotonic),
        };
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "CpuSet bitmask operations" {
    var cpuset = CpuSet.init();
    try std.testing.expectEqual(@as(usize, 0), cpuset.count());

    cpuset.set(0);
    cpuset.set(3);
    cpuset.set(63);
    cpuset.set(64);
    cpuset.set(127);
    cpuset.set(1000);

    try std.testing.expect(cpuset.isSet(0));
    try std.testing.expect(cpuset.isSet(3));
    try std.testing.expect(cpuset.isSet(63));
    try std.testing.expect(cpuset.isSet(64));
    try std.testing.expect(cpuset.isSet(127));
    try std.testing.expect(cpuset.isSet(1000));
    try std.testing.expect(!cpuset.isSet(1));
    try std.testing.expect(!cpuset.isSet(65));
    try std.testing.expectEqual(@as(usize, 6), cpuset.count());

    cpuset.clear(64);
    try std.testing.expect(!cpuset.isSet(64));
    try std.testing.expectEqual(@as(usize, 5), cpuset.count());

    cpuset.zero();
    try std.testing.expectEqual(@as(usize, 0), cpuset.count());

    cpuset.setRange(8, 16);
    try std.testing.expectEqual(@as(usize, 8), cpuset.count());
    try std.testing.expect(cpuset.isSet(8));
    try std.testing.expect(cpuset.isSet(15));
    try std.testing.expect(!cpuset.isSet(7));
    try std.testing.expect(!cpuset.isSet(16));
}

test "CPU affinity pinning helper" {
    // Tests calling pinning function without fatal failure
    pinCurrentThreadToCore(0) catch {};
    pinToNumaNode(0, 4) catch {};
}

test "Pipeline: Single packet end-to-end flow" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x42} ** 32;

    const pipeline = try Pipeline.create(allocator, .{
        .num_workers = 2,
        .key = key,
        .enable_affinity = false,
    });
    defer pipeline.destroy(allocator);

    const plaintext = "PING TUNNEL PACKET DATA OVERLOCK";
    const session: u32 = 100;
    const counter: u64 = 1;

    // 1. Construct valid BackPack wire packet
    var wire_buf: [MAX_PACKET_SIZE]u8 = undefined;
    const header = wire.Header{
        .kind = wire.Header.TYPE_DATA,
        .session = session,
        .counter = counter,
    };
    header.put(wire_buf[0..wire.Header.LEN]);

    const engine = AeadEngine.init(key);
    const body_len = try engine.seal(
        wire_buf[wire.Header.LEN..],
        counter,
        wire_buf[0..wire.Header.LEN],
        plaintext,
    );
    const total_wire_len = wire.Header.LEN + body_len;

    // 2. Ingest into Stage 1
    const accepted = pipeline.ingestRawPacket(wire_buf[0..total_wire_len]);
    try std.testing.expect(accepted);

    // 3. Step Stage 2 (Worker corresponding to session % 2)
    const worker_idx = pipeline.steerSession(session);
    try std.testing.expectEqual(@as(usize, 0), worker_idx);
    const worked_s2 = pipeline.stepWorker(worker_idx);
    try std.testing.expect(worked_s2);

    // 4. Step Stage 3 (TUN TX)
    const worked_s3 = pipeline.stepTx();
    try std.testing.expect(worked_s3);

    // 5. Verify packet arrived at TUN egress
    const out_pkt = pipeline.popTx();
    try std.testing.expect(out_pkt != null);
    try std.testing.expectEqualStrings(plaintext, out_pkt.?.slice());

    // 6. Verify stats
    const stats = pipeline.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.rx_packets);
    try std.testing.expectEqual(@as(usize, 1), stats.decrypt_packets);
    try std.testing.expectEqual(@as(usize, 1), stats.tx_packets);
    try std.testing.expectEqual(@as(usize, 0), stats.replay_drops);
    try std.testing.expectEqual(@as(usize, 0), stats.auth_fail_drops);
}

test "Pipeline: Anti-replay rejection" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x77} ** 32;

    const pipeline = try Pipeline.create(allocator, .{
        .num_workers = 2,
        .key = key,
        .enable_affinity = false,
    });
    defer pipeline.destroy(allocator);

    const plaintext = "SECURE PAYLOAD FOR REPLAY TEST";
    const session: u32 = 10;
    const counter: u64 = 42;

    var wire_buf: [MAX_PACKET_SIZE]u8 = undefined;
    const header = wire.Header{
        .kind = wire.Header.TYPE_DATA,
        .session = session,
        .counter = counter,
    };
    header.put(wire_buf[0..wire.Header.LEN]);

    const engine = AeadEngine.init(key);
    const body_len = try engine.seal(
        wire_buf[wire.Header.LEN..],
        counter,
        wire_buf[0..wire.Header.LEN],
        plaintext,
    );
    const total_wire_len = wire.Header.LEN + body_len;

    // Send first packet (valid)
    try std.testing.expect(pipeline.ingestRawPacket(wire_buf[0..total_wire_len]));
    _ = pipeline.stepWorker(pipeline.steerSession(session));
    _ = pipeline.stepTx();
    try std.testing.expect(pipeline.popTx() != null);

    // Send DUPLICATE packet with same counter (replayed)
    try std.testing.expect(pipeline.ingestRawPacket(wire_buf[0..total_wire_len]));
    _ = pipeline.stepWorker(pipeline.steerSession(session));
    _ = pipeline.stepTx();

    // Replay should NOT produce a packet at TUN egress
    try std.testing.expect(pipeline.popTx() == null);

    const stats = pipeline.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.rx_packets);
    try std.testing.expectEqual(@as(usize, 1), stats.decrypt_packets);
    try std.testing.expectEqual(@as(usize, 1), stats.replay_drops); // Correctly caught!
    try std.testing.expectEqual(@as(usize, 1), stats.tx_packets);
}

test "Pipeline: Tampered packet AEAD rejection" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x88} ** 32;

    const pipeline = try Pipeline.create(allocator, .{
        .num_workers = 2,
        .key = key,
        .enable_affinity = false,
    });
    defer pipeline.destroy(allocator);

    const plaintext = "CONFIDENTIAL PACKET";
    const session: u32 = 20;
    const counter: u64 = 1;

    var wire_buf: [MAX_PACKET_SIZE]u8 = undefined;
    const header = wire.Header{
        .kind = wire.Header.TYPE_DATA,
        .session = session,
        .counter = counter,
    };
    header.put(wire_buf[0..wire.Header.LEN]);

    const engine = AeadEngine.init(key);
    const body_len = try engine.seal(
        wire_buf[wire.Header.LEN..],
        counter,
        wire_buf[0..wire.Header.LEN],
        plaintext,
    );
    const total_wire_len = wire.Header.LEN + body_len;

    // Tamper with ciphertext byte
    wire_buf[total_wire_len - 1] ^= 0xFF;

    try std.testing.expect(pipeline.ingestRawPacket(wire_buf[0..total_wire_len]));
    _ = pipeline.stepWorker(pipeline.steerSession(session));
    _ = pipeline.stepTx();

    // Packet must be dropped due to authentication failure
    try std.testing.expect(pipeline.popTx() == null);

    const stats = pipeline.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.rx_packets);
    try std.testing.expectEqual(@as(usize, 0), stats.decrypt_packets);
    try std.testing.expectEqual(@as(usize, 1), stats.auth_fail_drops); // Correctly caught!
    try std.testing.expectEqual(@as(usize, 0), stats.tx_packets);
}

test "Pipeline: Multi-session worker distribution" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x33} ** 32;
    const num_workers: usize = 4;

    const pipeline = try Pipeline.create(allocator, .{
        .num_workers = num_workers,
        .key = key,
        .enable_affinity = false,
    });
    defer pipeline.destroy(allocator);

    const engine = AeadEngine.init(key);
    const total_packets: usize = 40;

    var i: usize = 0;
    while (i < total_packets) : (i += 1) {
        const session: u32 = @intCast(i % num_workers);
        const counter: u64 = @intCast(i + 1);
        const payload = "STREAM PACKET";

        var wire_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const header = wire.Header{
            .kind = wire.Header.TYPE_DATA,
            .session = session,
            .counter = counter,
        };
        header.put(wire_buf[0..wire.Header.LEN]);

        const body_len = try engine.seal(
            wire_buf[wire.Header.LEN..],
            counter,
            wire_buf[0..wire.Header.LEN],
            payload,
        );
        const sz = wire.Header.LEN + body_len;

        try std.testing.expect(pipeline.ingestRawPacket(wire_buf[0..sz]));
    }

    // Step all workers
    var drained: usize = 0;
    while (pipeline.stepAllWorkers() > 0) {
        drained += 1;
    }

    // Step TX
    _ = pipeline.stepTx();

    var received: usize = 0;
    while (pipeline.popTx()) |_| {
        received += 1;
    }

    try std.testing.expectEqual(total_packets, received);

    const stats = pipeline.getStats();
    try std.testing.expectEqual(total_packets, stats.rx_packets);
    try std.testing.expectEqual(total_packets, stats.decrypt_packets);
    try std.testing.expectEqual(total_packets, stats.tx_packets);
}

test "Pipeline: Multi-threaded concurrent execution" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x12} ** 32;

    const pipeline = try Pipeline.create(allocator, .{
        .num_workers = 2,
        .key = key,
        .enable_affinity = false,
    });
    defer pipeline.destroy(allocator);

    // Start background threads
    try pipeline.start();

    const engine = AeadEngine.init(key);
    const packet_count: usize = 50;

    var i: usize = 0;
    while (i < packet_count) : (i += 1) {
        const session: u32 = @intCast(i % 2);
        const counter: u64 = @intCast(i + 1);

        var wire_buf: [MAX_PACKET_SIZE]u8 = undefined;
        const header = wire.Header{
            .kind = wire.Header.TYPE_DATA,
            .session = session,
            .counter = counter,
        };
        header.put(wire_buf[0..wire.Header.LEN]);

        const body_len = try engine.seal(
            wire_buf[wire.Header.LEN..],
            counter,
            wire_buf[0..wire.Header.LEN],
            "ASYNC THREADED TEST",
        );
        const sz = wire.Header.LEN + body_len;

        // Ingest into pipeline
        while (!pipeline.ingestRawPacket(wire_buf[0..sz])) {
            std.Thread.yield() catch {};
        }
    }

    // Wait for processing to complete
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        const s = pipeline.getStats();
        if (s.tx_packets >= packet_count) break;
        std.time.sleep(5 * std.time.ns_per_ms);
    }

    pipeline.stop();

    const final_stats = pipeline.getStats();
    try std.testing.expectEqual(packet_count, final_stats.rx_packets);
    try std.testing.expectEqual(packet_count, final_stats.decrypt_packets);
    try std.testing.expectEqual(packet_count, final_stats.tx_packets);
}

test "Pipeline: GRE decapsulation end-to-end" {
    const allocator = std.testing.allocator;
    const key = [_]u8{0x99} ** 32;
    const gre_key: u32 = 0xDEADBEEF;

    const pipeline = try Pipeline.create(allocator, .{
        .num_workers = 2,
        .key = key,
        .enable_affinity = false,
        .gre_key = gre_key,
    });
    defer pipeline.destroy(allocator);

    // Inner IPv4 fake packet
    const inner_ip = [_]u8{ 0x45, 0x00, 0x00, 0x14 } ++ [_]u8{0xAA} ** 16;

    // Wrap in GRE
    const gre = GreEncap.init(gre_key);
    var gre_buf: [128]u8 = undefined;
    const gre_len = try gre.wrap(&gre_buf, &inner_ip);

    // Seal into BackPack wire packet
    const session: u32 = 5;
    const counter: u64 = 1;
    var wire_buf: [MAX_PACKET_SIZE]u8 = undefined;
    const header = wire.Header{
        .kind = wire.Header.TYPE_DATA,
        .session = session,
        .counter = counter,
    };
    header.put(wire_buf[0..wire.Header.LEN]);

    const engine = AeadEngine.init(key);
    const body_len = try engine.seal(
        wire_buf[wire.Header.LEN..],
        counter,
        wire_buf[0..wire.Header.LEN],
        gre_buf[0..gre_len],
    );
    const sz = wire.Header.LEN + body_len;

    // Ingest into pipeline
    try std.testing.expect(pipeline.ingestRawPacket(wire_buf[0..sz]));

    // Step Worker and TX
    _ = pipeline.stepWorker(pipeline.steerSession(session));
    _ = pipeline.stepTx();

    // Verify unwrap to original inner IP packet
    const out_pkt = pipeline.popTx();
    try std.testing.expect(out_pkt != null);
    try std.testing.expectEqualSlices(u8, &inner_ip, out_pkt.?.slice());
}
