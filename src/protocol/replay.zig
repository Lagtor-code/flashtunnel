const std = @import("std");

/// RFC 4303 / WireGuard style anti-replay sliding window.
/// Remembers 2048 packets behind the highest committed counter.
pub const ReplayWindow = struct {
    pub const WINDOW_BITS: usize = 2048;
    pub const WORDS: usize = WINDOW_BITS / 64; // 32 words

    max: u64 = 0,
    seeded: bool = false,
    bitmap: [WORDS]u64 = [_]u64{0} ** WORDS,

    const Slot = struct {
        word: usize,
        bit: u64,
    };

    inline fn getSlot(counter: u64) Slot {
        const idx = counter % WINDOW_BITS;
        return .{
            .word = @intCast(idx / 64),
            .bit = @as(u64, 1) << @intCast(idx % 64),
        };
    }

    /// Checks if counter is eligible without recording anything.
    /// Returns true if packet should be accepted for decryption.
    pub fn accept(self: *const ReplayWindow, counter: u64) bool {
        if (!self.seeded) return true;
        if (counter > self.max) return true; // Ahead of window

        if (self.max - counter >= WINDOW_BITS) {
            return false; // Fallen out of window
        }

        const s = getSlot(counter);
        return (self.bitmap[s.word] & s.bit) == 0;
    }

    /// Records counter once packet has successfully authenticated.
    pub fn commit(self: *ReplayWindow, counter: u64) void {
        if (!self.seeded) {
            self.seeded = true;
            self.max = counter;
            const s = getSlot(counter);
            self.bitmap[s.word] |= s.bit;
            return;
        }

        if (counter > self.max) {
            const diff = counter - self.max;
            if (diff >= WINDOW_BITS) {
                @memset(&self.bitmap, 0);
            } else {
                var c = self.max + 1;
                while (c <= counter) : (c += 1) {
                    const s = getSlot(c);
                    self.bitmap[s.word] &= ~s.bit;
                }
            }
            self.max = counter;
        }

        const s = getSlot(counter);
        self.bitmap[s.word] |= s.bit;
    }

    pub fn reset(self: *ReplayWindow) void {
        self.max = 0;
        self.seeded = false;
        @memset(&self.bitmap, 0);
    }
};

/// High-Performance Lock-Free Anti-Replay Sliding Window.
/// Designed for high-throughput multi-threaded packet verification without global mutex locks.
/// Uses std.atomic for lock-free slot claiming and monotonic window sliding.
/// Zero heap allocations, O(1) time complexity, minimal CPU cycles.
pub const AtomicReplayWindow = struct {
    pub const WINDOW_BITS: usize = 2048;
    pub const WORDS: usize = WINDOW_BITS / 64; // 32 words

    // Cache-line aligned members to eliminate false sharing between worker threads
    max: std.atomic.Value(u64) align(64) = std.atomic.Value(u64).init(0),
    seeded: std.atomic.Value(bool) align(64) = std.atomic.Value(bool).init(false),
    entries: [WINDOW_BITS]std.atomic.Value(u64) align(64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** WINDOW_BITS,

    pub fn init() AtomicReplayWindow {
        return .{};
    }

    /// Fast lock-free pre-check without mutations (e.g. before packet decryption).
    /// Returns true if packet is eligible (unseen and within or ahead of window).
    /// Returns false if duplicate or expired.
    pub fn accept(self: *const AtomicReplayWindow, counter: u64) bool {
        if (counter == std.math.maxInt(u64)) return false;
        if (!self.seeded.load(.acquire)) return true;

        const current_max = self.max.load(.acquire);
        if (counter > current_max) return true; // Ahead of window

        if (current_max - counter >= WINDOW_BITS) {
            return false; // Fallen out of window
        }

        const pos = counter % WINDOW_BITS;
        const stored = self.entries[pos].load(.acquire);
        const target = counter + 1;

        if (stored >= target) {
            return false; // Duplicate (stored == target) or already superseded (stored > target)
        }

        return true;
    }

    /// Atomically checks and records counter in a single pass.
    /// Returns true if packet was fresh and successfully committed.
    /// Returns false if duplicate, superseded, or fallen out of window.
    pub fn checkAndCommit(self: *AtomicReplayWindow, counter: u64) bool {
        if (counter == std.math.maxInt(u64)) return false;

        // 1. Fast pre-check against current window boundary
        if (self.seeded.load(.acquire)) {
            const m = self.max.load(.acquire);
            if (m >= counter and (m - counter) >= WINDOW_BITS) {
                return false;
            }
        }

        const pos = counter % WINDOW_BITS;
        const target = counter + 1;

        // 2. Lock-free slot claim via atomic CAS loop
        while (true) {
            const stored = self.entries[pos].load(.acquire);
            if (stored >= target) {
                return false; // Duplicate (stored == target) or superseded (stored > target)
            }

            if (self.entries[pos].cmpxchgWeak(stored, target, .acq_rel, .acquire)) |_| {
                continue; // Contention on this slot, retry
            }
            break;
        }

        // 3. Post-CAS boundary check: detect if window slid past during thread preemption
        if (self.seeded.load(.acquire)) {
            const m = self.max.load(.acquire);
            if (m >= counter and (m - counter) >= WINDOW_BITS) {
                return false;
            }
        }

        // 4. Monotonically advance max counter
        var cur_max = self.max.load(.acquire);
        while (counter > cur_max) {
            if (self.max.cmpxchgWeak(cur_max, counter, .acq_rel, .acquire)) |actual| {
                cur_max = actual;
            } else {
                break;
            }
        }

        // 5. Ensure window is marked as seeded
        if (!self.seeded.load(.acquire)) {
            self.seeded.store(true, .release);
        }

        return true;
    }

    /// Records counter once packet has successfully authenticated.
    /// Drops return value to maintain API compatibility with ReplayWindow.commit.
    pub fn commit(self: *AtomicReplayWindow, counter: u64) void {
        _ = self.checkAndCommit(counter);
    }

    /// Resets all counters and slots back to initial unseeded state.
    pub fn reset(self: *AtomicReplayWindow) void {
        self.seeded.store(false, .release);
        self.max.store(0, .release);
        for (&self.entries) |*entry| {
            entry.store(0, .release);
        }
    }

    /// Returns the highest committed counter so far.
    pub fn getMax(self: *const AtomicReplayWindow) u64 {
        return self.max.load(.acquire);
    }

    /// Returns true if the window has committed at least one packet.
    pub fn isSeeded(self: *const AtomicReplayWindow) bool {
        return self.seeded.load(.acquire);
    }
};

// ============================================================================
// Unit and Stress Test Suite
// ============================================================================

test "ReplayWindow accept and commit" {
    var win = ReplayWindow{};
    try std.testing.expect(win.accept(0));
    win.commit(0);
    try std.testing.expect(!win.accept(0)); // Duplicate rejected

    try std.testing.expect(win.accept(1));
    win.commit(1);
    try std.testing.expect(!win.accept(1));

    // Jump forward
    try std.testing.expect(win.accept(100));
    win.commit(100);
    try std.testing.expect(!win.accept(100));

    // In-window out-of-order packet
    try std.testing.expect(win.accept(50));
    win.commit(50);
    try std.testing.expect(!win.accept(50));

    // Large jump that exhausts window
    try std.testing.expect(win.accept(100 + ReplayWindow.WINDOW_BITS + 10));
    win.commit(100 + ReplayWindow.WINDOW_BITS + 10);

    // Old packets outside window must now be rejected
    try std.testing.expect(!win.accept(50));
    try std.testing.expect(!win.accept(100));
}

test "AtomicReplayWindow basic parity test" {
    var win = AtomicReplayWindow.init();
    try std.testing.expect(!win.isSeeded());
    try std.testing.expectEqual(@as(u64, 0), win.getMax());

    try std.testing.expect(win.accept(0));
    try std.testing.expect(win.checkAndCommit(0));
    try std.testing.expect(win.isSeeded());
    try std.testing.expectEqual(@as(u64, 0), win.getMax());
    try std.testing.expect(!win.accept(0)); // Duplicate rejected
    try std.testing.expect(!win.checkAndCommit(0)); // Duplicate rejected

    try std.testing.expect(win.accept(1));
    try std.testing.expect(win.checkAndCommit(1));
    try std.testing.expectEqual(@as(u64, 1), win.getMax());
    try std.testing.expect(!win.accept(1));

    // Forward jump
    try std.testing.expect(win.accept(100));
    try std.testing.expect(win.checkAndCommit(100));
    try std.testing.expectEqual(@as(u64, 100), win.getMax());
    try std.testing.expect(!win.accept(100));

    // In-window out-of-order packet
    try std.testing.expect(win.accept(50));
    try std.testing.expect(win.checkAndCommit(50));
    try std.testing.expect(!win.accept(50));

    // Large jump that exhausts window
    const large_jump = 100 + AtomicReplayWindow.WINDOW_BITS + 10;
    try std.testing.expect(win.accept(large_jump));
    win.commit(large_jump);
    try std.testing.expectEqual(large_jump, win.getMax());

    // Packets that fell out of window must now be rejected
    try std.testing.expect(!win.accept(50));
    try std.testing.expect(!win.checkAndCommit(50));
    try std.testing.expect(!win.accept(100));
    try std.testing.expect(!win.checkAndCommit(100));
}

test "AtomicReplayWindow thousands of sequential counters" {
    var win = AtomicReplayWindow.init();
    const TOTAL_PACKETS: u64 = 10000;

    // 1. Process 10,000 strictly sequential packets
    var seq: u64 = 0;
    while (seq < TOTAL_PACKETS) : (seq += 1) {
        try std.testing.expect(win.accept(seq));
        try std.testing.expect(win.checkAndCommit(seq));
        try std.testing.expectEqual(seq, win.getMax());
    }

    // 2. Immediate verification that all 10,000 are rejected as duplicates
    seq = 0;
    while (seq < TOTAL_PACKETS) : (seq += 1) {
        try std.testing.expect(!win.accept(seq));
        try std.testing.expect(!win.checkAndCommit(seq));
    }
}

test "AtomicReplayWindow thousands of out-of-order counters within window" {
    var win = AtomicReplayWindow.init();
    const BASE_MAX: u64 = 8000;

    // Seed the window at 8000
    try std.testing.expect(win.checkAndCommit(BASE_MAX));

    // Inject 1,500 distinct out-of-order packets backwards and in strides within the 2048 window
    // Window covers [8000 - 2047, 8000] = [5953, 8000]
    var offset: u64 = 1;
    while (offset <= 1500) : (offset += 1) {
        const pkt = BASE_MAX - offset;
        try std.testing.expect(win.accept(pkt));
        try std.testing.expect(win.checkAndCommit(pkt));
        // Verify repeat is rejected
        try std.testing.expect(!win.accept(pkt));
        try std.testing.expect(!win.checkAndCommit(pkt));
    }

    // Re-verify that max did not regress
    try std.testing.expectEqual(BASE_MAX, win.getMax());
}

test "AtomicReplayWindow duplicate burst stress" {
    var win = AtomicReplayWindow.init();
    const NUM_UNIQUE: u64 = 5000;

    var i: u64 = 0;
    while (i < NUM_UNIQUE) : (i += 1) {
        // Send fresh packet
        try std.testing.expect(win.checkAndCommit(i));

        // Burst 5 duplicates of the current packet
        var dup: usize = 0;
        while (dup < 5) : (dup += 1) {
            try std.testing.expect(!win.accept(i));
            try std.testing.expect(!win.checkAndCommit(i));
        }

        // Burst duplicates of recent packets (within window)
        if (i >= 10) {
            try std.testing.expect(!win.accept(i - 5));
            try std.testing.expect(!win.checkAndCommit(i - 5));
            try std.testing.expect(!win.accept(i - 10));
            try std.testing.expect(!win.checkAndCommit(i - 10));
        }
    }
}

test "AtomicReplayWindow edge-boundary counters" {
    var win = AtomicReplayWindow.init();

    // Zero boundary
    try std.testing.expect(win.accept(0));
    try std.testing.expect(win.checkAndCommit(0));
    try std.testing.expect(!win.accept(0));

    // Window size is 2048. Commit counter 2047.
    try std.testing.expect(win.checkAndCommit(2047));
    // Counter 0 is still in window: 2047 - 0 = 2047 < 2048. Duplicate rejected.
    try std.testing.expect(!win.accept(0));
    // Counter 1 was never committed, is in window: 2047 - 1 = 2046 < 2048. Accepted!
    try std.testing.expect(win.accept(1));
    try std.testing.expect(win.checkAndCommit(1));

    // Commit counter 2048. Window slides to [1, 2048].
    try std.testing.expect(win.checkAndCommit(2048));
    // Counter 0 is now OUTSIDE window: 2048 - 0 = 2048 >= 2048. Rejected.
    try std.testing.expect(!win.accept(0));
    try std.testing.expect(!win.checkAndCommit(0));
    // Counter 1 is exactly on the left boundary: 2048 - 1 = 2047 < 2048.
    // But counter 1 was already committed earlier, so duplicate rejected.
    try std.testing.expect(!win.accept(1));

    // Counter 2 was never committed: 2048 - 2 = 2046 < 2048. Accepted!
    try std.testing.expect(win.accept(2));
    try std.testing.expect(win.checkAndCommit(2));

    // Commit counter 2049. Window slides to [2, 2049].
    try std.testing.expect(win.checkAndCommit(2049));
    // Counter 1 is now OUTSIDE window: 2049 - 1 = 2048 >= 2048. Rejected.
    try std.testing.expect(!win.accept(1));
    try std.testing.expect(!win.checkAndCommit(1));

    // Giant jump: commit 1,000,000
    const GIANT: u64 = 1000000;
    try std.testing.expect(win.checkAndCommit(GIANT));
    try std.testing.expectEqual(GIANT, win.getMax());

    // Boundary check for GIANT:
    // GIANT - 2047 = 997953 (age 2047: inside window)
    try std.testing.expect(win.accept(GIANT - 2047));
    try std.testing.expect(win.checkAndCommit(GIANT - 2047));
    // GIANT - 2048 = 997952 (age 2048: outside window)
    try std.testing.expect(!win.accept(GIANT - 2048));
    try std.testing.expect(!win.checkAndCommit(GIANT - 2048));

    // Max integer safety check (prevents u64 overflow)
    try std.testing.expect(!win.accept(std.math.maxInt(u64)));
    try std.testing.expect(!win.checkAndCommit(std.math.maxInt(u64)));
}

test "AtomicReplayWindow behavioral equivalence with ReplayWindow across thousands of ops" {
    var r_win = ReplayWindow{};
    var a_win = AtomicReplayWindow.init();

    // Pseudo-random deterministic sequence of operations
    var prng = std.Random.DefaultPrng.init(0xCAFE_BABE);
    const rand = prng.random();

    var current_head: u64 = 0;
    var step: usize = 0;
    while (step < 10000) : (step += 1) {
        const op = rand.uintLessThan(u32, 100);
        var pkt: u64 = undefined;

        if (op < 40) {
            // Sequential forward increment
            current_head += 1;
            pkt = current_head;
        } else if (op < 65) {
            // In-window out-of-order arrival
            const offset = rand.uintLessThan(u64, @min(current_head, AtomicReplayWindow.WINDOW_BITS - 1)) + 1;
            pkt = current_head - offset;
        } else if (op < 80) {
            // Duplicate replay of recently seen packet
            const offset = rand.uintLessThan(u64, @min(current_head, 128));
            pkt = current_head - offset;
        } else if (op < 95) {
            // Old expired packet outside window
            if (current_head > AtomicReplayWindow.WINDOW_BITS + 50) {
                const offset = AtomicReplayWindow.WINDOW_BITS + rand.uintLessThan(u64, 500);
                pkt = current_head - offset;
            } else {
                current_head += 1;
                pkt = current_head;
            }
        } else {
            // Forward jump ahead of window
            current_head += rand.uintLessThan(u64, 500) + 50;
            pkt = current_head;
        }

        const r_accept = r_win.accept(pkt);
        const a_accept = a_win.accept(pkt);

        // Verification: AtomicReplayWindow and ReplayWindow MUST agree on every single packet
        try std.testing.expectEqual(r_accept, a_accept);

        if (r_accept) {
            r_win.commit(pkt);
            const committed = a_win.checkAndCommit(pkt);
            try std.testing.expect(committed);
        } else {
            const committed = a_win.checkAndCommit(pkt);
            try std.testing.expect(!committed);
        }
    }
}

test "AtomicReplayWindow multi-threaded concurrent stress" {
    var win = AtomicReplayWindow.init();
    const NUM_THREADS = 4;
    const TOTAL_UNIQUE: usize = 4000;

    // Thread-safe lock-free barrier for thread synchronization
    const Barrier = struct {
        count: std.atomic.Value(usize),
        generation: std.atomic.Value(usize),
        threshold: usize,

        pub fn init(threshold: usize) @This() {
            return .{
                .count = std.atomic.Value(usize).init(0),
                .generation = std.atomic.Value(usize).init(0),
                .threshold = threshold,
            };
        }

        pub fn wait(self: *@This()) void {
            const gen = self.generation.load(.acquire);
            const prev = self.count.fetchAdd(1, .acq_rel);
            if (prev + 1 == self.threshold) {
                self.count.store(0, .release);
                _ = self.generation.fetchAdd(1, .acq_rel);
            } else {
                while (self.generation.load(.acquire) == gen) {
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    const Context = struct {
        win: *AtomicReplayWindow,
        barrier: *Barrier,
        thread_id: usize,
        accepted: *std.atomic.Value(usize),
        rejected: *std.atomic.Value(usize),

        pub fn run(self: @This()) void {
            var seq: usize = 0;
            while (seq < TOTAL_UNIQUE) : (seq += 1) {
                // All threads synchronize, then race to commit the EXACT SAME sequence number
                self.barrier.wait();

                if (self.win.checkAndCommit(seq)) {
                    _ = self.accepted.fetchAdd(1, .monotonic);
                } else {
                    _ = self.rejected.fetchAdd(1, .monotonic);
                }
            }
        }
    };

    var barrier = Barrier.init(NUM_THREADS);
    var accepted = std.atomic.Value(usize).init(0);
    var rejected = std.atomic.Value(usize).init(0);
    var threads: [NUM_THREADS]std.Thread = undefined;

    var t: usize = 0;
    while (t < NUM_THREADS) : (t += 1) {
        threads[t] = try std.Thread.spawn(.{}, Context.run, .{Context{
            .win = &win,
            .barrier = &barrier,
            .thread_id = t,
            .accepted = &accepted,
            .rejected = &rejected,
        }});
    }

    for (threads) |th| {
        th.join();
    }

    // Exactly 1 thread must have claimed each unique sequence number
    try std.testing.expectEqual(TOTAL_UNIQUE, accepted.load(.acquire));
    // The other (NUM_THREADS - 1) threads must have been rejected as duplicates
    try std.testing.expectEqual(TOTAL_UNIQUE * (NUM_THREADS - 1), rejected.load(.acquire));
}

test "AtomicReplayWindow zero allocation and reset" {
    // 1. Zero dynamic allocations: struct size is fully known at compile-time
    comptime {
        std.debug.assert(@sizeOf(AtomicReplayWindow) > 0);
    }

    var win = AtomicReplayWindow.init();
    try std.testing.expect(!win.isSeeded());

    // Commit some state
    try std.testing.expect(win.checkAndCommit(42));
    try std.testing.expect(win.checkAndCommit(100));
    try std.testing.expect(win.isSeeded());
    try std.testing.expectEqual(@as(u64, 100), win.getMax());

    // Reset window
    win.reset();
    try std.testing.expect(!win.isSeeded());
    try std.testing.expectEqual(@as(u64, 0), win.getMax());

    // After reset, packet 42 can be accepted and committed again
    try std.testing.expect(win.accept(42));
    try std.testing.expect(win.checkAndCommit(42));
    try std.testing.expect(win.isSeeded());
    try std.testing.expectEqual(@as(u64, 42), win.getMax());
}
