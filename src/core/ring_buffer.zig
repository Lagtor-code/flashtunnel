const std = @import("std");

/// High-performance Lock-Free Single-Producer Single-Consumer (SPSC) Ring Buffer.
/// Used to pass packet pointers between I/O thread and worker threads without mutex contention.
pub fn SpscQueue(comptime T: type, comptime CAPACITY: usize) type {
    comptime {
        std.debug.assert(std.math.isPowerOfTwo(CAPACITY));
    }

    return struct {
        const Self = @This();
        const MASK = CAPACITY - 1;

        // Separate cache lines to prevent false sharing between producer and consumer
        head: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
        tail: std.atomic.Value(usize) align(64) = std.atomic.Value(usize).init(0),
        buffer: [CAPACITY]T align(64) = undefined,

        pub fn init() Self {
            return .{};
        }

        /// Pushes an item into the queue.
        /// Returns true on success, false if full.
        pub fn push(self: *Self, item: T) bool {
            const current_tail = self.tail.load(.monotonic);
            const current_head = self.head.load(.acquire);

            if (current_tail - current_head >= CAPACITY) {
                return false; // Queue is full
            }

            self.buffer[current_tail & MASK] = item;
            self.tail.store(current_tail + 1, .release);
            return true;
        }

        /// Pops an item from the queue.
        /// Returns the item or null if empty.
        pub fn pop(self: *Self) ?T {
            const current_head = self.head.load(.monotonic);
            const current_tail = self.tail.load(.acquire);

            if (current_head == current_tail) {
                return null; // Queue is empty
            }

            const item = self.buffer[current_head & MASK];
            self.head.store(current_head + 1, .release);
            return item;
        }

        pub inline fn isEmpty(self: *const Self) bool {
            return self.head.load(.monotonic) == self.tail.load(.monotonic);
        }

        pub inline fn count(self: *const Self) usize {
            const t = self.tail.load(.monotonic);
            const h = self.head.load(.monotonic);
            return t - h;
        }
    };
}

test "SpscQueue push and pop" {
    var q = SpscQueue(u32, 8).init();

    try std.testing.expect(q.isEmpty());
    try std.testing.expect(q.push(10));
    try std.testing.expect(q.push(20));
    try std.testing.expectEqual(@as(usize, 2), q.count());

    try std.testing.expectEqual(@as(?u32, 10), q.pop());
    try std.testing.expectEqual(@as(?u32, 20), q.pop());
    try std.testing.expectEqual(@as(?u32, null), q.pop());
}
