const std = @import("std");

/// FastMux: Ultra-lightweight binary stream multiplexer for TCP streams.
/// Designed as a high-performance zero-GC replacement for Go's smux.
///
/// Compact 8-byte Frame Header:
/// 0                    4          6          8
/// +--------------------+----------+----------+
/// |    stream_id       | flags/cmd|  length  |
/// |    (uint32BE)      | (uint16) | (uint16) |
/// +--------------------+----------+----------+
///
/// Followed immediately by `length` bytes of payload data on the wire.
pub const Header = extern struct {
    stream_id: u32,
    cmd: u16,
    length: u16,

    pub const LEN: usize = 8;

    // Commands and flags (u16)
    pub const CMD_SYN: u16 = 1 << 0;  // 0x0001
    pub const CMD_ACK: u16 = 1 << 1;  // 0x0002
    pub const CMD_FIN: u16 = 1 << 2;  // 0x0004
    pub const CMD_DATA: u16 = 1 << 3; // 0x0008
    pub const CMD_PING: u16 = 1 << 4; // 0x0010

    // Aliases directly matching prompt: flags/cmd (u16: SYN, ACK, FIN, DATA, PING)
    pub const SYN: u16 = CMD_SYN;
    pub const ACK: u16 = CMD_ACK;
    pub const FIN: u16 = CMD_FIN;
    pub const DATA: u16 = CMD_DATA;
    pub const PING: u16 = CMD_PING;

    pub const FLAG_SYN: u16 = CMD_SYN;
    pub const FLAG_ACK: u16 = CMD_ACK;
    pub const FLAG_FIN: u16 = CMD_FIN;
    pub const FLAG_DATA: u16 = CMD_DATA;
    pub const FLAG_PING: u16 = CMD_PING;

    /// Serializes the 8-byte header into `dst` in big-endian byte order.
    pub fn pack(self: Header, dst: []u8) void {
        std.debug.assert(dst.len >= LEN);
        std.mem.writeInt(u32, dst[0..4], self.stream_id, .big);
        std.mem.writeInt(u16, dst[4..6], self.cmd, .big);
        std.mem.writeInt(u16, dst[6..8], self.length, .big);
    }

    /// Serializes into an 8-byte array.
    pub fn toBytes(self: Header) [LEN]u8 {
        var buf: [LEN]u8 = undefined;
        self.pack(&buf);
        return buf;
    }

    /// Unpacks an 8-byte header from `buf`.
    pub fn unpack(buf: []const u8) error{BufferTooShort}!Header {
        if (buf.len < LEN) return error.BufferTooShort;
        return Header{
            .stream_id = std.mem.readInt(u32, buf[0..4], .big),
            .cmd = std.mem.readInt(u16, buf[4..6], .big),
            .length = std.mem.readInt(u16, buf[6..8], .big),
        };
    }

    pub inline fn flags(self: Header) u16 {
        return self.cmd;
    }

    pub inline fn isSyn(self: Header) bool {
        return (self.cmd & FLAG_SYN) != 0;
    }

    pub inline fn isAck(self: Header) bool {
        return (self.cmd & FLAG_ACK) != 0;
    }

    pub inline fn isFin(self: Header) bool {
        return (self.cmd & FLAG_FIN) != 0;
    }

    pub inline fn isData(self: Header) bool {
        return (self.cmd & FLAG_DATA) != 0;
    }

    pub inline fn isPing(self: Header) bool {
        return (self.cmd & FLAG_PING) != 0;
    }
};

/// A complete multiplexer frame containing an 8-byte header and optional payload.
pub const Frame = struct {
    header: Header,
    payload: []const u8 = &[_]u8{},

    pub inline fn totalLen(self: Frame) usize {
        return Header.LEN + self.payload.len;
    }

    /// Packs header and payload into destination buffer.
    pub fn pack(self: Frame, dst: []u8) error{BufferTooSmall}!usize {
        const total = self.totalLen();
        if (dst.len < total) return error.BufferTooSmall;
        self.header.pack(dst[0..Header.LEN]);
        if (self.payload.len > 0) {
            @memcpy(dst[Header.LEN..total], self.payload);
        }
        return total;
    }

    /// Unpacks a frame from a raw byte slice.
    pub fn unpack(buf: []const u8) error{ BufferTooShort, IncompleteFrame }!Frame {
        if (buf.len < Header.LEN) return error.BufferTooShort;
        const hdr = try Header.unpack(buf[0..Header.LEN]);
        const total = Header.LEN + @as(usize, hdr.length);
        if (buf.len < total) return error.IncompleteFrame;
        return Frame{
            .header = hdr,
            .payload = buf[Header.LEN..total],
        };
    }
};

/// Credit-based flow control window tracker.
/// Prevents sender from overwhelming receiver buffers.
pub const FlowControl = struct {
    initial_window: u32,
    max_window: u32,
    send_window: u32,
    recv_window: u32,
    consumed_unacked: u32,

    pub const DEFAULT_INITIAL_WINDOW: u32 = 256 * 1024; // 256 KB
    pub const DEFAULT_MAX_WINDOW: u32 = 16 * 1024 * 1024; // 16 MB

    pub fn init(initial_window: u32, max_window: u32) FlowControl {
        return .{
            .initial_window = initial_window,
            .max_window = max_window,
            .send_window = initial_window,
            .recv_window = initial_window,
            .consumed_unacked = 0,
        };
    }

    pub inline fn availableSend(self: *const FlowControl) u32 {
        return self.send_window;
    }

    pub inline fn availableRecv(self: *const FlowControl) u32 {
        return self.recv_window;
    }

    pub inline fn canSend(self: *const FlowControl, bytes: usize) bool {
        return self.send_window >= bytes;
    }

    /// Consumes send credit when transmitting DATA.
    pub fn consumeSend(self: *FlowControl, bytes: usize) error{WindowExhausted}!void {
        if (bytes > self.send_window) {
            return error.WindowExhausted;
        }
        self.send_window -= @intCast(bytes);
    }

    /// Adds send credit replenished by remote peer via ACK.
    pub fn addSendCredit(self: *FlowControl, credit: u32) void {
        const new_win = @as(u64, self.send_window) + credit;
        self.send_window = @intCast(@min(new_win, self.max_window));
    }

    /// Consumes receive credit when inbound DATA arrives from peer.
    pub fn consumeRecv(self: *FlowControl, bytes: usize) error{WindowOverflow}!void {
        if (bytes > self.recv_window) {
            return error.WindowOverflow;
        }
        self.recv_window -= @intCast(bytes);
    }

    /// Records bytes read by consumer from stream receive buffer.
    pub fn recordConsumed(self: *FlowControl, bytes: usize) void {
        self.consumed_unacked += @intCast(bytes);
    }

    /// Checks if threshold of consumed bytes warrants sending an ACK frame.
    pub fn shouldAck(self: *const FlowControl, threshold: u32) bool {
        return self.consumed_unacked >= threshold;
    }

    /// Claims accumulated unacknowledged bytes to transmit in an ACK frame,
    /// replenishing the local receive window.
    pub fn claimAckCredit(self: *FlowControl) u32 {
        const credit = self.consumed_unacked;
        self.consumed_unacked = 0;
        const new_win = @as(u64, self.recv_window) + credit;
        self.recv_window = @intCast(@min(new_win, self.max_window));
        return credit;
    }
};

/// Lifecycle state for an individual multiplexed stream.
pub const StreamState = enum {
    Idle,
    SynSent,
    SynReceived,
    Established,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
};

pub const WriteResult = struct {
    bytes_consumed: usize,
    frame_len: usize,
};

/// An individual bidirectional multiplexed stream over the shared connection.
pub const Stream = struct {
    id: u32,
    state: StreamState,
    flow_control: FlowControl,
    recv_buf: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, id: u32, initial_window: u32, max_window: u32) Stream {
        return .{
            .id = id,
            .state = .Idle,
            .flow_control = FlowControl.init(initial_window, max_window),
            .recv_buf = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.recv_buf.deinit();
    }

    /// Reads up to `dst.len` bytes from the stream's inbound buffer.
    /// Automatically tracks consumed bytes for flow control credit replenishment.
    pub fn read(self: *Stream, dst: []u8) usize {
        if (self.recv_buf.items.len == 0) return 0;
        const n = @min(dst.len, self.recv_buf.items.len);
        @memcpy(dst[0..n], self.recv_buf.items[0..n]);
        const remaining = self.recv_buf.items.len - n;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.recv_buf.items[0..remaining], self.recv_buf.items[n..]);
        }
        self.recv_buf.shrinkRetainingCapacity(remaining);
        self.flow_control.recordConsumed(n);
        return n;
    }

    /// Pushes incoming payload bytes received from the wire into this stream's buffer.
    pub fn pushIncomingData(self: *Stream, data: []const u8) !void {
        if (self.state == .Closed or self.state == .HalfClosedRemote) {
            return error.StreamClosed;
        }
        try self.flow_control.consumeRecv(data.len);
        try self.recv_buf.appendSlice(data);
    }

    /// Formats a single DATA frame containing as much of `data` as send credit and `max_frame_payload` allow.
    pub fn formatDataFrame(
        self: *Stream,
        data: []const u8,
        max_frame_payload: u16,
        dst: []u8,
    ) error{ BufferTooSmall, WindowExhausted, StreamClosed }!WriteResult {
        if (self.state == .Closed or self.state == .HalfClosedLocal) {
            return error.StreamClosed;
        }
        const max_send = self.flow_control.availableSend();
        if (max_send == 0) {
            return error.WindowExhausted;
        }

        const chunk_size: usize = @min(data.len, @as(usize, max_send), @as(usize, max_frame_payload));
        if (chunk_size == 0) return .{ .bytes_consumed = 0, .frame_len = 0 };

        const total_frame_len = Header.LEN + chunk_size;
        if (dst.len < total_frame_len) return error.BufferTooSmall;

        const hdr = Header{
            .stream_id = self.id,
            .cmd = Header.CMD_DATA,
            .length = @intCast(chunk_size),
        };
        hdr.pack(dst[0..Header.LEN]);
        @memcpy(dst[Header.LEN..total_frame_len], data[0..chunk_size]);

        try self.flow_control.consumeSend(chunk_size);
        return .{
            .bytes_consumed = chunk_size,
            .frame_len = total_frame_len,
        };
    }
};

/// Incremental frame parser that handles fragmented TCP stream chunks.
pub const FrameParser = struct {
    buf: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) FrameParser {
        return .{ .buf = std.ArrayList(u8).init(allocator) };
    }

    pub fn deinit(self: *FrameParser) void {
        self.buf.deinit();
    }

    pub fn append(self: *FrameParser, data: []const u8) !void {
        try self.buf.appendSlice(data);
    }

    /// Peeks at the next complete frame in the buffer without consuming it.
    pub fn peek(self: *const FrameParser) error{ IncompleteFrame, BufferTooShort }!Frame {
        if (self.buf.items.len < Header.LEN) return error.BufferTooShort;
        const hdr = try Header.unpack(self.buf.items[0..Header.LEN]);
        const total = Header.LEN + @as(usize, hdr.length);
        if (self.buf.items.len < total) return error.IncompleteFrame;
        return Frame{
            .header = hdr,
            .payload = self.buf.items[Header.LEN..total],
        };
    }

    /// Consumes `n` bytes from the front of the parser buffer.
    pub fn consume(self: *FrameParser, n: usize) void {
        std.debug.assert(self.buf.items.len >= n);
        const remaining = self.buf.items.len - n;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.buf.items[0..remaining], self.buf.items[n..]);
        }
        self.buf.shrinkRetainingCapacity(remaining);
    }

    /// Extracts the next complete frame if available.
    pub fn next(self: *FrameParser) error{ IncompleteFrame, BufferTooShort }!Frame {
        return self.peek();
    }
};

/// FastMux Session: Multiplexes multiple bidirectional streams over a single byte stream.
pub const FastMux = struct {
    allocator: std.mem.Allocator,
    is_server: bool,
    config: Config,
    next_stream_id: u32,
    streams: std.AutoHashMap(u32, *Stream),
    accept_queue: std.ArrayList(u32),
    parser: FrameParser,

    pub const Config = struct {
        initial_window_size: u32 = 256 * 1024,
        max_window_size: u32 = 16 * 1024 * 1024,
        max_frame_size: u16 = 16384,
        ack_threshold: u32 = 32 * 1024,
    };

    pub fn init(allocator: std.mem.Allocator, is_server: bool, config: Config) FastMux {
        return .{
            .allocator = allocator,
            .is_server = is_server,
            .config = config,
            .next_stream_id = if (is_server) 2 else 1,
            .streams = std.AutoHashMap(u32, *Stream).init(allocator),
            .accept_queue = std.ArrayList(u32).init(allocator),
            .parser = FrameParser.init(allocator),
        };
    }

    pub fn deinit(self: *FastMux) void {
        var it = self.streams.valueIterator();
        while (it.next()) |stream_ptr| {
            stream_ptr.*.deinit();
            self.allocator.destroy(stream_ptr.*);
        }
        self.streams.deinit();
        self.accept_queue.deinit();
        self.parser.deinit();
    }

    /// Opens a new outgoing stream and increments the stream ID sequence.
    pub fn openStream(self: *FastMux) !*Stream {
        const id = self.next_stream_id;
        self.next_stream_id += 2;

        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(self.allocator, id, self.config.initial_window_size, self.config.max_window_size);
        stream.state = .SynSent;
        try self.streams.put(id, stream);
        return stream;
    }

    /// Retrieves an existing stream by ID.
    pub fn getStream(self: *FastMux, id: u32) ?*Stream {
        return self.streams.get(id);
    }

    /// Accepts an incoming stream opened by the peer (via SYN).
    pub fn acceptStream(self: *FastMux) ?*Stream {
        if (self.accept_queue.items.len == 0) return null;
        const id = self.accept_queue.orderedRemove(0);
        return self.streams.get(id);
    }

    /// Ingests raw bytes from the underlying transport byte stream.
    /// Decodes complete frames and updates stream state and flow control.
    pub fn feed(self: *FastMux, data: []const u8) !usize {
        try self.parser.append(data);
        var frames_processed: usize = 0;

        while (true) {
            const frame = self.parser.peek() catch |err| switch (err) {
                error.BufferTooShort, error.IncompleteFrame => break,
            };

            const stream_id = frame.header.stream_id;

            if (frame.header.isSyn()) {
                if (!self.streams.contains(stream_id)) {
                    const stream = try self.allocator.create(Stream);
                    stream.* = Stream.init(self.allocator, stream_id, self.config.initial_window_size, self.config.max_window_size);
                    stream.state = .Established;
                    try self.streams.put(stream_id, stream);
                    try self.accept_queue.append(stream_id);
                }
            } else if (frame.header.isData()) {
                if (self.streams.get(stream_id)) |stream| {
                    try stream.pushIncomingData(frame.payload);
                }
            } else if (frame.header.isAck()) {
                if (self.streams.get(stream_id)) |stream| {
                    if (frame.payload.len >= 4) {
                        const credit = std.mem.readInt(u32, frame.payload[0..4], .big);
                        stream.flow_control.addSendCredit(credit);
                    }
                    if (stream.state == .SynSent) {
                        stream.state = .Established;
                    }
                }
            } else if (frame.header.isFin()) {
                if (self.streams.get(stream_id)) |stream| {
                    if (stream.state == .HalfClosedLocal) {
                        stream.state = .Closed;
                    } else {
                        stream.state = .HalfClosedRemote;
                    }
                }
            }

            self.parser.consume(frame.totalLen());
            frames_processed += 1;
        }

        return frames_processed;
    }

    /// Formats a SYN frame for an opened stream into `dst`.
    pub fn writeSyn(_: *FastMux, stream_id: u32, dst: []u8) error{BufferTooSmall}!usize {
        return formatSynFrame(stream_id, dst);
    }

    /// Formats an ACK frame with flow control credit for `stream` into `dst`.
    /// If `force` is false, returns 0 if threshold has not been reached.
    pub fn writeAck(self: *FastMux, stream: *Stream, dst: []u8, force: bool) error{BufferTooSmall}!usize {
        if (!force and !stream.flow_control.shouldAck(self.config.ack_threshold)) {
            return 0;
        }
        const credit = stream.flow_control.claimAckCredit();
        return formatAckFrame(stream.id, credit, dst);
    }

    /// Writes data on a stream, chunking into DATA frames within `max_frame_size` and send window limits.
    pub fn writeData(
        self: *FastMux,
        stream: *Stream,
        data: []const u8,
        dst: []u8,
    ) error{ BufferTooSmall, WindowExhausted, StreamClosed }!WriteResult {
        return stream.formatDataFrame(data, self.config.max_frame_size, dst);
    }

    /// Formats a FIN frame for closing a stream.
    pub fn writeFin(_: *FastMux, stream: *Stream, dst: []u8) error{BufferTooSmall}!usize {
        const sz = try formatFinFrame(stream.id, dst);
        if (stream.state == .HalfClosedRemote) {
            stream.state = .Closed;
        } else {
            stream.state = .HalfClosedLocal;
        }
        return sz;
    }

    /// Formats a PING frame with sequence ID.
    pub fn writePing(_: *FastMux, seq: u32, dst: []u8) error{BufferTooSmall}!usize {
        return formatPingFrame(seq, dst);
    }

    /// Convenience: Fragments and appends up to all bytes of `data` as DATA frames onto `wire_out`.
    pub fn appendStreamData(
        self: *FastMux,
        stream: *Stream,
        data: []const u8,
        wire_out: *std.ArrayList(u8),
    ) !usize {
        var data_idx: usize = 0;
        var frame_buf: [Header.LEN + 65535]u8 = undefined;

        while (data_idx < data.len) {
            if (stream.flow_control.availableSend() == 0) break;
            const res = self.writeData(stream, data[data_idx..], &frame_buf) catch |err| switch (err) {
                error.WindowExhausted => break,
                else => return err,
            };
            if (res.bytes_consumed == 0) break;
            try wire_out.appendSlice(frame_buf[0..res.frame_len]);
            data_idx += res.bytes_consumed;
        }
        return data_idx;
    }

    /// Closes and deallocates a stream by ID.
    pub fn closeStream(self: *FastMux, stream_id: u32) void {
        if (self.streams.fetchRemove(stream_id)) |kv| {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }
};

// Helper frame formatting functions
pub fn formatSynFrame(stream_id: u32, dst: []u8) error{BufferTooSmall}!usize {
    if (dst.len < Header.LEN) return error.BufferTooSmall;
    const hdr = Header{
        .stream_id = stream_id,
        .cmd = Header.CMD_SYN,
        .length = 0,
    };
    hdr.pack(dst[0..Header.LEN]);
    return Header.LEN;
}

pub fn formatAckFrame(stream_id: u32, credit: u32, dst: []u8) error{BufferTooSmall}!usize {
    const total = Header.LEN + 4;
    if (dst.len < total) return error.BufferTooSmall;
    const hdr = Header{
        .stream_id = stream_id,
        .cmd = Header.CMD_ACK,
        .length = 4,
    };
    hdr.pack(dst[0..Header.LEN]);
    std.mem.writeInt(u32, dst[Header.LEN..total], credit, .big);
    return total;
}

pub fn formatFinFrame(stream_id: u32, dst: []u8) error{BufferTooSmall}!usize {
    if (dst.len < Header.LEN) return error.BufferTooSmall;
    const hdr = Header{
        .stream_id = stream_id,
        .cmd = Header.CMD_FIN,
        .length = 0,
    };
    hdr.pack(dst[0..Header.LEN]);
    return Header.LEN;
}

pub fn formatPingFrame(seq: u32, dst: []u8) error{BufferTooSmall}!usize {
    if (dst.len < Header.LEN) return error.BufferTooSmall;
    const hdr = Header{
        .stream_id = seq,
        .cmd = Header.CMD_PING,
        .length = 0,
    };
    hdr.pack(dst[0..Header.LEN]);
    return Header.LEN;
}

// ============================================================================
// COMPREHENSIVE UNIT TESTS
// ============================================================================

test "Header packing, unpacking, and command flags" {
    const hdr = Header{
        .stream_id = 0x12345678,
        .cmd = Header.CMD_DATA,
        .length = 512,
    };
    var buf: [Header.LEN]u8 = undefined;
    hdr.pack(&buf);

    // Verify wire endianness (big-endian)
    try std.testing.expectEqual(@as(u8, 0x12), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x34), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x56), buf[2]);
    try std.testing.expectEqual(@as(u8, 0x78), buf[3]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[4]);
    try std.testing.expectEqual(@as(u8, 0x08), buf[5]);
    try std.testing.expectEqual(@as(u8, 0x02), buf[6]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[7]);

    const unpacked = try Header.unpack(&buf);
    try std.testing.expectEqual(hdr.stream_id, unpacked.stream_id);
    try std.testing.expectEqual(hdr.cmd, unpacked.cmd);
    try std.testing.expectEqual(hdr.length, unpacked.length);
    try std.testing.expect(unpacked.isData());
    try std.testing.expect(!unpacked.isSyn());
    try std.testing.expect(!unpacked.isAck());
    try std.testing.expect(!unpacked.isFin());
    try std.testing.expect(!unpacked.isPing());

    // Test flags/cmd variants
    const syn_hdr = Header{ .stream_id = 1, .cmd = Header.CMD_SYN, .length = 0 };
    try std.testing.expect(syn_hdr.isSyn());
    const ack_hdr = Header{ .stream_id = 1, .cmd = Header.CMD_ACK, .length = 4 };
    try std.testing.expect(ack_hdr.isAck());
    const fin_hdr = Header{ .stream_id = 1, .cmd = Header.CMD_FIN, .length = 0 };
    try std.testing.expect(fin_hdr.isFin());
    const ping_hdr = Header{ .stream_id = 0, .cmd = Header.CMD_PING, .length = 0 };
    try std.testing.expect(ping_hdr.isPing());

    // Test bit flags
    const flag_hdr = Header{ .stream_id = 2, .cmd = Header.FLAG_SYN | Header.FLAG_ACK, .length = 0 };
    try std.testing.expect(flag_hdr.isSyn());
    try std.testing.expect(flag_hdr.isAck());
    try std.testing.expect(!flag_hdr.isFin());

    // Buffer too short test
    try std.testing.expectError(error.BufferTooShort, Header.unpack(buf[0..7]));
}

test "Full Frame pack and unpack" {
    const payload = "BackPack FastMux High-Performance Stream Multiplexer";
    const frame = Frame{
        .header = .{
            .stream_id = 42,
            .cmd = Header.CMD_DATA,
            .length = @intCast(payload.len),
        },
        .payload = payload,
    };

    var wire_buf: [128]u8 = undefined;
    const packed_len = try frame.pack(&wire_buf);
    try std.testing.expectEqual(Header.LEN + payload.len, packed_len);

    const decoded = try Frame.unpack(wire_buf[0..packed_len]);
    try std.testing.expectEqual(@as(u32, 42), decoded.header.stream_id);
    try std.testing.expectEqual(Header.CMD_DATA, decoded.header.cmd);
    try std.testing.expectEqualSlices(u8, payload, decoded.payload);

    // Incomplete frame tests
    try std.testing.expectError(error.BufferTooShort, Frame.unpack(wire_buf[0..4]));
    try std.testing.expectError(error.IncompleteFrame, Frame.unpack(wire_buf[0 .. packed_len - 1]));
}

test "Credit-based flow control window tracking" {
    var fc = FlowControl.init(1000, 4000);
    try std.testing.expectEqual(@as(u32, 1000), fc.availableSend());
    try std.testing.expectEqual(@as(u32, 1000), fc.availableRecv());

    // 1. Consume send window
    try std.testing.expect(fc.canSend(500));
    try fc.consumeSend(500);
    try std.testing.expectEqual(@as(u32, 500), fc.availableSend());

    try std.testing.expect(fc.canSend(500));
    try fc.consumeSend(500);
    try std.testing.expectEqual(@as(u32, 0), fc.availableSend());

    // Window exhausted
    try std.testing.expect(!fc.canSend(1));
    try std.testing.expectError(error.WindowExhausted, fc.consumeSend(1));

    // 2. Consume receive window
    try fc.consumeRecv(800);
    try std.testing.expectEqual(@as(u32, 200), fc.availableRecv());
    try std.testing.expectError(error.WindowOverflow, fc.consumeRecv(201));

    // 3. Application reads data and generates ACK credits
    fc.recordConsumed(400);
    try std.testing.expect(!fc.shouldAck(500));
    fc.recordConsumed(200);
    try std.testing.expect(fc.shouldAck(500));

    const credit_to_ack = fc.claimAckCredit();
    try std.testing.expectEqual(@as(u32, 600), credit_to_ack);
    try std.testing.expectEqual(@as(u32, 800), fc.availableRecv());
    try std.testing.expect(!fc.shouldAck(500));

    // 4. Peer receives ACK and replenishes send window
    fc.addSendCredit(credit_to_ack);
    try std.testing.expectEqual(@as(u32, 600), fc.availableSend());
    try std.testing.expect(fc.canSend(600));
}

test "FrameParser handles fragmented and chunked byte streams" {
    const payload = "Zero-copy SIMD chunk reassembly verification payload";
    const frame = Frame{
        .header = .{
            .stream_id = 99,
            .cmd = Header.CMD_DATA,
            .length = @intCast(payload.len),
        },
        .payload = payload,
    };
    var wire_buf: [128]u8 = undefined;
    const packed_len = try frame.pack(&wire_buf);

    var parser = FrameParser.init(std.testing.allocator);
    defer parser.deinit();

    // Feed 3 bytes at a time
    var i: usize = 0;
    while (i < packed_len) {
        const chunk_end = @min(i + 3, packed_len);
        try parser.append(wire_buf[i..chunk_end]);
        i = chunk_end;

        if (i < packed_len) {
            _ = parser.peek() catch |err| {
                try std.testing.expect(err == error.IncompleteFrame or err == error.BufferTooShort);
            };
        }
    }

    const reassembled = try parser.peek();
    try std.testing.expectEqual(@as(u32, 99), reassembled.header.stream_id);
    try std.testing.expectEqualSlices(u8, payload, reassembled.payload);
    parser.consume(reassembled.totalLen());
}

test "Multiplexing multiple concurrent streams over a single byte stream" {
    const allocator = std.testing.allocator;

    var client = FastMux.init(allocator, false, .{
        .initial_window_size = 65536,
        .max_frame_size = 1024,
    });
    defer client.deinit();

    var server = FastMux.init(allocator, true, .{
        .initial_window_size = 65536,
        .max_frame_size = 1024,
    });
    defer server.deinit();

    // Single shared byte stream representing a TCP connection
    var tcp_byte_stream = std.ArrayList(u8).init(allocator);
    defer tcp_byte_stream.deinit();

    // Client opens 4 concurrent streams: 1, 3, 5, 7
    const s1 = try client.openStream();
    const s3 = try client.openStream();
    const s5 = try client.openStream();
    const s7 = try client.openStream();

    try std.testing.expectEqual(@as(u32, 1), s1.id);
    try std.testing.expectEqual(@as(u32, 3), s3.id);
    try std.testing.expectEqual(@as(u32, 5), s5.id);
    try std.testing.expectEqual(@as(u32, 7), s7.id);

    // Send SYN frames for all streams onto the TCP byte stream
    var syn_buf: [Header.LEN]u8 = undefined;
    _ = try client.writeSyn(s1.id, &syn_buf);
    try tcp_byte_stream.appendSlice(&syn_buf);
    _ = try client.writeSyn(s3.id, &syn_buf);
    try tcp_byte_stream.appendSlice(&syn_buf);
    _ = try client.writeSyn(s5.id, &syn_buf);
    try tcp_byte_stream.appendSlice(&syn_buf);
    _ = try client.writeSyn(s7.id, &syn_buf);
    try tcp_byte_stream.appendSlice(&syn_buf);

    // Server ingests the connection stream and accepts all 4 streams
    _ = try server.feed(tcp_byte_stream.items);
    tcp_byte_stream.clearRetainingCapacity();

    const srv_s1 = server.acceptStream() orelse return error.StreamNotFound;
    const srv_s3 = server.acceptStream() orelse return error.StreamNotFound;
    const srv_s5 = server.acceptStream() orelse return error.StreamNotFound;
    const srv_s7 = server.acceptStream() orelse return error.StreamNotFound;
    try std.testing.expectEqual(@as(?*Stream, null), server.acceptStream());

    try std.testing.expectEqual(@as(u32, 1), srv_s1.id);
    try std.testing.expectEqual(@as(u32, 3), srv_s3.id);
    try std.testing.expectEqual(@as(u32, 5), srv_s5.id);
    try std.testing.expectEqual(@as(u32, 7), srv_s7.id);

    // Prepare distinct data payloads for each stream
    const data_s1 = "Stream 1: Alpha payload with high-frequency tunnel frames.";
    const data_s3 = "Stream 3: Beta payload testing concurrent multiplexing with zero crosstalk.";
    const data_s5 = "Stream 5: Gamma payload validating credit window tracking and packet order.";
    const data_s7 = "Stream 7: Delta payload representing large bulk data transfer across multiplexer.";

    // Interleave writing DATA frames from multiple streams onto the single byte stream
    _ = try client.appendStreamData(s1, data_s1, &tcp_byte_stream);
    _ = try client.appendStreamData(s3, data_s3, &tcp_byte_stream);
    _ = try client.appendStreamData(s5, data_s5, &tcp_byte_stream);
    _ = try client.appendStreamData(s7, data_s7, &tcp_byte_stream);

    // Simulate fragmented TCP delivery to server (e.g. 64-byte packets)
    var offset: usize = 0;
    while (offset < tcp_byte_stream.items.len) {
        const end = @min(offset + 64, tcp_byte_stream.items.len);
        _ = try server.feed(tcp_byte_stream.items[offset..end]);
        offset = end;
    }
    tcp_byte_stream.clearRetainingCapacity();

    // Read back and verify exact payload integrity on each stream
    var read_buf: [256]u8 = undefined;

    const n1 = srv_s1.read(&read_buf);
    try std.testing.expectEqualSlices(u8, data_s1, read_buf[0..n1]);

    const n3 = srv_s3.read(&read_buf);
    try std.testing.expectEqualSlices(u8, data_s3, read_buf[0..n3]);

    const n5 = srv_s5.read(&read_buf);
    try std.testing.expectEqualSlices(u8, data_s5, read_buf[0..n5]);

    const n7 = srv_s7.read(&read_buf);
    try std.testing.expectEqualSlices(u8, data_s7, read_buf[0..n7]);
}

test "Bidirectional multiplexing with concurrent ping-pong exchanges" {
    const allocator = std.testing.allocator;

    var client = FastMux.init(allocator, false, .{ .initial_window_size = 32768 });
    defer client.deinit();
    var server = FastMux.init(allocator, true, .{ .initial_window_size = 32768 });
    defer server.deinit();

    var c2s = std.ArrayList(u8).init(allocator);
    defer c2s.deinit();
    var s2c = std.ArrayList(u8).init(allocator);
    defer s2c.deinit();

    // Client opens stream 1
    const cli_s1 = try client.openStream();
    var syn_buf: [Header.LEN]u8 = undefined;
    _ = try client.writeSyn(cli_s1.id, &syn_buf);
    try c2s.appendSlice(&syn_buf);

    _ = try server.feed(c2s.items);
    c2s.clearRetainingCapacity();
    const srv_s1 = server.acceptStream() orelse return error.StreamNotFound;

    // Client sends request on Stream 1
    const request = "GET /tunnel/stats HTTP/1.1\r\n\r\n";
    _ = try client.appendStreamData(cli_s1, request, &c2s);

    _ = try server.feed(c2s.items);
    c2s.clearRetainingCapacity();

    var srv_read: [128]u8 = undefined;
    const req_n = srv_s1.read(&srv_read);
    try std.testing.expectEqualSlices(u8, request, srv_read[0..req_n]);

    // Server sends response on Stream 1
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    _ = try server.appendStreamData(srv_s1, response, &s2c);

    _ = try client.feed(s2c.items);
    s2c.clearRetainingCapacity();

    var cli_read: [128]u8 = undefined;
    const resp_n = cli_s1.read(&cli_read);
    try std.testing.expectEqualSlices(u8, response, cli_read[0..resp_n]);
}

test "End-to-end credit-based flow control backpressure over byte stream" {
    const allocator = std.testing.allocator;

    // Small initial window of 100 bytes to test backpressure
    var client = FastMux.init(allocator, false, .{
        .initial_window_size = 100,
        .max_frame_size = 50,
        .ack_threshold = 50,
    });
    defer client.deinit();

    var server = FastMux.init(allocator, true, .{
        .initial_window_size = 100,
        .max_frame_size = 50,
        .ack_threshold = 50,
    });
    defer server.deinit();

    var c2s = std.ArrayList(u8).init(allocator);
    defer c2s.deinit();
    var s2c = std.ArrayList(u8).init(allocator);
    defer s2c.deinit();

    // Client opens stream 1
    const cli_s1 = try client.openStream();
    var syn_buf: [Header.LEN]u8 = undefined;
    _ = try client.writeSyn(cli_s1.id, &syn_buf);
    try c2s.appendSlice(&syn_buf);

    _ = try server.feed(c2s.items);
    c2s.clearRetainingCapacity();
    const srv_s1 = server.acceptStream() orelse return error.StreamNotFound;

    // Client attempts to send 150 bytes of data (exceeds 100-byte initial window)
    const large_payload = [_]u8{0xAA} ** 150;
    const sent_bytes = try client.appendStreamData(cli_s1, &large_payload, &c2s);

    // Client should only be able to send 100 bytes before send window is exhausted
    try std.testing.expectEqual(@as(usize, 100), sent_bytes);
    try std.testing.expectEqual(@as(u32, 0), cli_s1.flow_control.availableSend());

    // Server receives the 100 bytes
    _ = try server.feed(c2s.items);
    c2s.clearRetainingCapacity();

    // Server reads 60 bytes, triggering flow control ACK
    var srv_buf: [150]u8 = undefined;
    const read1 = srv_s1.read(srv_buf[0..60]);
    try std.testing.expectEqual(@as(usize, 60), read1);

    // Server generates ACK frame
    var ack_buf: [64]u8 = undefined;
    const ack_sz = try server.writeAck(srv_s1, &ack_buf, false);
    try std.testing.expect(ack_sz > 0);
    try s2c.appendSlice(ack_buf[0..ack_sz]);

    // Client processes ACK from server -> send window replenished by 60 bytes
    _ = try client.feed(s2c.items);
    s2c.clearRetainingCapacity();
    try std.testing.expectEqual(@as(u32, 60), cli_s1.flow_control.availableSend());

    // Client can now send the remaining 50 bytes!
    const sent2 = try client.appendStreamData(cli_s1, large_payload[100..150], &c2s);
    try std.testing.expectEqual(@as(usize, 50), sent2);

    // Server receives and reads the rest
    _ = try server.feed(c2s.items);
    c2s.clearRetainingCapacity();

    const read2 = srv_s1.read(srv_buf[60..150]);
    try std.testing.expectEqual(@as(usize, 90), read2);
    try std.testing.expectEqualSlices(u8, &large_payload, srv_buf[0..150]);
}

test "Stream graceful half-close and full-close lifecycle (FIN)" {
    const allocator = std.testing.allocator;

    var client = FastMux.init(allocator, false, .{});
    defer client.deinit();
    var server = FastMux.init(allocator, true, .{});
    defer server.deinit();

    var wire = std.ArrayList(u8).init(allocator);
    defer wire.deinit();

    const cli_s = try client.openStream();
    var buf: [64]u8 = undefined;

    // SYN
    _ = try client.writeSyn(cli_s.id, &buf);
    try wire.appendSlice(buf[0..Header.LEN]);
    _ = try server.feed(wire.items);
    wire.clearRetainingCapacity();

    const srv_s = server.acceptStream() orelse return error.StreamNotFound;
    try std.testing.expectEqual(StreamState.Established, srv_s.state);

    // Client sends FIN
    const fin_sz = try client.writeFin(cli_s, &buf);
    try wire.appendSlice(buf[0..fin_sz]);
    try std.testing.expectEqual(StreamState.HalfClosedLocal, cli_s.state);

    // Server receives FIN -> transitions to HalfClosedRemote
    _ = try server.feed(wire.items);
    wire.clearRetainingCapacity();
    try std.testing.expectEqual(StreamState.HalfClosedRemote, srv_s.state);

    // Server sends FIN -> transitions to Closed
    const srv_fin_sz = try server.writeFin(srv_s, &buf);
    try wire.appendSlice(buf[0..srv_fin_sz]);
    try std.testing.expectEqual(StreamState.Closed, srv_s.state);

    // Client receives server FIN -> transitions to Closed
    _ = try client.feed(wire.items);
    wire.clearRetainingCapacity();
    try std.testing.expectEqual(StreamState.Closed, cli_s.state);
}

test "PING heartbeat frame roundtrip" {
    const allocator = std.testing.allocator;

    var mux_inst = FastMux.init(allocator, false, .{});
    defer mux_inst.deinit();

    var ping_buf: [Header.LEN]u8 = undefined;
    const sz = try mux_inst.writePing(0xCAFE, &ping_buf);
    try std.testing.expectEqual(Header.LEN, sz);

    const hdr = try Header.unpack(&ping_buf);
    try std.testing.expectEqual(@as(u32, 0xCAFE), hdr.stream_id);
    try std.testing.expect(hdr.isPing());
    try std.testing.expectEqual(@as(u16, 0), hdr.length);
}
