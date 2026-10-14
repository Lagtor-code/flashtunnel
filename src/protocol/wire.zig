const std = @import("std");

/// Wire format definitions matching BackPack tunnel protocol.
///
/// Header (13 bytes):
/// 0      1                    5                            13
/// +------+--------------------+----------------------------+
/// | kind | session (uint32BE) | counter (uint64BE)         |
/// +------+--------------------+----------------------------+
pub const Header = struct {
    kind: u8,
    session: u32,
    counter: u64,

    pub const LEN: usize = 13;
    pub const TAG_LEN: usize = 16;
    pub const DATA_OVERHEAD: usize = LEN + TAG_LEN;

    pub const TYPE_INIT: u8 = 1;
    pub const TYPE_RESP: u8 = 2;
    pub const TYPE_DATA: u8 = 3;
    pub const TYPE_PROBE: u8 = 4;
    pub const TYPE_PROBE_ACK: u8 = 5;

    pub fn put(self: Header, dst: []u8) void {
        std.debug.assert(dst.len >= LEN);
        dst[0] = self.kind;
        std.mem.writeInt(u32, dst[1..5], self.session, .big);
        std.mem.writeInt(u64, dst[5..13], self.counter, .big);
    }

    pub fn toBytes(self: Header) [LEN]u8 {
        var buf: [LEN]u8 = undefined;
        self.put(&buf);
        return buf;
    }

    pub fn parse(buf: []const u8) error{ShortPacket, BadKind}!struct { header: Header, body: []const u8 } {
        if (buf.len < LEN) {
            return error.ShortPacket;
        }

        const kind = buf[0];
        if (kind < TYPE_INIT or kind > TYPE_PROBE_ACK) {
            return error.BadKind;
        }

        const session = std.mem.readInt(u32, buf[1..5], .big);
        const counter = std.mem.readInt(u64, buf[5..13], .big);

        return .{
            .header = .{
                .kind = kind,
                .session = session,
                .counter = counter,
            },
            .body = buf[LEN..],
        };
    }
};

test "Header serialize and parse" {
    const h = Header{
        .kind = Header.TYPE_DATA,
        .session = 0x12345678,
        .counter = 0xabcdef0123456789,
    };
    var buf: [Header.LEN]u8 = undefined;
    h.put(&buf);

    const parsed = try Header.parse(&buf);
    try std.testing.expectEqual(h.kind, parsed.header.kind);
    try std.testing.expectEqual(h.session, parsed.header.session);
    try std.testing.expectEqual(h.counter, parsed.header.counter);
    try std.testing.expectEqual(@as(usize, 0), parsed.body.len);
}
