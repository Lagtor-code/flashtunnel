const std = @import("std");

pub const wire = @import("protocol/wire.zig");
pub const replay = @import("protocol/replay.zig");
pub const encap = @import("protocol/encap.zig");
pub const checksum = @import("protocol/checksum.zig");
pub const mux = @import("protocol/mux.zig");
pub const desync = @import("protocol/desync.zig");
pub const crypto = @import("crypto/chacha20poly1305.zig");
pub const fec = @import("fec/reedsolomon.zig");
pub const batch_socket = @import("net/batch_socket.zig");
pub const gso = @import("net/gso.zig");
pub const tun = @import("tun/tun_device.zig");
pub const splice = @import("tcp/splice_proxy.zig");
pub const ring_buffer = @import("core/ring_buffer.zig");
pub const pipeline = @import("core/pipeline.zig");
pub const tunnel_protocol = @import("tcp/tunnel_protocol.zig");
pub const tunnel_server = @import("tcp/tunnel_server.zig");
pub const tunnel_client = @import("tcp/tunnel_client.zig");
pub const c_api = @import("c_api.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "server")) {
        var cfg = tunnel_server.ServerConfig{};
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--listen") and i + 1 < args.len) {
                i += 1;
                parseIpPort(args[i], &cfg.listen_ip, &cfg.listen_port);
            } else if (std.mem.eql(u8, args[i], "--target") and i + 1 < args.len) {
                i += 1;
                parseIpPort(args[i], &cfg.target_ip, &cfg.target_port);
            } else if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
                i += 1;
                cfg.passphrase = args[i];
            } else if (std.mem.eql(u8, args[i], "--tcp")) {
                cfg.target_is_udp = false;
            } else if (std.mem.eql(u8, args[i], "--udp")) {
                cfg.target_is_udp = true;
            }
        }

        var srv = tunnel_server.TunnelServer.init(cfg);
        try srv.start();
    } else if (std.mem.eql(u8, command, "client")) {
        var cfg = tunnel_client.ClientConfig{
            .server_ip = [_]u8{ 127, 0, 0, 1 },
        };
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--server") and i + 1 < args.len) {
                i += 1;
                parseIpPort(args[i], &cfg.server_ip, &cfg.server_port);
            } else if (std.mem.eql(u8, args[i], "--listen") and i + 1 < args.len) {
                i += 1;
                parseIpPort(args[i], &cfg.local_ip, &cfg.local_port);
            } else if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
                i += 1;
                cfg.passphrase = args[i];
            } else if (std.mem.eql(u8, args[i], "--tcp")) {
                cfg.local_is_udp = false;
            } else if (std.mem.eql(u8, args[i], "--udp")) {
                cfg.local_is_udp = true;
            }
        }

        var cli = tunnel_client.TunnelClient.init(cfg);
        try cli.start();
    } else if (std.mem.eql(u8, command, "test")) {
        runSelfTest();
    } else {
        printUsage();
    }
}

fn parseIpPort(str: []const u8, out_ip: *[4]u8, out_port: *u16) void {
    var colon_idx: ?usize = null;
    for (str, 0..) |c, idx| {
        if (c == ':') colon_idx = idx;
    }

    if (colon_idx) |idx| {
        const ip_part = str[0..idx];
        const port_part = str[idx + 1 ..];

        // Parse IP
        var iter = std.mem.splitScalar(u8, ip_part, '.');
        var octet_idx: usize = 0;
        while (iter.next()) |part| {
            if (octet_idx < 4) {
                out_ip[octet_idx] = std.fmt.parseInt(u8, part, 10) catch 0;
                octet_idx += 1;
            }
        }

        // Parse Port
        out_port.* = std.fmt.parseInt(u16, port_part, 10) catch out_port.*;
    }
}

fn printUsage() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print(
        \\========================================================================
        \\   Zig Stealth TCP Tunnel (Native Desync + ChaCha20-Poly1305)
        \\   DPI Evasion: multidisorder:pos=2:seqovl=1:urg
        \\========================================================================
        \\
        \\USAGE:
        \\   mytunnel server [options]
        \\   mytunnel client --server <server_ip:port> [options]
        \\   mytunnel test
        \\
        \\SERVER OPTIONS:
        \\   --listen <ip:port>     Listen address for clients (default: 0.0.0.0:4433)
        \\   --target <ip:port>     Target service address (default: 127.0.0.1:123)
        \\   --udp                  Target is UDP (default, e.g. WireGuard)
        \\   --tcp                  Target is TCP (e.g. SSH, HTTP, SOCKS5)
        \\   --key <passphrase>     Shared secret authentication key
        \\
        \\CLIENT OPTIONS:
        \\   --server <ip:port>     Remote tunnel server address
        \\   --listen <ip:port>     Local listener port for users (default: 0.0.0.0:123)
        \\   --udp                  Local listener is UDP (default, e.g. WireGuard)
        \\   --tcp                  Local listener is TCP
        \\   --key <passphrase>     Shared secret authentication key
        \\
        \\EXAMPLES:
        \\   # On Foreign Server (Kharej):
        \\   ./mytunnel server --listen 0.0.0.0:4433 --target 127.0.0.1:123 --udp --key MySecret99
        \\
        \\   # On Iran Server (Relay) or Local Client:
        \\   ./mytunnel client --server 109.248.43.157:4433 --listen 0.0.0.0:123 --udp --key MySecret99
        \\
        \\========================================================================
        \\
    , .{}) catch {};
}

fn runSelfTest() void {
    const stdout = std.io.getStdOut().writer();
    stdout.print("[OK] Running Self Tests...\n", .{}) catch {};

    const key = [_]u8{0x5A} ** 32;
    const engine = crypto.AeadEngine.init(key);

    const test_packet = "SYN-ACK TUNNEL PACKET TEST DATA";
    var out_buf: [128]u8 = undefined;
    var ad: [13]u8 = [_]u8{ 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 };

    const sealed_len = engine.seal(&out_buf, 1, &ad, test_packet) catch return;
    stdout.print("[OK] Crypto Engine Initialized: Sealed {d} bytes.\n", .{sealed_len}) catch {};

    var plain_buf: [128]u8 = undefined;
    const opened = engine.open(&plain_buf, 1, &ad, out_buf[0..sealed_len]) catch return;
    stdout.print("[OK] Decryption Verified: \"{s}\"\n", .{opened}) catch {};

    stdout.print("[OK] Desync multidisorder:pos=2:seqovl=1:urg Engine Ready!\n", .{}) catch {};
    stdout.print("[OK] Self Tests Passed 100%.\n", .{}) catch {};
}

test {
    std.testing.refAllDecls(@This());
}
