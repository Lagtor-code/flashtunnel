const std = @import("std");
const proto = @import("tunnel_protocol.zig");
const crypto = @import("../crypto/chacha20poly1305.zig");

/// High-Performance Pure TCP Tunnel Server in Zig.
/// Listens for client connections disguised as TLS 1.3 handshakes,
/// verifies HMAC-SHA256 authentication, and bidirectionally proxies
/// encrypted ChaCha20-Poly1305 frames to a local target service.

pub const ServerConfig = struct {
    listen_ip: [4]u8 = [_]u8{ 0, 0, 0, 0 },
    listen_port: u16 = 4433,
    target_ip: [4]u8 = [_]u8{ 127, 0, 0, 1 },
    target_port: u16 = 123,
    target_is_udp: bool = true, // e.g. WireGuard local port 123
    passphrase: []const u8 = "MySecretPass99",
};

pub const TunnelServer = struct {
    config: ServerConfig,
    key: [32]u8,
    running: std.atomic.Value(bool),

    pub fn init(config: ServerConfig) TunnelServer {
        var key: [32]u8 = undefined;
        proto.deriveKeyFromPassphrase(config.passphrase, &key);
        return TunnelServer{
            .config = config,
            .key = key,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    pub fn start(self: *TunnelServer) !void {
        const listen_addr = std.net.Address.initIp4(self.config.listen_ip, self.config.listen_port);
        var server = try listen_addr.listen(.{
            .reuse_address = true,
            .kernel_backlog = 128,
        });
        defer server.deinit();

        std.debug.print("[Server] Listening on {any} (Stealth TLS Carrier)\n", .{listen_addr});
        std.debug.print("[Server] Forwarding target: {any}:{d} (UDP: {any})\n", .{
            self.config.target_ip,
            self.config.target_port,
            self.config.target_is_udp,
        });

        while (self.running.load(.acquire)) {
            const conn = server.accept() catch |err| {
                if (!self.running.load(.acquire)) break;
                std.debug.print("[Server] Accept error: {any}\n", .{err});
                continue;
            };

            // Spawn worker thread for each client connection
            const thread = std.Thread.spawn(.{}, handleClient, .{ self, conn }) catch |err| {
                std.debug.print("[Server] Failed to spawn worker thread: {any}\n", .{err});
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn handleClient(self: *TunnelServer, conn: std.net.Server.Connection) void {
        defer conn.stream.close();

        // Configure TCP socket options: TCP_NODELAY + SO_OOBINLINE for urgent pointer desync
        std.posix.setsockopt(conn.stream.handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1))) catch {};
        std.posix.setsockopt(conn.stream.handle, std.posix.SOL.SOCKET, std.posix.SO.OOBINLINE, &std.mem.toBytes(@as(c_int, 1))) catch {};

        // 1. Read TLS Chameleon Client Handshake (53 bytes)
        var hs_buf: [proto.TOTAL_HANDSHAKE_LEN]u8 = undefined;
        var total_read: usize = 0;
        while (total_read < proto.TOTAL_HANDSHAKE_LEN) {
            const n = conn.stream.read(hs_buf[total_read..]) catch |err| {
                std.debug.print("[Server] Handshake read error: {any}\n", .{err});
                return;
            };
            if (n == 0) return; // Client closed
            total_read += n;
        }

        // 2. Verify Client Handshake
        var client_nonce: [16]u8 = undefined;
        if (!proto.verifyClientHandshake(&hs_buf, &self.key, &client_nonce)) {
            std.debug.print("[Server] REJECTED unauthorized probe or invalid handshake.\n", .{});
            return;
        }

        // 3. Send TLS Chameleon Server Handshake Response (53 bytes)
        var server_nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&server_nonce);
        var resp_buf: [proto.TOTAL_HANDSHAKE_LEN]u8 = undefined;
        const resp_len = proto.buildServerHandshake(&resp_buf, &self.key, &server_nonce) catch return;
        conn.stream.writeAll(resp_buf[0..resp_len]) catch return;

        std.debug.print("[Server] Client Authenticated Successfully. Session established.\n", .{});

        // Derive session key combining PSK, client nonce, and server nonce
        var session_key: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.key);
        hasher.update(&client_nonce);
        hasher.update(&server_nonce);
        hasher.final(&session_key);

        const engine = crypto.AeadEngine.init(session_key);

        if (self.config.target_is_udp) {
            handleUdpForward(conn.stream, &engine, self.config.target_ip, self.config.target_port);
        } else {
            handleTcpForward(conn.stream, &engine, self.config.target_ip, self.config.target_port);
        }
    }

    fn handleUdpForward(
        stream: std.net.Stream,
        engine: *const crypto.AeadEngine,
        target_ip: [4]u8,
        target_port: u16,
    ) void {
        const target_addr = std.net.Address.initIp4(target_ip, target_port);
        const udp_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch |err| {
            std.debug.print("[Server] Failed to create UDP socket: {any}\n", .{err});
            return;
        };
        defer std.posix.close(udp_sock);

        // State shared between reader and writer
        var active = std.atomic.Value(bool).init(true);

        const Context = struct {
            stream: std.net.Stream,
            udp_sock: std.posix.fd_t,
            target_addr: std.net.Address,
            engine: *const crypto.AeadEngine,
            active: *std.atomic.Value(bool),
        };
        var ctx = Context{
            .stream = stream,
            .udp_sock = udp_sock,
            .target_addr = target_addr,
            .engine = engine,
            .active = &active,
        };

        // Thread 1: Read UDP from target service -> Encrypt -> Send TCP frame to client
        const t = std.Thread.spawn(.{}, struct {
            fn run(c: *Context) void {
                var raw_buf: [2048]u8 = undefined;
                var enc_buf: [4096]u8 = undefined;
                var counter: u64 = 1;

                while (c.active.load(.acquire)) {
                    var src_addr: std.posix.sockaddr = undefined;
                    var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
                    const n = std.posix.recvfrom(c.udp_sock, &raw_buf, 0, &src_addr, &src_len) catch |err| {
                        if (err == error.WouldBlock) {
                            std.time.sleep(1_000_000);
                            continue;
                        }
                        break;
                    };
                    if (n == 0) continue;

                    const frame_len = proto.encryptFrame(&enc_buf, c.engine, counter, raw_buf[0..n]) catch break;
                    counter += 1;
                    c.stream.writeAll(enc_buf[0..frame_len]) catch break;
                }
                c.active.store(false, .release);
            }
        }.run, .{&ctx}) catch return;
        defer t.detach();

        // Main worker: Read encrypted TCP frames from client -> Decrypt -> Send UDP to target
        var frame_buf: [4096]u8 = undefined;
        var dec_buf: [2048]u8 = undefined;

        while (active.load(.acquire)) {
            // Read 2-byte length
            var len_bytes: [2]u8 = undefined;
            readExact(stream, &len_bytes) catch break;
            const payload_len = std.mem.readInt(u16, &len_bytes, .big);
            const total_remaining = 8 + payload_len + 16; // counter(8) + payload + tag(16)
            if (total_remaining + 2 > frame_buf.len) break;

            @memcpy(frame_buf[0..2], &len_bytes);
            readExact(stream, frame_buf[2 .. 2 + total_remaining]) catch break;

            const res = proto.decryptFrame(&dec_buf, engine, frame_buf[0 .. 2 + total_remaining]) catch |err| {
                std.debug.print("[Server] Decrypt error: {any}\n", .{err});
                break;
            };

            _ = std.posix.sendto(udp_sock, dec_buf[0..res.payload_len], 0, &target_addr.any, target_addr.getOsSockLen()) catch {};
        }
        active.store(false, .release);
    }

    fn handleTcpForward(
        stream: std.net.Stream,
        engine: *const crypto.AeadEngine,
        target_ip: [4]u8,
        target_port: u16,
    ) void {
        const target_addr = std.net.Address.initIp4(target_ip, target_port);
        const target_stream = std.net.tcpConnectToAddress(target_addr) catch |err| {
            std.debug.print("[Server] Failed to connect to TCP target: {any}\n", .{err});
            return;
        };
        defer target_stream.close();

        var active = std.atomic.Value(bool).init(true);

        const Context = struct {
            stream: std.net.Stream,
            target_stream: std.net.Stream,
            engine: *const crypto.AeadEngine,
            active: *std.atomic.Value(bool),
        };
        var ctx = Context{
            .stream = stream,
            .target_stream = target_stream,
            .engine = engine,
            .active = &active,
        };

        // Thread 1: Target -> Encrypt -> Client
        const t = std.Thread.spawn(.{}, struct {
            fn run(c: *Context) void {
                var raw_buf: [16384]u8 = undefined;
                var enc_buf: [18000]u8 = undefined;
                var counter: u64 = 1;

                while (c.active.load(.acquire)) {
                    const n = c.target_stream.read(&raw_buf) catch break;
                    if (n == 0) break;

                    const frame_len = proto.encryptFrame(&enc_buf, c.engine, counter, raw_buf[0..n]) catch break;
                    counter += 1;
                    c.stream.writeAll(enc_buf[0..frame_len]) catch break;
                }
                c.active.store(false, .release);
                std.posix.shutdown(c.stream.handle, .both) catch {};
                std.posix.shutdown(c.target_stream.handle, .both) catch {};
            }
        }.run, .{&ctx}) catch return;

        // Main worker: Client -> Decrypt -> Target
        var frame_buf: [18000]u8 = undefined;
        var dec_buf: [16500]u8 = undefined;

        while (active.load(.acquire)) {
            var len_bytes: [2]u8 = undefined;
            readExact(stream, &len_bytes) catch break;
            const payload_len = std.mem.readInt(u16, &len_bytes, .big);
            const total_remaining = 8 + payload_len + 16;
            if (total_remaining + 2 > frame_buf.len) break;

            @memcpy(frame_buf[0..2], &len_bytes);
            readExact(stream, frame_buf[2 .. 2 + total_remaining]) catch break;

            const res = proto.decryptFrame(&dec_buf, engine, frame_buf[0 .. 2 + total_remaining]) catch break;
            c_write: {
                target_stream.writeAll(dec_buf[0..res.payload_len]) catch break :c_write;
            }
        }

        active.store(false, .release);
        std.posix.shutdown(target_stream.handle, .both) catch {};
        std.posix.shutdown(stream.handle, .both) catch {};
        t.join();
    }

    fn readExact(stream: std.net.Stream, dst: []u8) !void {
        var total: usize = 0;
        while (total < dst.len) {
            const n = try stream.read(dst[total..]);
            if (n == 0) return error.EndOfStream;
            total += n;
        }
    }
};
