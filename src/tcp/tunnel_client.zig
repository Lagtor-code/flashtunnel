const std = @import("std");
const proto = @import("tunnel_protocol.zig");
const desync = @import("../protocol/desync.zig");
const crypto = @import("../crypto/chacha20poly1305.zig");

/// High-Performance Pure TCP Tunnel Client in Zig.
/// Connects to the remote server using the multidisorder:pos=2:seqovl=1:urg
/// Desync Engine to bypass DPI egress filters, then relays traffic bidirectionally
/// over a ChaCha20-Poly1305 encrypted carrier.

pub const ClientConfig = struct {
    local_ip: [4]u8 = [_]u8{ 0, 0, 0, 0 },
    local_port: u16 = 123,
    local_is_udp: bool = true, // e.g. listening for WireGuard UDP on port 123
    server_ip: [4]u8,
    server_port: u16 = 4433,
    passphrase: []const u8 = "MySecretPass99",
    desync: desync.DesyncConfig = .{
        .pos = 2,
        .seqovl = 1,
        .use_urg = true,
        .urg_ptr = 1,
        .multidisorder = true,
        .chunk_count = 3,
    },
};

pub const TunnelClient = struct {
    config: ClientConfig,
    key: [32]u8,
    running: std.atomic.Value(bool),

    pub fn init(config: ClientConfig) TunnelClient {
        var key: [32]u8 = undefined;
        proto.deriveKeyFromPassphrase(config.passphrase, &key);
        return TunnelClient{
            .config = config,
            .key = key,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    pub fn start(self: *TunnelClient) !void {
        std.debug.print("[Client] Starting Tunnel Client...\n", .{});
        std.debug.print("[Client] Connecting to Remote Server: {d}.{d}.{d}.{d}:{d}\n", .{
            self.config.server_ip[0],
            self.config.server_ip[1],
            self.config.server_ip[2],
            self.config.server_ip[3],
            self.config.server_port,
        });
        std.debug.print("[Client] Desync Strategy: multidisorder:pos={d}:seqovl={d}:urg={any}\n", .{
            self.config.desync.pos,
            self.config.desync.seqovl,
            self.config.desync.use_urg,
        });

        if (self.config.local_is_udp) {
            try self.startUdpRelay();
        } else {
            try self.startTcpRelay();
        }
    }

    fn startUdpRelay(self: *TunnelClient) !void {
        const local_addr = std.net.Address.initIp4(self.config.local_ip, self.config.local_port);
        const udp_sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(udp_sock);

        // Bind UDP listener
        try std.posix.setsockopt(udp_sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        try std.posix.bind(udp_sock, &local_addr.any, local_addr.getOsSockLen());

        std.debug.print("[Client] UDP Listener active on {any} (WireGuard / UDP Relay)\n", .{local_addr});

        // Connect to server and establish desynced session
        var tunnel_session = try self.connectAndHandshake();
        defer tunnel_session.stream.close();

        std.debug.print("[Client] Connected and Desynced Session Established!\n", .{});

        var active = std.atomic.Value(bool).init(true);

        const UdpCtx = struct {
            stream: std.net.Stream,
            udp_sock: std.posix.fd_t,
            engine: *const crypto.AeadEngine,
            active: *std.atomic.Value(bool),
            last_client_addr: ?std.posix.sockaddr = null,
            last_client_len: std.posix.socklen_t = 0,
        };
        var ctx = UdpCtx{
            .stream = tunnel_session.stream,
            .udp_sock = udp_sock,
            .engine = &tunnel_session.engine,
            .active = &active,
        };

        // Thread 1: Read from remote server -> Decrypt -> Send back to local UDP client
        const t = try std.Thread.spawn(.{}, struct {
            fn run(c: *UdpCtx) void {
                var frame_buf: [4096]u8 = undefined;
                var dec_buf: [2048]u8 = undefined;

                while (c.active.load(.acquire)) {
                    var len_bytes: [2]u8 = undefined;
                    readExact(c.stream, &len_bytes) catch break;
                    const payload_len = std.mem.readInt(u16, &len_bytes, .big);
                    const total_remaining = 8 + payload_len + 16;
                    if (total_remaining + 2 > frame_buf.len) break;

                    @memcpy(frame_buf[0..2], &len_bytes);
                    readExact(c.stream, frame_buf[2 .. 2 + total_remaining]) catch break;

                    const res = proto.decryptFrame(&dec_buf, c.engine, frame_buf[0 .. 2 + total_remaining]) catch break;

                    if (c.last_client_addr) |client_sa| {
                        _ = std.posix.sendto(c.udp_sock, dec_buf[0..res.payload_len], 0, &client_sa, c.last_client_len) catch {};
                    }
                }
                c.active.store(false, .release);
            }
        }.run, .{&ctx});
        defer t.detach();

        // Main thread: Read from local UDP client -> Encrypt -> Send to remote server
        var raw_buf: [2048]u8 = undefined;
        var enc_buf: [4096]u8 = undefined;
        var counter: u64 = 1;

        while (active.load(.acquire)) {
            var client_sa: std.posix.sockaddr = undefined;
            var client_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            const n = std.posix.recvfrom(udp_sock, &raw_buf, 0, &client_sa, &client_len) catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(1_000_000);
                    continue;
                }
                break;
            };
            if (n == 0) continue;

            // Remember client address for reply routing
            ctx.last_client_addr = client_sa;
            ctx.last_client_len = client_len;

            const frame_len = proto.encryptFrame(&enc_buf, &tunnel_session.engine, counter, raw_buf[0..n]) catch break;
            counter += 1;
            tunnel_session.stream.writeAll(enc_buf[0..frame_len]) catch break;
        }
        active.store(false, .release);
    }

    fn startTcpRelay(self: *TunnelClient) !void {
        const local_addr = std.net.Address.initIp4(self.config.local_ip, self.config.local_port);
        var listener = try local_addr.listen(.{
            .reuse_address = true,
            .kernel_backlog = 128,
        });
        defer listener.deinit();

        std.debug.print("[Client] TCP Listener active on {any}\n", .{local_addr});

        while (self.running.load(.acquire)) {
            const client_conn = listener.accept() catch continue;

            const thread = std.Thread.spawn(.{}, handleTcpClient, .{ self, client_conn }) catch {
                client_conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    fn handleTcpClient(self: *TunnelClient, client_conn: std.net.Server.Connection) void {
        defer client_conn.stream.close();

        var tunnel_session = self.connectAndHandshake() catch |err| {
            std.debug.print("[Client] Failed to establish tunnel session: {any}\n", .{err});
            return;
        };
        defer tunnel_session.stream.close();

        var active = std.atomic.Value(bool).init(true);

        const TcpCtx = struct {
            client_stream: std.net.Stream,
            tunnel_stream: std.net.Stream,
            engine: *const crypto.AeadEngine,
            active: *std.atomic.Value(bool),
        };
        var ctx = TcpCtx{
            .client_stream = client_conn.stream,
            .tunnel_stream = tunnel_session.stream,
            .engine = &tunnel_session.engine,
            .active = &active,
        };

        // Thread 1: Tunnel -> Client
        const t = std.Thread.spawn(.{}, struct {
            fn run(c: *TcpCtx) void {
                var frame_buf: [18000]u8 = undefined;
                var dec_buf: [16500]u8 = undefined;

                while (c.active.load(.acquire)) {
                    var len_bytes: [2]u8 = undefined;
                    readExact(c.tunnel_stream, &len_bytes) catch break;
                    const payload_len = std.mem.readInt(u16, &len_bytes, .big);
                    const total_remaining = 8 + payload_len + 16;
                    if (total_remaining + 2 > frame_buf.len) break;

                    @memcpy(frame_buf[0..2], &len_bytes);
                    readExact(c.tunnel_stream, frame_buf[2 .. 2 + total_remaining]) catch break;

                    const res = proto.decryptFrame(&dec_buf, c.engine, frame_buf[0 .. 2 + total_remaining]) catch break;
                    c.client_stream.writeAll(dec_buf[0..res.payload_len]) catch break;
                }
                c.active.store(false, .release);
                std.posix.shutdown(c.client_stream.handle, .both) catch {};
                std.posix.shutdown(c.tunnel_stream.handle, .both) catch {};
            }
        }.run, .{&ctx}) catch return;

        // Main worker: Client -> Tunnel
        var raw_buf: [16384]u8 = undefined;
        var enc_buf: [18000]u8 = undefined;
        var counter: u64 = 1;

        while (active.load(.acquire)) {
            const n = client_conn.stream.read(&raw_buf) catch break;
            if (n == 0) break;

            const frame_len = proto.encryptFrame(&enc_buf, &tunnel_session.engine, counter, raw_buf[0..n]) catch break;
            counter += 1;
            tunnel_session.stream.writeAll(enc_buf[0..frame_len]) catch break;
        }

        active.store(false, .release);
        std.posix.shutdown(client_conn.stream.handle, .both) catch {};
        std.posix.shutdown(tunnel_session.stream.handle, .both) catch {};
        t.join();
    }

    pub const Session = struct {
        stream: std.net.Stream,
        engine: crypto.AeadEngine,
    };

    fn connectAndHandshake(self: *TunnelClient) !Session {
        const server_addr = std.net.Address.initIp4(self.config.server_ip, self.config.server_port);
        const stream = try std.net.tcpConnectToAddress(server_addr);
        errdefer stream.close();

        // Set TCP_NODELAY
        std.posix.setsockopt(stream.handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1))) catch {};

        // 1. Build TLS Chameleon Handshake
        var client_nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&client_nonce);

        var hs_buf: [proto.TOTAL_HANDSHAKE_LEN]u8 = undefined;
        const hs_len = try proto.buildClientHandshake(&hs_buf, &self.key, &client_nonce);

        // 2. Transmit Handshake using Desync Engine: pos=2 split with URG pointer injection
        if (self.config.desync.pos > 0 and hs_len > self.config.desync.pos) {
            const pos = self.config.desync.pos;
            const chunk1 = hs_buf[0..pos];
            const chunk2 = hs_buf[pos..hs_len];

            // Send chunk 1 (pos=2: bytes 0..2)
            try stream.writeAll(chunk1);
            std.time.sleep(1_000_000); // 1 ms boundary to force separate TCP segment

            // Send chunk 2 with URG flag (MSG_OOB on the boundary byte)
            if (self.config.desync.use_urg and chunk2.len > 0) {
                const MSG_OOB: u32 = 0x01;
                _ = std.posix.send(stream.handle, chunk2[0..1], MSG_OOB) catch {
                    try stream.writeAll(chunk2[0..1]);
                };
                if (chunk2.len > 1) {
                    try stream.writeAll(chunk2[1..]);
                }
            } else {
                try stream.writeAll(chunk2);
            }
        } else {
            try stream.writeAll(hs_buf[0..hs_len]);
        }

        // 3. Read Server Handshake Response (53 bytes)
        var resp_buf: [proto.TOTAL_HANDSHAKE_LEN]u8 = undefined;
        try readExact(stream, &resp_buf);

        // 4. Verify Server Handshake
        var server_nonce: [16]u8 = undefined;
        if (!proto.verifyServerHandshake(&resp_buf, &self.key, &server_nonce)) {
            return error.AuthenticationFailed;
        }

        // 5. Derive Session Key
        var session_key: [32]u8 = undefined;
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.key);
        hasher.update(&client_nonce);
        hasher.update(&server_nonce);
        hasher.final(&session_key);

        return Session{
            .stream = stream,
            .engine = crypto.AeadEngine.init(session_key),
        };
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
