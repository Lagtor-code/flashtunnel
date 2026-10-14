# FlashTunnel

High-performance, lightweight TCP stealth tunnel designed for secure, low-latency relay connections.

## Features

- Native Zig Core: Minimal memory footprint (<0.5MB baseline) with zero garbage collection overhead.
- TLS 1.3 Record Carrier: Streams are encapsulated within standard TLS records for protocol masking.
- Integrated Anti-DPI Segmentation: Out-of-order TCP segmentation with sequence overlap and urgent flag signaling directly at the transport layer.
- ChaCha20-Poly1305 AEAD: Authenticated end-to-end encryption with vectorized processing.
- Multi-Port Redirection: Native iptables support for mapping alternative ports (e.g., 8443, 2087, 8080) to the primary entry port.
- Built-in Interactive Management: Terminal dashboard for configuration, service control, and live monitoring.

## Installation

Run the one-command installer on your Linux server (x86_64):

```bash
bash <(curl -sSL https://raw.githubusercontent.com/Lagtor-code/flashtunnel/main/install.sh)
```

Or clone the repository manually:

```bash
git clone https://github.com/Lagtor-code/flashtunnel.git /opt/flashtunnel && bash /opt/flashtunnel/install.sh
```

After installation, access the management menu anytime by running:

```bash
flashtunnel
```

## Quick Start

### 1. Server Setup (Upstream / Destination)
1. Run `flashtunnel` on your remote destination server.
2. Select option `1` (Configure Server).
3. Set the tunnel listen port (default: `4433`), local target service port (default: `443`), and a security key.
4. The service will start automatically via systemd.

### 2. Client Setup (Relay / Local Entry)
1. Run `flashtunnel` on your local relay server.
2. Select option `2` (Configure Client).
3. Enter the remote server IP, tunnel port, incoming listen port (default: `443`), optional redirect ports, and the matching security key.
4. The relay service will start immediately.

### 3. Client Configuration
Point your proxy client (e.g., VLESS / Trojan / Shadowsocks) to the relay server's IP address and chosen port.

## Command-Line Usage

```bash
# Run server directly
flashtunnel server --listen 0.0.0.0:4433 --target 127.0.0.1:443 --tcp --key <SECRET_KEY>

# Run client directly
flashtunnel client --server <REMOTE_IP>:4433 --listen 0.0.0.0:443 --tcp --key <SECRET_KEY>

# Run cryptographic and transport self-tests
flashtunnel test
```

## Repository Structure

```text
flashtunnel/
├── bin/
│   └── flashtunnel             # Precompiled static Linux x86_64 binary
├── src/                        # Complete Zig source code
│   ├── main.zig                # CLI entrypoint
│   ├── tcp/
│   │   ├── tunnel_server.zig   # Server listener and decryptor
│   │   ├── tunnel_client.zig   # Client relay and desync injector
│   │   └── tunnel_protocol.zig # Protocol frame framing and AEAD
│   ├── protocol/
│   │   └── desync.zig          # Packet desynchronization engine
│   └── crypto/
│       └── chacha20poly1305.zig# ChaCha20-Poly1305 implementation
├── build.zig                   # Zig build configuration
├── flashtunnel.sh              # Management TUI script
├── install.sh                  # One-command installer
├── flashtunnel-server.service  # Systemd unit template for server
├── flashtunnel-client.service  # Systemd unit template for client
└── README.md                   # Documentation
```

## License

Open-source under the MIT License.
