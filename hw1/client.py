import argparse
import asyncio
import hashlib
import socket
import ssl
import struct
import sys
import time

from common import (
    MB,
    INIT_STRUCT,
    RESP_STRUCT,
    MODE_STREAMING,
    MODE_STOP_AND_WAIT,
    MSG_INIT,
    MSG_DATA,
    MSG_ACK,
    MSG_FIN,
    MSG_HASH,
    DEFAULT_PORT,
    SOCKET_BUF,
    recv_exact,
    generate_block,
    format_size,
)


def print_result(
    protocol, mode_name, block_size, total_size,
    elapsed, msg_sent, bytes_sent,
    msg_recv, bytes_recv,
    client_hash, server_hash
):
    lost_bytes = bytes_sent - bytes_recv
    lost_msgs = msg_sent - msg_recv
    loss_pct = (lost_bytes / bytes_sent * 100) if bytes_sent > 0 else 0.0
    print("=" * 50)
    print(f"Protocol: {protocol}")
    print(f"Mode: {mode_name}")
    print(f"Block size: {block_size} bytes")
    print(f"Data size: {format_size(total_size)}")
    print(f"Time: {elapsed:.3f} s")
    if elapsed > 0:
        print(f"Speed: {format_size(int(bytes_sent / elapsed))}/s")
    print(f"Messages sent: {msg_sent}")
    print(f"Messages received: {msg_recv}")
    print(f"Messages lost: {lost_msgs}")
    print(f"Bytes sent: {bytes_sent}")
    print(f"Bytes received: {bytes_recv}")
    print(f"Bytes lost: {lost_bytes}")
    print(f"Data loss: {loss_pct:.2f}%")
    print(f"SHA-256 (client): {client_hash}")
    print(f"SHA-256 (server): {server_hash}")
    print(f"Hash match: {client_hash == server_hash}")
    print("=" * 50)

# tcp

def run_tcp_client(host, port, total_size, block_size, mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF)
    except OSError:
        pass
    sock.connect((host, port))

    if mode == MODE_STOP_AND_WAIT:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    meta = INIT_STRUCT.pack(mode, total_size, block_size)
    sock.sendall(meta)

    block = generate_block(block_size)
    hasher = hashlib.sha256()
    sent = 0
    msg_count = 0
    mode_name = "streaming" if mode == MODE_STREAMING else "stop-and-wait"

    start = time.time()

    if mode == MODE_STREAMING:
        while sent < total_size:
            remaining = total_size - sent
            size = min(block_size, remaining)
            chunk = block[:size]
            sock.sendall(chunk)
            hasher.update(chunk)
            sent += size
            msg_count += 1
    else:
        while sent < total_size:
            remaining = total_size - sent
            size = min(block_size, remaining)
            chunk = block[:size]
            header = struct.pack("!I", size)
            sock.sendall(header + chunk)
            hasher.update(chunk)
            sent += size
            msg_count += 1
            recv_exact(sock, 1)
        sock.sendall(struct.pack("!I", 0))

    resp = recv_exact(sock, RESP_STRUCT.size + 64)
    bytes_recv, msg_recv = RESP_STRUCT.unpack(resp[:RESP_STRUCT.size])
    server_hash = resp[RESP_STRUCT.size:].decode()
    elapsed = time.time() - start
    client_hash = hasher.hexdigest()

    sock.close()
    print_result(
        "TCP", mode_name, block_size, total_size,
        elapsed, msg_count, sent,
        msg_recv, bytes_recv,
        client_hash, server_hash,
    )

# udp

def _udp_send_reliable(sock, addr, data, timeout=2.0, retries=10):
    for _ in range(retries):
        sock.sendto(data, addr)
        sock.settimeout(timeout)
        try:
            resp, _ = sock.recvfrom(65536)
            return resp
        except socket.timeout:
            continue
    raise TimeoutError("No response from server")


def run_udp_client(host, port, total_size, block_size, mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF)
    except OSError:
        pass

    server_addr = (host, port)
    mode_name = "streaming" if mode == MODE_STREAMING else "stop-and-wait"

    init_data = (
        struct.pack("!BB", MSG_INIT, mode)
        + struct.pack("!QI", total_size, block_size)
    )
    _udp_send_reliable(sock, server_addr, init_data)

    block = generate_block(block_size)
    hasher = hashlib.sha256()
    sent = 0
    msg_count = 0
    seq = 0

    start = time.time()

    if mode == MODE_STREAMING:
        while sent < total_size:
            remaining = total_size - sent
            size = min(block_size, remaining)
            chunk = block[:size]
            dgram = struct.pack("!BI", MSG_DATA, seq) + chunk
            sock.sendto(dgram, server_addr)
            hasher.update(chunk)
            sent += size
            msg_count += 1
            seq += 1
    else:
        while sent < total_size:
            remaining = total_size - sent
            size = min(block_size, remaining)
            chunk = block[:size]
            dgram = struct.pack("!BI", MSG_DATA, seq) + chunk
            _udp_send_reliable(sock, server_addr, dgram)
            hasher.update(chunk)
            sent += size
            msg_count += 1
            seq += 1

    server_hash = None
    bytes_recv = 0
    msg_recv = 0
    fin_msg = struct.pack("!B", MSG_FIN)
    for _ in range(5):
        sock.sendto(fin_msg, server_addr)
        sock.settimeout(15.0)
        try:
            while True:
                resp, _ = sock.recvfrom(256)
                if resp[0] == MSG_HASH:
                    payload = resp[1:]
                    bytes_recv, msg_recv = RESP_STRUCT.unpack(
                        payload[:RESP_STRUCT.size]
                    )
                    server_hash = payload[RESP_STRUCT.size:].decode()
                    break
        except socket.timeout:
            continue
        if server_hash:
            break

    elapsed = time.time() - start
    client_hash = hasher.hexdigest()

    sock.close()
    if server_hash is None:
        server_hash = "TIMEOUT"
    print_result(
        "UDP", mode_name, block_size, total_size,
        elapsed, msg_count, sent,
        msg_recv, bytes_recv,
        client_hash, server_hash,
    )

# quic

def run_quic_client(host, port, total_size, block_size, mode):
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(_quic_transfer(host, port, total_size, block_size, mode))


async def _quic_transfer(host, port, total_size, block_size, mode):
    from aioquic.asyncio import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived

    class ClientProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.resp_queue = asyncio.Queue()

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                self.resp_queue.put_nowait(event.data)

    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["transfer-test"],
        max_data=256 * MB,
        max_stream_data=256 * MB,
        idle_timeout=1200.0,
    )
    config.verify_mode = ssl.CERT_NONE

    mode_name = "streaming" if mode == MODE_STREAMING else "stop-and-wait"

    async with connect(
        host, port, configuration=config, create_protocol=ClientProtocol
    ) as client:
        stream_id = client._quic.get_next_available_stream_id()
        block = generate_block(block_size)
        hasher = hashlib.sha256()
        sent = 0
        msg_count = 0

        meta = INIT_STRUCT.pack(mode, total_size, block_size)
        client._quic.send_stream_data(stream_id, meta)

        start = time.time()

        if mode == MODE_STREAMING:
            while sent < total_size:
                remaining = total_size - sent
                size = min(block_size, remaining)
                chunk = block[:size]
                client._quic.send_stream_data(stream_id, chunk)
                client.transmit()
                await asyncio.sleep(0)
                hasher.update(chunk)
                sent += size
                msg_count += 1
            client._quic.send_stream_data(
                stream_id, b"", end_stream=True
            )
            client.transmit()
        else:
            while sent < total_size:
                remaining = total_size - sent
                size = min(block_size, remaining)
                chunk = block[:size]
                header = struct.pack("!I", size)
                client._quic.send_stream_data(stream_id, header + chunk)
                client.transmit()
                hasher.update(chunk)
                sent += size
                msg_count += 1
                await asyncio.wait_for(
                    client.resp_queue.get(), timeout=60.0
                )
            client._quic.send_stream_data(
                stream_id, struct.pack("!I", 0), end_stream=True
            )
            client.transmit()

        resp_timeout = max(120.0, total_size / MB * 2)
        resp_data = bytearray()
        resp_len = RESP_STRUCT.size + 64
        while len(resp_data) < resp_len:
            chunk = await asyncio.wait_for(
                client.resp_queue.get(), timeout=resp_timeout
            )
            resp_data.extend(chunk)
        bytes_recv, msg_recv = RESP_STRUCT.unpack(
            resp_data[:RESP_STRUCT.size]
        )
        server_hash = resp_data[RESP_STRUCT.size:RESP_STRUCT.size + 64].decode()

        elapsed = time.time() - start
        client_hash = hasher.hexdigest()

        print_result(
            "QUIC", mode_name, block_size, total_size,
            elapsed, msg_count, sent,
            msg_recv, bytes_recv,
            client_hash, server_hash,
        )


# main


def main():
    parser = argparse.ArgumentParser(description="Data transfer test client")
    parser.add_argument(
        "--protocol", required=True, choices=["tcp", "udp", "quic"]
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--size", type=int, required=True, help="Data size in MB"
    )
    parser.add_argument(
        "--block-size", type=int, required=True,
        help="Block size in bytes (1-65535)",
    )
    parser.add_argument(
        "--mode", required=True, choices=["streaming", "stop-and-wait"]
    )
    args = parser.parse_args()

    if args.block_size < 1 or args.block_size > 65535:
        parser.error("Block size must be between 1 and 65535")

    total_size = args.size * MB
    mode = (
        MODE_STREAMING if args.mode == "streaming" else MODE_STOP_AND_WAIT
    )

    handlers = {
        "tcp": lambda: run_tcp_client(
            args.host, args.port, total_size, args.block_size, mode
        ),
        "udp": lambda: run_udp_client(
            args.host, args.port, total_size, args.block_size, mode
        ),
        "quic": lambda: run_quic_client(
            args.host, args.port, total_size, args.block_size, mode
        ),
    }

    handlers[args.protocol]()


if __name__ == "__main__":
    main()
