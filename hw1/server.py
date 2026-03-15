import argparse
import asyncio
import hashlib
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
    CERT_FILE,
    KEY_FILE,
    format_size,
    ensure_certs,
)


def print_summary(protocol, msg_count, total_bytes, hash_hex):
    print("=" * 50)
    print(f"Protocol: {protocol}")
    print(f"Messages received: {msg_count}")
    print(f"Bytes received: {total_bytes} ({format_size(total_bytes)})")
    print(f"SHA-256: {hash_hex}")
    print("=" * 50)
    print()


async def recv_exact_async(reader, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)

# tcp

async def run_tcp_server(host, port):
    server = await asyncio.start_server(
        _handle_tcp_connection, host, port,
    )
    for sock in server.sockets:
        sock.setsockopt(
            __import__("socket").SOL_SOCKET,
            __import__("socket").SO_REUSEADDR, 1,
        )
    print(f"TCP server listening on {host}:{port}")
    await server.serve_forever()


async def _handle_tcp_connection(reader, writer):
    addr = writer.get_extra_info("peername")
    print(f"TCP connection from {addr}")
    try:
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(
                __import__("socket").SOL_SOCKET,
                __import__("socket").SO_RCVBUF,
                SOCKET_BUF,
            )
    except OSError:
        pass

    try:
        meta = await recv_exact_async(reader, INIT_STRUCT.size)
        mode, total_size, block_size = INIT_STRUCT.unpack(meta)
        hasher = hashlib.sha256()
        total_received = 0
        msg_count = 0

        if mode == MODE_STREAMING:
            while total_received < total_size:
                to_read = min(65536, total_size - total_received)
                chunk = await reader.read(to_read)
                if not chunk:
                    break
                hasher.update(chunk)
                total_received += len(chunk)
            msg_count = (total_size + block_size - 1) // block_size
        else:
            while True:
                raw_len = await recv_exact_async(reader, 4)
                length = struct.unpack("!I", raw_len)[0]
                if length == 0:
                    break
                data = await recv_exact_async(reader, length)
                hasher.update(data)
                total_received += len(data)
                msg_count += 1
                writer.write(b"\x06")
                await writer.drain()

        hash_hex = hasher.hexdigest()
        resp = RESP_STRUCT.pack(total_received, msg_count) + hash_hex.encode()
        writer.write(resp)
        await writer.drain()
        print_summary("TCP", msg_count, total_received, hash_hex)
    except Exception as e:
        print(f"TCP error ({addr}): {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

# udp

class UdpServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.sessions = {}
        self.init_queue = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not data:
            return
        if data[0] == MSG_INIT:
            self.init_queue.put_nowait((data, addr))
        elif addr in self.sessions:
            self.sessions[addr].put_nowait(data)

    def register_session(self, addr, queue):
        self.sessions[addr] = queue

    def unregister_session(self, addr):
        self.sessions.pop(addr, None)


async def run_udp_server(host, port):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        UdpServerProtocol,
        local_addr=(host, port),
    )
    try:
        sock = transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(
                __import__("socket").SOL_SOCKET,
                __import__("socket").SO_RCVBUF,
                SOCKET_BUF,
            )
    except OSError:
        pass
    print(f"UDP server listening on {host}:{port}")
    try:
        while True:
            init_data, addr = await protocol.init_queue.get()
            asyncio.create_task(_handle_udp_session(protocol, init_data, addr))
    finally:
        transport.close()


async def _handle_udp_session(protocol, init_data, addr):
    mode = init_data[1]
    total_size, block_size = struct.unpack("!QI", init_data[2:14])
    queue = asyncio.Queue()
    protocol.register_session(addr, queue)
    protocol.transport.sendto(struct.pack("!B", MSG_ACK), addr)
    print(f"UDP session from {addr}: size={format_size(total_size)}, block={block_size}")

    hasher = hashlib.sha256()
    next_seq = 0
    pending = {}
    total_received = 0
    msg_count = 0

    try:
        while True:
            try:
                dgram = await asyncio.wait_for(queue.get(), timeout=10.0)
            except asyncio.TimeoutError:
                break

            msg_type = dgram[0]

            if msg_type == MSG_FIN:
                protocol.transport.sendto(struct.pack("!B", MSG_ACK), addr)
                break

            if msg_type == MSG_DATA:
                seq = struct.unpack("!I", dgram[1:5])[0]
                payload = dgram[5:]

                if seq < next_seq or seq in pending:
                    if mode == MODE_STOP_AND_WAIT:
                        protocol.transport.sendto(
                            struct.pack("!BI", MSG_ACK, seq), addr
                        )
                    continue

                msg_count += 1
                total_received += len(payload)

                if seq == next_seq:
                    hasher.update(payload)
                    next_seq += 1
                    while next_seq in pending:
                        hasher.update(pending.pop(next_seq))
                        next_seq += 1
                else:
                    if len(pending) < 100000:
                        pending[seq] = payload

                if mode == MODE_STOP_AND_WAIT:
                    protocol.transport.sendto(
                        struct.pack("!BI", MSG_ACK, seq), addr
                    )

        for seq in sorted(pending):
            hasher.update(pending[seq])
        pending.clear()

        hash_hex = hasher.hexdigest()
        hash_msg = (
            struct.pack("!B", MSG_HASH)
            + RESP_STRUCT.pack(total_received, msg_count)
            + hash_hex.encode()
        )
        for _ in range(3):
            protocol.transport.sendto(hash_msg, addr)
            await asyncio.sleep(0.01)
        print_summary("UDP", msg_count, total_received, hash_hex)

        try:
            while True:
                await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            pass
    finally:
        protocol.unregister_session(addr)

# quic

async def run_quic_server(host, port):
    ensure_certs()
    from aioquic.asyncio import serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived

    class ServerProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._streams = {}

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                sid = event.stream_id
                if sid not in self._streams:
                    q = asyncio.Queue()
                    self._streams[sid] = q
                    asyncio.ensure_future(self._process(sid, q))
                if event.data:
                    self._streams[sid].put_nowait(event.data)
                if event.end_stream:
                    self._streams[sid].put_nowait(None)

        async def _process(self, sid, queue):
            buf = bytearray()
            ended = False

            async def read_n(n):
                nonlocal buf, ended
                while len(buf) < n and not ended:
                    item = await queue.get()
                    if item is None:
                        ended = True
                    else:
                        buf.extend(item)
                result = bytes(buf[:n])
                del buf[:n]
                return result

            try:
                meta = await read_n(INIT_STRUCT.size)
                mode, total_size, block_size = INIT_STRUCT.unpack(meta)
                hasher = hashlib.sha256()
                total_received = 0
                msg_count = 0

                if mode == MODE_STREAMING:
                    if buf:
                        hasher.update(bytes(buf))
                        total_received += len(buf)
                        buf.clear()
                    while not ended:
                        item = await queue.get()
                        if item is None:
                            ended = True
                        else:
                            hasher.update(item)
                            total_received += len(item)
                    msg_count = (total_size + block_size - 1) // block_size
                else:
                    while True:
                        hdr = await read_n(4)
                        length = struct.unpack("!I", hdr)[0]
                        if length == 0:
                            break
                        data = await read_n(length)
                        hasher.update(data)
                        total_received += len(data)
                        msg_count += 1
                        self._quic.send_stream_data(sid, b"\x06")
                        self.transmit()

                hash_hex = hasher.hexdigest()
                resp = RESP_STRUCT.pack(total_received, msg_count) + hash_hex.encode()
                self._quic.send_stream_data(
                    sid, resp, end_stream=True
                )
                self.transmit()
                print_summary("QUIC", msg_count, total_received, hash_hex)
            except Exception as e:
                print(f"QUIC stream error: {e}")

    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=["transfer-test"],
        max_data=256 * MB,
        max_stream_data=256 * MB,
        idle_timeout=1200.0,
    )
    config.load_cert_chain(CERT_FILE, KEY_FILE)
    print(f"QUIC server listening on {host}:{port}")
    await serve(host, port, configuration=config, create_protocol=ServerProtocol)
    await asyncio.Future()

# main

def main():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(description="Data transfer test server")
    parser.add_argument(
        "--protocol", required=True, choices=["tcp", "udp", "quic"]
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    handlers = {
        "tcp": lambda: run_tcp_server(args.host, args.port),
        "udp": lambda: run_udp_server(args.host, args.port),
        "quic": lambda: run_quic_server(args.host, args.port),
    }

    try:
        asyncio.run(handlers[args.protocol]())
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()
