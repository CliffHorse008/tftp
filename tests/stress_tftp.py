#!/usr/bin/env python3

import argparse
import hashlib
import random
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5
BLOCK_SIZE = 512
TIMEOUT_SEC = 3.0


def packet_request(opcode: int, filename: str, mode: str = "octet") -> bytes:
    return opcode.to_bytes(2, "big") + filename.encode() + b"\0" + mode.encode() + b"\0"


def packet_ack(block: int) -> bytes:
    return OP_ACK.to_bytes(2, "big") + block.to_bytes(2, "big")


def packet_data(block: int, payload: bytes) -> bytes:
    return OP_DATA.to_bytes(2, "big") + block.to_bytes(2, "big") + payload


def recv_packet(sock: socket.socket) -> tuple[bytes, tuple[str, int]]:
    while True:
        data, addr = sock.recvfrom(4 + BLOCK_SIZE + 128)
        opcode = int.from_bytes(data[:2], "big") if len(data) >= 2 else -1
        if opcode == OP_ERROR:
            msg = data[4:-1].decode(errors="replace") if len(data) > 4 else "unknown error"
            raise RuntimeError(f"TFTP error from {addr}: {msg}")
        return data, addr


def encode_netascii(payload: bytes) -> bytes:
    encoded = bytearray()
    for byte in payload:
        if byte == 0x0A:
            encoded.extend(b"\r\n")
        elif byte == 0x0D:
            encoded.extend(b"\r\0")
        else:
            encoded.append(byte)
    return bytes(encoded)


def decode_netascii(payload: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    while index < len(payload):
        byte = payload[index]
        if byte != 0x0D:
            decoded.append(byte)
            index += 1
            continue

        if index + 1 >= len(payload):
            decoded.append(0x0D)
            break

        nxt = payload[index + 1]
        if nxt == 0x0A:
            decoded.append(0x0A)
            index += 2
            continue
        if nxt == 0x00:
            decoded.append(0x0D)
            index += 2
            continue

        decoded.append(0x0D)
        index += 1

    return bytes(decoded)


def tftp_put(host: str, port: int, remote_name: str, payload: bytes, mode: str = "octet") -> str:
    digest = hashlib.sha256(payload).hexdigest()
    wire_payload = encode_netascii(payload) if mode == "netascii" else payload
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_SEC)
        sock.sendto(packet_request(OP_WRQ, remote_name, mode), (host, port))

        data, server_addr = recv_packet(sock)
        if len(data) != 4 or int.from_bytes(data[:2], "big") != OP_ACK or int.from_bytes(data[2:4], "big") != 0:
            raise RuntimeError("expected ACK block 0")

        block = 1
        offset = 0
        while True:
            chunk = wire_payload[offset:offset + BLOCK_SIZE]
            sock.sendto(packet_data(block, chunk), server_addr)
            data, addr = recv_packet(sock)
            if addr != server_addr:
                raise RuntimeError("server transfer id changed during upload")
            if len(data) != 4 or int.from_bytes(data[:2], "big") != OP_ACK or int.from_bytes(data[2:4], "big") != block:
                raise RuntimeError(f"unexpected ACK for block {block}")

            offset += len(chunk)
            if len(chunk) < BLOCK_SIZE:
                break
            block = (block + 1) & 0xFFFF
            if block == 0:
                block = 1

    return digest


def tftp_get(host: str, port: int, remote_name: str, mode: str = "octet") -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_SEC)
        sock.sendto(packet_request(OP_RRQ, remote_name, mode), (host, port))

        expected_block = 1
        chunks: list[bytes] = []
        server_addr = None

        while True:
            data, addr = recv_packet(sock)
            if server_addr is None:
                server_addr = addr
            elif addr != server_addr:
                raise RuntimeError("server transfer id changed during download")

            opcode = int.from_bytes(data[:2], "big")
            block = int.from_bytes(data[2:4], "big")
            if opcode != OP_DATA or block != expected_block:
                raise RuntimeError(f"unexpected packet during download: opcode={opcode}, block={block}, expected={expected_block}")

            payload = data[4:]
            chunks.append(payload)
            sock.sendto(packet_ack(block), server_addr)

            if len(payload) < BLOCK_SIZE:
                joined = b"".join(chunks)
                return decode_netascii(joined) if mode == "netascii" else joined

            expected_block = (expected_block + 1) & 0xFFFF
            if expected_block == 0:
                expected_block = 1


def make_payload(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(0, 256) for _ in range(size))


def wait_for_udp_port(host: str, port: int, timeout_sec: float) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.sendto(packet_request(OP_RRQ, "__probe_missing__.bin"), (host, port))
                data, _ = sock.recvfrom(1024)
                if len(data) >= 2:
                    return
            except (socket.timeout, OSError):
                time.sleep(0.1)
    raise RuntimeError(f"server did not respond on udp/{port} within {timeout_sec:.1f}s")


def main() -> int:
    parser = argparse.ArgumentParser(description="Local stress test for the TFTP server")
    parser.add_argument("--server-binary", required=True)
    parser.add_argument("--port", type=int, default=1069)
    parser.add_argument("--uploads", type=int, default=24)
    parser.add_argument("--downloads", type=int, default=24)
    parser.add_argument("--size", type=int, default=65536)
    args = parser.parse_args()

    temp_dir = tempfile.mkdtemp(prefix="tftp-stress-")
    root_dir = Path(temp_dir) / "root"
    root_dir.mkdir(parents=True, exist_ok=True)

    server = subprocess.Popen(
        [args.server_binary, str(root_dir), str(args.port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    stderr_lines: list[str] = []
    stderr_lock = threading.Lock()

    def read_stderr() -> None:
        assert server.stderr is not None
        for line in server.stderr:
            with stderr_lock:
                stderr_lines.append(line.rstrip())

    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stderr_thread.start()

    try:
        wait_for_udp_port("127.0.0.1", args.port, 5.0)

        expected_uploads: dict[str, str] = {}
        expected_downloads: dict[str, str] = {}

        for i in range(args.downloads):
            name = f"download_{i:03d}.bin"
            payload = make_payload(1000 + i, args.size)
            (root_dir / name).write_bytes(payload)
            expected_downloads[name] = hashlib.sha256(payload).hexdigest()

        futures = []
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.uploads + args.downloads) as executor:
            for i in range(args.uploads):
                name = f"upload_{i:03d}.bin"
                payload = make_payload(2000 + i, args.size)
                expected_uploads[name] = hashlib.sha256(payload).hexdigest()
                futures.append(executor.submit(tftp_put, "127.0.0.1", args.port, name, payload))

            for name, digest in expected_downloads.items():
                futures.append(executor.submit(tftp_get, "127.0.0.1", args.port, name))

            upload_results = []
            download_results = []
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, str):
                    upload_results.append(result)
                else:
                    download_results.append(hashlib.sha256(result).hexdigest())

        duration = time.perf_counter() - started

        if sorted(upload_results) != sorted(expected_uploads.values()):
            raise RuntimeError("upload digest set did not match expected values")
        if sorted(download_results) != sorted(expected_downloads.values()):
            raise RuntimeError("download digest set did not match expected values")

        for name, digest in expected_uploads.items():
            actual = hashlib.sha256((root_dir / name).read_bytes()).hexdigest()
            if actual != digest:
                raise RuntimeError(f"uploaded file verification failed for {name}")

        overwrite_name = "overwrite_target.bin"
        original_payload = make_payload(3000, BLOCK_SIZE * 2)
        replacement_payload = make_payload(3001, BLOCK_SIZE + 137)
        (root_dir / overwrite_name).write_bytes(original_payload)

        overwrite_digest = tftp_put("127.0.0.1", args.port, overwrite_name, replacement_payload)
        actual_payload = (root_dir / overwrite_name).read_bytes()
        if hashlib.sha256(actual_payload).hexdigest() != overwrite_digest:
            raise RuntimeError("overwrite verification failed for stored file")

        downloaded_payload = tftp_get("127.0.0.1", args.port, overwrite_name)
        if downloaded_payload != replacement_payload:
            raise RuntimeError("overwrite verification failed for downloaded file")

        netascii_name = "netascii_sample.txt"
        netascii_payload = b"line1\nline2\rline3\r\nline4\n"
        netascii_digest = tftp_put("127.0.0.1", args.port, netascii_name, netascii_payload, mode="netascii")
        actual_netascii = (root_dir / netascii_name).read_bytes()
        if hashlib.sha256(actual_netascii).hexdigest() != netascii_digest:
            raise RuntimeError("netascii upload verification failed for stored file")

        downloaded_netascii = tftp_get("127.0.0.1", args.port, netascii_name, mode="netascii")
        if downloaded_netascii != netascii_payload:
            raise RuntimeError("netascii download verification failed")

        total_bytes = (args.uploads + args.downloads) * args.size
        rate_mib = total_bytes / duration / (1024 * 1024)
        print(
            "stress_ok "
            f"uploads={args.uploads} "
            f"downloads={args.downloads} "
            f"size={args.size} "
            f"duration_sec={duration:.3f} "
            f"throughput_mib_s={rate_mib:.2f} "
            "overwrite=ok "
            "netascii=ok"
        )
        return 0
    finally:
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

        stderr_thread.join(timeout=1)
        shutil.rmtree(temp_dir, ignore_errors=True)

        if server.returncode not in (0, None):
            with stderr_lock:
                joined = "\n".join(stderr_lines[-20:])
            raise RuntimeError(f"server exited with code {server.returncode}\n{joined}")


if __name__ == "__main__":
    raise SystemExit(main())
