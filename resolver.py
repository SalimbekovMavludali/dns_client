import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ResolverEndpoint:
    host: str
    port: int = 53
    failed_since: float = 0.0
    fail_count: int = 0

class TCPConnectionPool:
    def __init__(self, host: str, port: int = 53, max_size: int = 5):
        self.host = host
        self.port = port
        self._pool: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self._lock = asyncio.Lock()

    async def _create(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        return reader, writer

    async def get(self):
        try:
            return self._pool.get_nowait()
        except asyncio.QueueEmpty:
            return await self._create()

    async def release(self, reader, writer):
        if writer.is_closing():
            return
        try:
            self._pool.put_nowait((reader, writer))
        except asyncio.QueueFull:
            writer.close()
            await writer.wait_closed()

    async def close_all(self):
        while not self._pool.empty():
            r, w = self._pool.get_nowait()
            w.close()

class AsyncMultiResolver:
    def __init__(self, endpoints: list[ResolverEndpoint]):
        self.endpoints = endpoints
        self._pools: dict[str, TCPConnectionPool] = {}
        self._lock = asyncio.Lock()

    def _get_pool(self, endpoint: ResolverEndpoint) -> TCPConnectionPool:
        key = f"{endpoint.host}:{endpoint.port}"
        if key not in self._pools:
            self._pools[key] = TCPConnectionPool(endpoint.host, endpoint.port)
        return self._pools[key]

    async def _udp_query(self, endpoint: ResolverEndpoint, query: bytes, timeout: float = 2.0) -> Optional[bytes]:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if ":" in endpoint.host else socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            await loop.sock_connect(sock, (endpoint.host, endpoint.port))
            await loop.sock_sendall(sock, query)
            return await loop.sock_recv(sock, 4096)
        except Exception:
            return None
        finally:
            sock.close()

    async def _tcp_query(self, endpoint: ResolverEndpoint, query: bytes, timeout: float = 2.0) -> Optional[bytes]:
        pool = self._get_pool(endpoint)
        reader, writer = await pool.get()
        try:
            writer.write(struct.pack("!H", len(query)) + query)
            await writer.drain()
            length = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout))[0]
            return await asyncio.wait_for(reader.readexactly(length), timeout)
        except Exception:
            writer.close()
            await writer.wait_closed()
        finally:
            await pool.release(reader, writer)

    async def resolve(self, query: bytes, tx_id: int, timeout: float = 2.0, retries: int = 2) -> bytes:
        async with self._lock:
            active = sorted(self.endpoints, key=lambda e: (e.failed_since > 0, e.fail_count))

            for ep in active:
                if ep.failed_since > 0 and time.time() - ep.failed_since < 60:
                    continue

                for attempt in range(retries):
                    resp = await self._udp_query(ep, query, timeout)
                    if resp:
                        flags = struct.unpack_from("!H", resp, 2)[0]
                        if not (flags & 0x0200):
                            ep.failed_since = 0.0
                            ep.fail_count = 0
                            return resp

                    resp = await self._tcp_query(ep, query, timeout)
                    if resp:
                        ep.failed_since = 0.0
                        ep.fail_count = 0
                        return resp

                    await asyncio.sleep(0.5 * (2**attempt))

                ep.fail_count += 1
                ep.failed_since = time.time()

        raise ConnectionError("All resolvers exhausted")

    async def cleanup(self):
        for pool in self._pools.values():
            await pool.close_all()