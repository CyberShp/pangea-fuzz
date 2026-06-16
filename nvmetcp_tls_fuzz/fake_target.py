from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ssl
from typing import Awaitable, Callable

from .pdu import HEADER_SIZE, NvmeTcpFrame, NvmeTcpHeader, PduType


FrameHandler = Callable[[NvmeTcpFrame], Awaitable[list[NvmeTcpFrame]]]


@dataclass
class FakeTargetConfig:
    host: str = "0.0.0.0"
    port: int = 4420
    ssl_context: ssl.SSLContext | None = None
    namespace_size: int = 64 * 1024 * 1024


class FakeTarget:
    """Minimal async NVMe/TCP target harness.

    Python 3.11 does not expose TLS-PSK callbacks in ssl, so production PSK
    runs should either pass an SSLContext supplied by a PSK-capable wrapper or
    place a TLS terminator in front of this process. The protocol engine itself
    consumes cleartext NVMe/TCP PDUs after TLS termination.
    """

    def __init__(self, config: FakeTargetConfig, handler: FrameHandler | None = None):
        self.config = config
        self.handler = handler or self.default_handler
        self.storage = bytearray(config.namespace_size)

    async def serve_forever(self) -> None:
        server = await asyncio.start_server(
            self._handle_client,
            self.config.host,
            self.config.port,
            ssl=self.config.ssl_context,
        )
        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                raw_header = await reader.readexactly(HEADER_SIZE)
                header = NvmeTcpHeader.from_bytes(raw_header)
                payload = await reader.readexactly(max(0, header.plen - HEADER_SIZE))
                responses = await self.handler(NvmeTcpFrame(header, payload))
                for response in responses:
                    writer.write(response.to_bytes())
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return
        finally:
            writer.close()
            await writer.wait_closed()

    async def default_handler(self, frame: NvmeTcpFrame) -> list[NvmeTcpFrame]:
        if frame.header.pdu_type == PduType.ICREQ:
            # ICResp minimal header. Further target behavior is intentionally
            # supplied by mutation scripts because this is a fuzz harness.
            header = NvmeTcpHeader(PduType.ICRESP, flags=0, hlen=128, pdo=0, plen=128)
            return [NvmeTcpFrame(header, b"\x00" * (128 - HEADER_SIZE))]
        if frame.header.pdu_type == PduType.CAPSULE_CMD:
            header = NvmeTcpHeader(PduType.RESPONSE_CAPSULE, flags=0, hlen=24, pdo=0, plen=24)
            return [NvmeTcpFrame(header, b"\x00" * (24 - HEADER_SIZE))]
        return []
