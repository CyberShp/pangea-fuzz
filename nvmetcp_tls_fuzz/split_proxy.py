from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ssl

from .mutator import Mutation, MutationEngine
from .pdu import HEADER_SIZE, NvmeTcpHeader


@dataclass(frozen=True)
class ProxyMutationRule:
    direction: str
    ordinal: int
    mutation: Mutation


@dataclass
class SplitProxyConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 4420
    target_host: str = "127.0.0.1"
    target_port: int = 4420
    server_ssl: ssl.SSLContext | None = None
    client_ssl: ssl.SSLContext | None = None


class SplitProxy:
    def __init__(self, config: SplitProxyConfig, rules: list[ProxyMutationRule] | None = None):
        self.config = config
        self.rules = rules or []
        self.engine = MutationEngine()

    async def serve_forever(self) -> None:
        server = await asyncio.start_server(
            self._handle_client,
            self.config.listen_host,
            self.config.listen_port,
            ssl=self.config.server_ssl,
        )
        async with server:
            await server.serve_forever()

    async def _handle_client(self, host_reader: asyncio.StreamReader, host_writer: asyncio.StreamWriter) -> None:
        target_reader, target_writer = await asyncio.open_connection(
            self.config.target_host,
            self.config.target_port,
            ssl=self.config.client_ssl,
        )
        await asyncio.gather(
            self._pipe("host_to_target", host_reader, target_writer),
            self._pipe("target_to_host", target_reader, host_writer),
        )

    async def _pipe(
        self,
        direction: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        ordinal = 0
        try:
            while True:
                raw_header = await reader.readexactly(HEADER_SIZE)
                header = NvmeTcpHeader.from_bytes(raw_header)
                payload = await reader.readexactly(max(0, header.plen - HEADER_SIZE))
                frame = raw_header + payload
                ordinal += 1
                for rule in self.rules:
                    if rule.direction == direction and rule.ordinal == ordinal:
                        frame = self.engine.apply(frame, rule.mutation)
                writer.write(frame)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            writer.close()
            await writer.wait_closed()
