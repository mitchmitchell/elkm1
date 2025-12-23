"""Manage connection and IO to Elk."""

from __future__ import annotations

import asyncio
import logging
from asyncio import timeout as asyncio_timeout
from collections import deque
from functools import reduce
from typing import Any, NamedTuple

from .message import MessageEncode, decode, get_elk_command
from .notify import Notifier
from .util import parse_url, calculate_crc16_checksum

LOG = logging.getLogger(__name__)
HEARTBEAT_TIME = 120
MESSAGE_RESPONSE_TIME = 5.0


class QueuedWrite(NamedTuple):
    """Structure for entries in the write queue."""

    msg: str
    response_cmd: str | None
    timeout: float = 5.0


class Connection:
    """Manage connection to ElkE27 panel."""

    def __init__(self, url: str, notifier: Notifier):
        self._url = url
        self._notifier = notifier

        self._writer: asyncio.StreamWriter | None = None
        self._awaiting_response_command: str | None = None
        self._paused = False
        self._write_queue: deque[QueuedWrite] = deque()
        self._check_write_queue = asyncio.Event()
        self._response_received = asyncio.Event()
        self._heartbeat_event = asyncio.Event()
        self._tasks: set[asyncio.Task[Any]] = set()

    async def connect(self) -> None:
        """Create connection to Elk."""

        LOG.info("Connecting to ElkE27 at %s", self._url)
        retry_time = 1
        scheme, dest, param, ssl_context = parse_url(self._url)
        while not self._writer:
            try:
                async with asyncio_timeout(30):
                    reader, self._writer = await asyncio.open_connection(
                        host=dest, port=param, ssl=ssl_context
                    )
            except (TimeoutError, ValueError, OSError) as err:
                LOG.warning(
                    "Error connecting to ElkE27 (%s). Retrying in %d seconds",
                    err,
                    retry_time,
                )
                await asyncio.sleep(retry_time)
                retry_time = min(60, retry_time * 2)
                continue

            self._tasks.add(asyncio.create_task(self._heartbeat_timer()))
            self._tasks.add(asyncio.create_task(self._read_stream(reader)))
            self._tasks.add(asyncio.create_task(self._write_stream()))
            self._notifier.notify("connected", {})

    async def _read_stream(self, reader: asyncio.StreamReader) -> None:
        read_buffer = ""
        while True:
            data = await reader.read(500)
            if not data:
                break
            self._heartbeat()

            read_buffer += data.decode("ISO-8859-1")
            while "\r\n" in read_buffer:
                line, read_buffer = read_buffer.split("\r\n", 1)
                if get_elk_command(line) == self._awaiting_response_command:
                    self._response_received.set()

                LOG.debug("got_data '%s'", line)
                try:
                    decoded = decode(line)
                    if decoded:
                        self._notifier.notify(decoded[0], decoded[1])
                except (ValueError, AttributeError) as exc:
                    LOG.error("Invalid message '%s'", data, exc_info=exc)

    async def _write_stream(self) -> None:
        async def write_msg() -> None:
            cksum = calculate_crc16_checksum(0, q_entry.msg)
            msg = f"{q_entry.msg}{cksum:02X}\r\n"
            LOG.debug("write_data '%s'", msg[:-2])
            self._writer.write((msg).encode())  # type: ignore

        async def await_msg_response() -> None:
            self._awaiting_response_command = q_entry.response_cmd
            try:
                async with asyncio_timeout(MESSAGE_RESPONSE_TIME):
                    await self._response_received.wait()
            except TimeoutError:
                self._notifier.notify("timeout", {"msg_code": q_entry.response_cmd})
            self._response_received.clear()
            self._awaiting_response_command = None

        while True:
            if not self._write_queue:
                await self._check_write_queue.wait()
            if not self._writer:
                break
            self._check_write_queue.clear()
            if self._write_queue:
                q_entry = self._write_queue.popleft()
                await write_msg()
                if q_entry.response_cmd:
                    await await_msg_response()

    def _send(self, q_entry: QueuedWrite, priority_send: bool) -> None:
        if self._paused:
            return
        if priority_send:
            self._write_queue.appendleft(q_entry)
        else:
            self._write_queue.append(q_entry)
        self._check_write_queue.set()

    def send(self, msg: MessageEncode, priority_send: bool = False) -> None:
        """Send a message to Elk."""
        self._send(QueuedWrite(msg.message, msg.response_command), priority_send)

    def is_connected(self) -> bool:
        """Is the connection active?"""
        return self._writer is not None

    def disconnect(self, reason: str = "") -> None:
        """Disconnect and cleanup."""
        if reason:
            LOG.warning("ElkE27 at %s disconnecting %s", self._url, reason)
        else:
            LOG.info("ElkE27 at %s disconnecting", self._url)
        if self._writer:
            self._writer.close()
            self._writer = None
        for task in self._tasks:
            if asyncio.current_task() != task:
                task.cancel()
        self._tasks = set()
        self._notifier.notify("disconnected", {})

    def _heartbeat(self) -> None:
        self._heartbeat_event.set()

    async def _heartbeat_timer(self) -> None:
        while True:
            self._heartbeat_event.clear()
            try:
                async with asyncio_timeout(HEARTBEAT_TIME):
                    await self._heartbeat_event.wait()
            except TimeoutError:
                if self._paused:
                    continue
                self.disconnect("(heartbeat timeout)")
                await self.connect()
                break
