"""Discovery of Elk panels."""

from __future__ import annotations

import json
import asyncio
import logging
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from struct import unpack

_LOGGER = logging.getLogger(__name__)


@dataclass
class ElkSystem:
    """An ELKE27 system."""

    mac_address: str
    ip_address: str
    name: str
    port: int
    tls_port: int


def create_udp_socket(discovery_port: int) -> socket.socket:
    """Create a udp socket used for communicating with the device."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", 0))
    sock.setblocking(False)
    return sock


class ELKDiscovery(asyncio.DatagramProtocol):
    """Discovery main class."""

    def __init__(
        self,
        destination: tuple[str, int],
        on_response: Callable[[bytes, tuple[str, int]], None],
    ) -> None:
        self.transport = None
        self.destination = destination
        self.on_response = on_response

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Trigger on_response."""
        self.on_response(data, addr)

    def error_received(self, exc: Exception | None) -> None:
        """Handle error."""
        _LOGGER.error("ELKDiscovery error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """Do nothing on connection lost."""


def _decode_data(raw_response: bytes) -> ElkSystem:
    """Decode an ELK discovery response packet."""

    try:
        data = json.loads(raw_response)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

    mac_address = data['MAC_ADDR']
    ip_address = data['IPV4_ADDR']
    port = data['LISTEN_PORT']
    tls_port = data['ENCRYPTED_LISTEN_PORT']
    name = data['NAME']

    return ElkSystem(mac_address, ip_address, name, port, tls_port)


class AIOELKDiscovery:
    """A 30303 discovery scanner."""

    DISCOVERY_PORT = 2362
    BROADCAST_FREQUENCY = 3
    DISCOVER_MESSAGE = b"{ \"FIND\": \"ELKWCID\" }"
    BROADCAST_ADDRESS = "<broadcast>"

    def __init__(self) -> None:
        self.found_devices: list[ElkSystem] = []

    def _destination_from_address(self, address: str | None) -> tuple[str, int]:
        if address is None:
            address = self.BROADCAST_ADDRESS
        return (address, self.DISCOVERY_PORT)

    def _process_response(
        self,
        data: bytes | None,
        from_address: tuple[str, int],
        address: str | None,
        response_list: dict[tuple[str, int], ElkSystem],
    ) -> bool:
        """Process a response.

        Returns True if processing should stop
        """
        if (
            data is None
            or data == self.DISCOVER_MESSAGE
            or not (b"ELKWC2017" in data)
        ):
            return False
        try:
            response_list[from_address] = _decode_data(data)
        except Exception as ex:  # pylint: disable=broad-except
            _LOGGER.warning("Failed to decode response from %s: %s", from_address, ex)
            return False
        return from_address[0] == address

    async def _async_run_scan(
        self,
        transport: asyncio.DatagramTransport,
        destination: tuple[str, int],
        timeout: int,
        found_all_future: asyncio.Future[bool],
    ) -> None:
        """Send the scans."""
        _LOGGER.debug("discover: %s => %s", destination, self.DISCOVER_MESSAGE)
        transport.sendto(self.DISCOVER_MESSAGE, destination)
        quit_time = time.monotonic() + timeout
        remain_time = float(timeout)
        while True:
            time_out = min(remain_time, timeout / self.BROADCAST_FREQUENCY)
            if time_out <= 0:
                return
            try:
                await asyncio.wait_for(
                    asyncio.shield(found_all_future), timeout=time_out
                )
            except TimeoutError:
                if time.monotonic() >= quit_time:
                    return
                # No response, send broadcast again in cast it got lost
                _LOGGER.debug("discover: %s => %s", destination, self.DISCOVER_MESSAGE)
                transport.sendto(self.DISCOVER_MESSAGE, destination)
            else:
                return  # found_all
            remain_time = quit_time - time.monotonic()

    async def async_scan(
        self, timeout: int = 10, address: str | None = None
    ) -> list[ElkSystem]:
        """Discover ELK devices."""
        sock = create_udp_socket(self.DISCOVERY_PORT)
        destination = self._destination_from_address(address)
        found_all_future: asyncio.Future[bool] = asyncio.Future()
        response_list: dict[tuple[str, int], ElkSystem] = {}

        def _on_response(data: bytes, addr: tuple[str, int]) -> None:
            _LOGGER.debug("discover: %s <= %s", addr, data)
            if self._process_response(data, addr, address, response_list):
                found_all_future.set_result(True)

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: ELKDiscovery(
                destination=destination,
                on_response=_on_response,
            ),
            sock=sock,
        )
        try:
            await self._async_run_scan(
                transport,
                destination,
                timeout,
                found_all_future,
            )
        finally:
            transport.close()

        self.found_devices = list(response_list.values())
        return self.found_devices
