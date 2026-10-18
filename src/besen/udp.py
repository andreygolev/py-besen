"""Local UDP transport using the established Besen session and controls.

LAN registration and port discovery were researched with the MIT-licensed
RafaelSchridi/evsemaster implementation. No cloud service is involved.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

from .client import BesenClient
from .exceptions import CannotConnect, CommandFailed, InvalidAuth, ProtocolError
from .protocol import ParsedPacket, build_command, parse_packet
from .wifi import UDP_PORT

PROBE_PORT = 7248
HEARTBEAT_TIMEOUT = 35.0
LOGIN_INTERVAL = 3.0
LOGIN_ATTEMPTS = 4


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, hub: BesenUdpHub) -> None:
        self.hub = hub
        self.closed = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.hub.receive(data, addr)

    def connection_lost(self, exc: Exception | None) -> None:
        self.closed.set()
        self.hub.transport = None


class BesenUdpHub:
    """Share one listening socket between all chargers and config flows.

    Do not use SO_REUSEPORT: it can split replies between independent sockets.
    Routing uses the serial, with host matching only before a serial is known.
    """

    def __init__(self, *, port: int = UDP_PORT, bind: str = "0.0.0.0") -> None:
        self.port = port
        self.bind = bind
        self.transport: asyncio.DatagramTransport | None = None
        self._protocol: _Protocol | None = None
        self._lock = asyncio.Lock()
        self.clients: set[BesenUdpClient] = set()
        self.discovered: dict[str, tuple[str, int]] = {}
        self.last_seen: dict[str, float] = {}

    async def async_start(self) -> None:
        """Open the listener, once, even when entries start concurrently."""
        async with self._lock:
            if self.transport is not None:
                return
            try:
                (
                    self.transport,
                    self._protocol,
                ) = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: _Protocol(self),
                    local_addr=(self.bind, self.port),
                    allow_broadcast=True,
                )
            except OSError as err:
                raise CannotConnect("Unable to bind the Besen UDP listener") from err

    async def async_stop(self) -> None:
        """Release clients and wait until the socket can be rebound."""
        for client in tuple(self.clients):
            await client.async_stop()
        async with self._lock:
            transport, protocol = self.transport, self._protocol
            self.transport = None
            self._protocol = None
            if transport is not None:
                transport.close()
            if protocol is not None:
                async with asyncio.timeout(2):
                    await protocol.closed.wait()
            self.discovered.clear()
            self.last_seen.clear()

    def send(self, data: bytes, addr: tuple[str, int]) -> None:
        """Send a frame without logging its credentials or contents."""
        if self.transport is None:
            raise CommandFailed("Besen UDP listener is closed")
        self.transport.sendto(data, addr)

    def probe(self) -> None:
        """Discover chargers without broadcasting a real PIN."""
        self.send(build_command(0, "\x00" * 6, 0x8002), ("255.255.255.255", PROBE_PORT))

    def receive(self, data: bytes, addr: tuple[str, int]) -> None:
        """Validate each datagram independently and route it to one session."""
        try:
            packet = parse_packet(data)
        except ProtocolError:
            return
        if packet.identifier == "0000000000000000":
            return
        self.discovered[packet.identifier] = addr
        self.last_seen[packet.identifier] = time.monotonic()
        for client in tuple(self.clients):
            serial = client.state.info.serial
            if serial == packet.identifier or (
                serial is None and client.host == addr[0]
            ):
                client.receive(packet, addr)
                return


class BesenUdpClient(BesenClient):
    """Use UDP for every operation on a charger, with no Bluetooth fallback."""

    def __init__(
        self,
        *,
        address: str,
        pin: str,
        hub: BesenUdpHub,
        logger: logging.Logger,
        host: str | None = None,
        serial: str | None = None,
        advertised_name: str | None = None,
        sync_clock: bool = True,
    ) -> None:
        super().__init__(
            address=address,
            pin=pin,
            logger=logger,
            ble_device_provider=lambda: None,
            advertised_name=advertised_name,
            sync_clock=sync_clock,
        )
        if serial is not None and (
            len(serial) != 16 or len(bytes.fromhex(serial)) != 8
        ):
            raise ValueError("Invalid charger serial")
        self.hub = hub
        self.host = host
        self.port = PROBE_PORT
        self._active = False
        self._last_heading = 0.0
        self._heading_received = asyncio.Event()
        self._update_info(serial=serial)

    async def async_wait_for_heartbeat(self, timeout: float = 20.0) -> None:
        """Verify that login registered a push session, beyond request replies."""
        async with asyncio.timeout(timeout):
            await self._heading_received.wait()
        if not self._state.authenticated or not self._state.available:
            raise CannotConnect("LAN registration is no longer active")

    @property
    def is_connected(self) -> bool:
        """Return whether this session owns a running UDP listener."""
        return self._active and self.hub.transport is not None

    async def _connect_and_login_locked(self) -> None:
        await self._disconnect_client()
        await self.hub.async_start()
        if self.host:
            try:
                addresses = await asyncio.get_running_loop().getaddrinfo(
                    self.host, None, family=socket.AF_INET, type=socket.SOCK_DGRAM
                )
                self.host = str(addresses[0][4][0])
            except OSError as err:
                raise CannotConnect("Unable to resolve the charger host") from err
        for other in self.hub.clients:
            if (
                self.state.info.serial is not None
                and other.state.info.serial == self.state.info.serial
            ) or (self.host is not None and other.host == self.host):
                raise CannotConnect("Charger already has an active LAN session")
        self.hub.clients.add(self)
        self._active = True
        self._auth_failed = False
        self._connection_error = None
        self._ready_event = asyncio.Event()
        self._heading_received.clear()
        self._login_request_sent = False
        self._login_confirm_sent = False
        self._set_state(available=False, authenticated=False, last_error=None)
        for _attempt in range(LOGIN_ATTEMPTS):
            if self._stopping:
                raise CannotConnect("Besen client is stopping")
            if addr := self.hub.discovered.get(self.state.info.serial or ""):
                self.host, self.port = addr
            if self.host:
                await self._send_login_request()
            else:
                self.hub.probe()
            try:
                async with asyncio.timeout(LOGIN_INTERVAL):
                    await self._ready_event.wait()
            except TimeoutError:
                continue
            if self._auth_failed:
                raise InvalidAuth("The charger rejected the configured PIN")
            if self._state.authenticated:
                self._reconnect_requested = False
                return
            raise CannotConnect("LAN login was interrupted")
        raise CannotConnect("Timed out waiting for charger LAN login")

    async def _disconnect_client(self) -> None:
        self._active = False
        self.hub.clients.discard(self)
        self._connection_generation += 1
        self._end_charge_start()
        await self._cancel_background_tasks()
        self._reset_schedule()

    async def _send_login_request(self) -> None:
        if self.host is None:
            return
        serial = self.state.info.serial or "0000000000000000"
        self._login_request_sent = True
        self.hub.send(self._build_packet(serial, 0x8002, None), (self.host, self.port))

    def _build_packet(
        self, serial: str, command: int, payload: list[Any] | None
    ) -> bytes:
        # Parsed identifiers contain wire-order hex, not decimal serial numbers.
        return build_command(
            int.from_bytes(bytes.fromhex(serial), "little"), self.pin, command, payload
        )

    async def _write_packet(self, packet: bytes) -> None:
        if self.host is None or not self.is_connected:
            raise CommandFailed("Charger is not connected")
        self.hub.send(packet, (self.host, self.port))

    async def _send_command(
        self,
        command: int,
        payload: list[Any] | None,
        *,
        name: str,
        start_response: asyncio.Future[dict[str, Any] | None] | None = None,
    ) -> None:
        # The login handler reads configuration before it marks authentication
        # complete. User controls must never use an expired registration.
        if not self._state.authenticated and name not in {
            "login_confirm",
            "get_temperature_unit",
            "get_config_version",
            "get_device_name",
            "get_output_amps",
            "get_language",
            "get_lcd_brightness",
            "set_time",
            "get_time",
        }:
            raise CommandFailed("Charger is not authenticated")
        await super()._send_command(
            command, payload, name=name, start_response=start_response
        )

    def receive(self, packet: ParsedPacket, addr: tuple[str, int]) -> None:
        """Learn source port/address only for the serial routed by the hub."""
        if self._stopping or not self._active:
            return
        if self._state.info.serial is None:
            self._update_info(serial=packet.identifier)
        self.host, self.port = addr
        self._last_message = time.monotonic()
        task = asyncio.create_task(
            self._async_handle_packet(
                packet.command,
                packet.data,
                packet.identifier,
                generation=self._connection_generation,
            )
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_task_done)

    async def _async_handle_packet_locked(
        self, command: int, data: bytes, identifier: str
    ) -> None:
        # BS20 firmware broadcasts metadata even after successful registration.
        # The shared handler updates it without invalidating authentication;
        # only heartbeat expiry proves that the push registration has expired.
        await super()._async_handle_packet_locked(command, data, identifier)
        if command == 2 and self._state.authenticated:
            self._last_heading = time.monotonic()
            await self._send_command(0x800D, None, name="get_status")
            await self._send_command(0x8006, None, name="get_session")
        if command == 3 and self._state.authenticated:
            self._last_heading = time.monotonic()
            self._heading_received.set()
            if self._state.config.temperature_unit is None:
                await self._send_command(0x8112, [2, 0], name="get_temperature_unit")
        if command in (4, 5) and self._state.authenticated:
            await self._send_command(
                0x8004 if command == 4 else 0x8005,
                None if command == 4 else [0],
                name="acknowledge_status",
            )

    async def _watchdog_loop(self) -> None:
        while not self._stopping and not self._auth_failed:
            await asyncio.sleep(5)
            if (
                self._state.authenticated
                and time.monotonic() - self._last_heading > HEARTBEAT_TIMEOUT
            ):
                self._set_state(
                    available=False,
                    authenticated=False,
                    last_error="LAN heartbeat expired; reconnecting",
                )
                self._schedule_reconnect()
