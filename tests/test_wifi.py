"""Provisioning byte limits, layout selection and safe BLE fragmentation."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from besen import client as client_module
from besen.client import BesenClient
from besen.exceptions import CannotConnect, CommandFailed
from besen.models import BoardRevision, CharacteristicPair
from besen.protocol import PacketAssembler
from besen.wifi import wifi_payload


@pytest.mark.parametrize(
    ("feature", "ssid_bytes", "password_bytes", "length"),
    [(1490681806, 32, 64, 105), (1490681306, 15, 16, 41)],
)
def test_wifi_wire_layout(
    feature: int, ssid_bytes: int, password_bytes: int, length: int
) -> None:
    """Match app-derived slots, UTF-8 encoding, zero padding and listener port."""
    slot = 32 if length == 105 else 16
    result = wifi_payload(feature, "x" * ssid_bytes, "y" * password_bytes)
    assert len(result) == length
    assert result[0] == 1
    assert result[1 : 1 + slot] == (b"x" * ssid_bytes).ljust(slot, b"\0")
    assert result[1 + slot : -2].rstrip(b"\0") == b"y" * password_bytes
    assert result[-2:] == b"\x6e\xd8"
    assert wifi_payload(feature, "é", "סוד")[1:3] == "é".encode()
    for ssid, password in (
        ("x" * (ssid_bytes + 1), "y"),
        ("x", "y" * (password_bytes + 1)),
    ):
        with pytest.raises(ValueError):
            wifi_payload(feature, ssid, password)


@pytest.mark.parametrize("feature", [None, 0, 999])
def test_unknown_feature_fails_closed(feature: int | None) -> None:
    with pytest.raises(ValueError, match="capabilities"):
        wifi_payload(feature, "network", "password")


@pytest.mark.parametrize(
    ("ssid", "password"),
    [
        ("", "pw"),
        ("net", ""),
        ("a\0b", "pw"),
        ("net", "pw\0"),
        ("é" * 17, "pw"),
        ("net", "é" * 33),
    ],
)
def test_invalid_credentials(ssid: str, password: str) -> None:
    with pytest.raises(ValueError):
        wifi_payload(1490681806, ssid, password)


@pytest.mark.parametrize("mtu", [23, 185])
async def test_provisioning_fragments_without_retaining_password(mtu: int) -> None:
    """The complete frame survives minimum-MTU writes in the selected mode."""
    client = BesenClient(
        address="test",
        pin="123456",
        ble_device_provider=lambda: None,
        logger=logging.getLogger(__name__),
    )
    fake = AsyncMock()
    fake.is_connected = True
    fake.mtu_size = mtu
    fake.services = Mock()
    fake.services.get_characteristic.return_value = SimpleNamespace(
        properties=["write"]
    )
    client._client = fake
    client._characteristics = CharacteristicPair(
        "read", "write", BoardRevision.OLD, False
    )
    serial = "1234567890ABCDEF"
    client._update_info(serial=serial, feature=1490681806)
    with pytest.raises(CommandFailed, match="authenticated"):
        await client.async_configure_wifi("network", "private-password")
    client._set_state(authenticated=True)
    received = PacketAssembler()

    async def acknowledge(uuid: str, chunk: bytes, *, response: bool) -> None:
        for _packet in received.feed(chunk):
            await client._async_handle_packet(0x010A, b"\x01private-password", serial)

    fake.write_gatt_char.side_effect = acknowledge
    await client.async_configure_wifi("network", "private-password")
    chunks = [call.args[1] for call in fake.write_gatt_char.await_args_list]
    assert all(len(chunk) <= mtu - 3 for chunk in chunks)
    assert all(
        call.kwargs["response"] is True for call in fake.write_gatt_char.await_args_list
    )
    assembler = PacketAssembler()
    packets = [packet for chunk in chunks for packet in assembler.feed(chunk)]
    assert len(packets) == 1
    assert packets[0].command == 0x810A
    assert packets[0].identifier == serial
    assert client.wifi_acknowledgement == 1
    assert len(packets[0].data) == 105
    assert "private-password" not in repr(client.state)


async def test_wifi_delivery_timeout_keeps_credentials_out_of_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = BesenClient(
        address="test",
        pin="123456",
        ble_device_provider=lambda: None,
        logger=logging.getLogger(__name__),
    )
    client._update_info(serial="1234567890ABCDEF", feature=1490681806)
    client._set_state(authenticated=True)
    client._send_command = AsyncMock()  # type: ignore[method-assign]
    monkeypatch.setattr(client_module, "WIFI_SETUP_TIMEOUT", 0.01)
    with pytest.raises(CannotConnect, match="acknowledge"):
        await client.async_configure_wifi("network", "private-password")
    assert client._wifi_response is None
    assert client.wifi_acknowledgement is None
    assert "private-password" not in repr(client.state)


async def test_wifi_ack_is_correlated_and_does_not_claim_network_success() -> None:
    client = BesenClient(
        address="test",
        pin="123456",
        ble_device_provider=lambda: None,
        logger=logging.getLogger(__name__),
    )
    serial = "1234567890ABCDEF"
    client._update_info(serial=serial, feature=1490681806)
    client._set_state(authenticated=True)
    client._send_command = AsyncMock()  # type: ignore[method-assign]
    task = asyncio.create_task(
        client.async_configure_wifi("network", "private-password")
    )
    await asyncio.sleep(0)
    await client._async_handle_packet(0x010A, b"", serial)
    await client._async_handle_packet(0x010A, b"\x09private-password", "other")
    assert not task.done()
    await client._async_handle_packet(0x010A, b"\x09private-password", serial)
    assert await task == 9
    assert client.wifi_acknowledgement == 9
    assert client._wifi_response is None
    assert "private-password" not in repr(client.state)
    # Some firmware echoes credentials; a reply must never enter diagnostics state.
    await client._async_handle_packet(0x010A, b"private-password", serial)
    assert "private-password" not in repr(client.state)
