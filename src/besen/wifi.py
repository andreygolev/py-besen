"""Wi-Fi provisioning format recovered from EVSEMaster 3.1.38."""

from __future__ import annotations

UDP_PORT = 28376


def wifi_payload(feature: int | None, ssid: str, password: str) -> bytes:
    """Validate UTF-8 byte limits and build the firmware-specific SET payload.

    The decimal feature subfield selects the layout, as in the official app.
    Unknown capabilities are deliberately rejected instead of guessed.
    """
    if feature is None or feature < 1000:
        raise ValueError("Wi-Fi capabilities are not available yet")
    extended = int(str(feature)[-4:-2]) > 13
    ssid_size, password_size = (32, 70) if extended else (16, 22)
    ssid_limit, password_limit = (32, 64) if extended else (15, 16)
    if not ssid or "\x00" in ssid or len(ssid.encode()) > ssid_limit:
        raise ValueError(f"Network name must contain 1 to {ssid_limit} UTF-8 bytes")
    if not password or "\x00" in password or len(password.encode()) > password_limit:
        raise ValueError(f"Password must contain 1 to {password_limit} UTF-8 bytes")
    return (
        b"\x01"
        + ssid.encode().ljust(ssid_size, b"\x00")
        + password.encode().ljust(password_size, b"\x00")
        + UDP_PORT.to_bytes(2, "big")
    )
