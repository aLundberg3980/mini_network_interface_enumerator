"""Portable network interface enumeration using only the standard library.

On Linux we use ``socket.if_nameindex`` plus ``fcntl.ioctl`` with the legacy
``SIOCGIF*`` requests.  Those ioctls return C ``struct ifreq`` buffers whose
layout is fixed by the kernel ABI; we slice the first 16 bytes for the name
and the next 4 bytes for the address.  We deliberately do not try to parse
``/proc/net/dev`` because that file is Linux-specific and does not carry
addresses.

On platforms without those ioctls (macOS, Windows, BSD) we fall back to
``socket.getaddrinfo`` over the loopback host and the host's own name.  That
is best-effort: it discovers addresses that the resolver knows about, which
is not the same as a full interface table.  The trade-off is portability
versus completeness; the library documents this rather than pretending to
be a portable ``getifaddrs``.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

__all__ = ["Interface", "list_interfaces"]


@dataclass(frozen=True)
class Interface:
    """A single network interface and its associated addresses.

    ``flags`` is a set of lower-case strings such as ``"up"`` or
    ``"loopback"``.  ``address`` and ``netmask`` are dotted-quad strings for
    IPv4 interfaces; they are ``None`` when the interface has no address or
    when the platform did not report one.
    """

    name: str
    address: Optional[str]
    netmask: Optional[str]
    flags: frozenset

    def is_up(self) -> bool:
        """Return True when the kernel reports the interface as up."""
        return "up" in self.flags


# Linux ioctl request numbers.  These are stable ABI values from
# <linux/sockios.h>.  They are defined here rather than imported from fcntl
# because fcntl does not export them on every platform.
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B
_SIOCGIFFLAGS = 0x8913

# struct ifreq is 40 bytes on 32-bit and 64-bit Linux.  The name field is
# IFNAMSIZ (16) bytes and the union that follows is at least 16 bytes; the
# address occupies the first 4 bytes of that union.
_IFREQ_SIZE = 40
_IFNAMSIZ = 16


def _has_linux_ioctls() -> bool:
    """Return True when the running interpreter can use the Linux ioctls."""
    try:
        import fcntl  # noqa: F401
    except ImportError:
        return False
    return hasattr(socket, "if_nameindex")


def _encode_ifreq(name: str) -> bytes:
    """Build a zero-padded ifreq buffer carrying just the interface name."""
    encoded = name.encode("ascii", "strict")
    if len(encoded) >= _IFNAMSIZ:
        raise ValueError("interface name too long: %r" % (name,))
    return encoded + b"\x00" * (_IFREQ_SIZE - len(encoded))


def _ioctl_address(sock: socket.socket, name: str, request: int) -> Optional[str]:
    """Run one of the SIOCGIF* address ioctls and decode the result.

    Returns ``None`` when the kernel reports no address for the interface
    (for example a down interface), rather than raising, because a missing
    address is a normal state and callers should not have to catch OSError
    to discover it.
    """
    import fcntl

    buf = _encode_ifreq(name)
    try:
        result = fcntl.ioctl(sock.fileno(), request, buf)
    except OSError:
        return None
    # The address lives at offset IFNAMSIZ in the returned union.
    packed = result[_IFNAMSIZ:_IFNAMSIZ + 4]
    if len(packed) != 4:
        return None
    return socket.inet_ntoa(packed)


def _ioctl_flags(sock: socket.socket, name: str) -> frozenset:
    """Return the interface flags as a frozenset of lower-case names."""
    import fcntl

    buf = _encode_ifreq(name)
    try:
        result = fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, buf)
    except OSError:
        return frozenset()
    # struct ifreq: char name[16]; short flags; ...  The short is at offset 16.
    (raw,) = struct.unpack_from("H", result, _IFNAMSIZ)
    return _decode_flags(raw)


# Linux IFF_* flag bits.  Only the ones we can name meaningfully are listed;
# unknown bits are ignored rather than surfaced as opaque numbers.
_IFF_UP = 0x1
_IFF_BROADCAST = 0x2
_IFF_LOOPBACK = 0x8
_IFF_POINTOPOINT = 0x10
_IFF_RUNNING = 0x40
_IFF_MULTICAST = 0x1000


def _decode_flags(raw: int) -> frozenset:
    """Translate a raw Linux flags word into a set of readable names."""
    names = []
    if raw & _IFF_UP:
        names.append("up")
    if raw & _IFF_BROADCAST:
        names.append("broadcast")
    if raw & _IFF_LOOPBACK:
        names.append("loopback")
    if raw & _IFF_POINTOPOINT:
        names.append("pointopoint")
    if raw & _IFF_RUNNING:
        names.append("running")
    if raw & _IFF_MULTICAST:
        names.append("multicast")
    return frozenset(names)


def _list_interfaces_linux() -> List[Interface]:
    """Enumerate interfaces using Linux ioctls."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        interfaces = []
        for index, name in socket.if_nameindex():
            del index  # the index is not part of our public model
            address = _ioctl_address(sock, name, _SIOCGIFADDR)
            netmask = _ioctl_address(sock, name, _SIOCGIFNETMASK)
            flags = _ioctl_flags(sock, name)
            interfaces.append(
                Interface(
                    name=name,
                    address=address,
                    netmask=netmask,
                    flags=flags,
                )
            )
        return interfaces
    finally:
        sock.close()


def _list_interfaces_fallback() -> List[Interface]:
    """Best-effort enumeration for platforms without the Linux ioctls.

    We resolve the loopback name and the local host name.  This is not a
    full interface table, but it gives callers something portable and
    honest: an entry named ``"loopback"`` for 127.0.0.1 and an entry for
    the local host name when the resolver can produce an IPv4 address.
    Duplicate addresses are collapsed.
    """
    seen: List[Tuple[str, str]] = []

    def add(name: str, host: str) -> None:
        try:
            infos = socket.getaddrinfo(
                host, None, socket.AF_INET, socket.SOCK_DGRAM
            )
        except socket.gaierror:
            return
        for info in infos:
            addr = info[4][0]
            pair = (name, addr)
            if pair not in seen:
                seen.append(pair)

    add("loopback", "127.0.0.1")
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    if hostname:
        add(hostname, hostname)

    results = []
    for name, addr in seen:
        flags = frozenset(["up", "loopback"] if name == "loopback" else ["up"])
        # We cannot discover the real netmask through getaddrinfo; the
        # loopback mask is well known, everything else is left as None
        # rather than guessed.
        netmask = "255.0.0.0" if name == "loopback" else None
        results.append(
            Interface(name=name, address=addr, netmask=netmask, flags=flags)
        )
    return results


def list_interfaces() -> List[Interface]:
    """Return the network interfaces visible to this process.

    On Linux the result comes from ``socket.if_nameindex`` and the
    ``SIOCGIFADDR``/``SIOCGIFNETMASK``/``SIOCGIFFLAGS`` ioctls.  On other
    platforms a resolver-based fallback is used; see the module docstring
    for the trade-off.
    """
    if _has_linux_ioctls():
        return _list_interfaces_linux()
    return _list_interfaces_fallback()
