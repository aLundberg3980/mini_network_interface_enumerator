# mini_network_interface_enumerator

List network interface names, IPv4 addresses, netmasks and flags using only the
Python standard library.

```python
from mini_network_interface_enumerator import list_interfaces

for iface in list_interfaces():
    print(iface.name, iface.address, iface.netmask, sorted(iface.flags))
```

`list_interfaces()` returns a list of `Interface` values.  Each `Interface` has
four attributes:

- `name` — the interface name, e.g. `"lo"` or `"eth0"`.
- `address` — the IPv4 address as a dotted-quad string, or `None`.
- `netmask` — the IPv4 netmask as a dotted-quad string, or `None`.
- `flags` — a `frozenset` of lower-case flag names such as `"up"`,
  `"loopback"`, `"broadcast"`, `"running"` and `"multicast"`.

`Interface.is_up()` is a convenience method that checks for `"up"` in `flags`.

## Why this exists

The standard library has `socket.if_nameindex()`, which gives you names but not
addresses or flags, and `socket.getaddrinfo()`, which gives you addresses but
not interface names.  Getting both at once usually means pulling in a
C-extension package such as `netifaces` or `psutil`.  This library wraps the
Linux `SIOCGIFADDR`, `SIOCGIFNETMASK` and `SIOCGIFFLAGS` ioctls directly so a
small tool can stay dependency-free.

The trade-off is portability.  The ioctl path is Linux-only.  On other
platforms the library falls back to resolving `127.0.0.1` and the local
hostname, which produces a much smaller table and cannot report real netmasks.
That fallback is honest about what it knows: it never invents an address, and
`netmask` is `None` unless the mask is well known (loopback).

## The awkward edge

On Linux, an interface that is down may still appear in
`socket.if_nameindex()` but the address ioctls will fail for it.  In that case
`address` and `netmask` are `None` rather than raising `OSError`.  Code that
assumes every interface has an address will break on a machine with a
disabled interface; check for `None` before formatting.

Interface names longer than 15 bytes are rejected by the encoder with a
`ValueError`.  The kernel limit is `IFNAMSIZ - 1`, so this only triggers for
names the kernel would not accept in the first place.
