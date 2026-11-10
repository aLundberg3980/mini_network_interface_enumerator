import socket
import unittest

from mini_network_interface_enumerator import Interface, list_interfaces
from mini_network_interface_enumerator import core


class InterfaceTests(unittest.TestCase):
    def test_is_up_true(self):
        iface = Interface(
            name="eth0",
            address="10.0.0.1",
            netmask="255.255.255.0",
            flags=frozenset(["up", "broadcast"]),
        )
        self.assertTrue(iface.is_up())

    def test_is_up_false(self):
        iface = Interface(
            name="eth0",
            address=None,
            netmask=None,
            flags=frozenset(["broadcast"]),
        )
        self.assertFalse(iface.is_up())

    def test_is_frozen(self):
        iface = Interface(
            name="eth0",
            address=None,
            netmask=None,
            flags=frozenset(),
        )
        with self.assertRaises(Exception):
            iface.name = "eth1"  # type: ignore[misc]


class FlagDecodingTests(unittest.TestCase):
    def test_empty_flags(self):
        self.assertEqual(core._decode_flags(0), frozenset())

    def test_up_and_loopback(self):
        self.assertEqual(
            core._decode_flags(core._IFF_UP | core._IFF_LOOPBACK),
            frozenset(["up", "loopback"]),
        )

    def test_all_known_flags(self):
        raw = (
            core._IFF_UP
            | core._IFF_BROADCAST
            | core._IFF_LOOPBACK
            | core._IFF_POINTOPOINT
            | core._IFF_RUNNING
            | core._IFF_MULTICAST
        )
        self.assertEqual(
            core._decode_flags(raw),
            frozenset(
                [
                    "up",
                    "broadcast",
                    "loopback",
                    "pointopoint",
                    "running",
                    "multicast",
                ]
            ),
        )

    def test_unknown_bits_are_ignored(self):
        # Bit 31 is not in our table; it must not produce a name.
        self.assertEqual(core._decode_flags(0x80000000), frozenset())


class IfreqEncodingTests(unittest.TestCase):
    def test_buffer_is_forty_bytes(self):
        buf = core._encode_ifreq("eth0")
        self.assertEqual(len(buf), 40)

    def test_name_is_nul_padded(self):
        buf = core._encode_ifreq("eth0")
        self.assertEqual(buf[:4], b"eth0")
        self.assertEqual(buf[4:16], b"\x00" * 12)

    def test_long_name_rejected(self):
        with self.assertRaises(ValueError):
            core._encode_ifreq("x" * 16)

    def test_non_ascii_name_rejected(self):
        with self.assertRaises(UnicodeEncodeError):
            core._encode_ifreq("eth\u00e9")


class ListInterfacesTests(unittest.TestCase):
    def test_returns_a_list(self):
        result = list_interfaces()
        self.assertIsInstance(result, list)
        for item in result:
            self.assertIsInstance(item, Interface)

    def test_names_are_non_empty_strings(self):
        for item in list_interfaces():
            self.assertIsInstance(item.name, str)
            self.assertTrue(item.name)

    def test_flags_are_frozensets(self):
        for item in list_interfaces():
            self.assertIsInstance(item.flags, frozenset)
            for flag in item.flags:
                self.assertIsInstance(flag, str)

    def test_address_is_none_or_ipv4_string(self):
        for item in list_interfaces():
            if item.address is None:
                continue
            # inet_aton raises OSError for malformed dotted quads.
            socket.inet_aton(item.address)

    def test_netmask_is_none_or_ipv4_string(self):
        for item in list_interfaces():
            if item.netmask is None:
                continue
            socket.inet_aton(item.netmask)

    def test_loopback_is_present_and_up(self):
        # Every platform this library targets has a loopback interface.
        names = {item.name for item in list_interfaces()}
        self.assertIn("lo", names | {"loopback"})
        loopbacks = [
            item
            for item in list_interfaces()
            if item.name in ("lo", "loopback")
        ]
        self.assertTrue(loopbacks)
        self.assertTrue(any(item.is_up() for item in loopbacks))


class FallbackTests(unittest.TestCase):
    def test_fallback_contains_loopback(self):
        result = core._list_interfaces_fallback()
        names = {item.name for item in result}
        self.assertIn("loopback", names)

    def test_fallback_loopback_address(self):
        result = core._list_interfaces_fallback()
        loopback = [item for item in result if item.name == "loopback"]
        self.assertEqual(len(loopback), 1)
        self.assertEqual(loopback[0].address, "127.0.0.1")
        self.assertEqual(loopback[0].netmask, "255.0.0.0")
        self.assertIn("up", loopback[0].flags)
        self.assertIn("loopback", loopback[0].flags)


if __name__ == "__main__":
    unittest.main()
