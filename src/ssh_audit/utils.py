import ipaddress
import re
import sys

from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class Utils:
    @classmethod
    def _type_err(cls, v: Any, target: str) -> TypeError:
        return TypeError('cannot convert {} to {}'.format(type(v), target))

    @classmethod
    def to_bytes(cls, v: Union[bytes, str], enc: str = 'utf-8') -> bytes:
        pass

    @classmethod
    def to_text(cls, v: Union[str, bytes], enc: str = 'utf-8') -> str:
        if isinstance(v, str):
            return v
        elif isinstance(v, bytes):
            return v.decode(enc)
        raise cls._type_err(v, 'unicode text')

    @classmethod
    def _is_ascii(cls, v: str, char_filter: Callable[[int], bool] = lambda x: x <= 127) -> bool:
        r = False
        if isinstance(v, str):
            for c in v:
                i = cls.ctoi(c)
                if not char_filter(i):
                    return r
            r = True
        return r

    @classmethod
    def _to_ascii(cls, v: str, char_filter: Callable[[int], bool] = lambda x: x <= 127, errors: str = 'replace') -> str:
        if isinstance(v, str):
            r = bytearray()
            for c in v:
                i = cls.ctoi(c)
                if char_filter(i):
                    r.append(i)
                else:
                    if errors == 'ignore':
                        continue
                    r.append(63)
            return cls.to_text(r.decode('ascii'))
        raise cls._type_err(v, 'ascii')

    @classmethod
    def is_ascii(cls, v: str) -> bool:
        pass

    @classmethod
    def to_ascii(cls, v: str, errors: str = 'replace') -> str:
        pass

    @classmethod
    def is_print_ascii(cls, v: str) -> bool:
        return cls._is_ascii(v, lambda x: 126 >= x >= 32)

    @classmethod
    def to_print_ascii(cls, v: str, errors: str = 'replace') -> str:
        return cls._to_ascii(v, lambda x: 126 >= x >= 32, errors)

    @classmethod
    def unique_seq(cls, seq: Sequence[Any]) -> Sequence[Any]:
        pass

    @classmethod
    def ctoi(cls, c: Union[str, int]) -> int:
        if isinstance(c, str):
            return ord(c[0])
        else:
            return c

    @staticmethod
    def parse_int(v: Any) -> int:
        try:
            return int(v)
        except ValueError:
            return 0

    @staticmethod
    def parse_float(v: Any) -> float:
        pass

    @staticmethod
    def parse_host_and_port(host_and_port: str, default_port: int = 22) -> Tuple[str, int]:
        '''Parses a string into a tuple of its host and port.  The port is 0 if not specified.'''
        host = host_and_port
        port = default_port

        if host.startswith("unix://"):
            return host, 1

        mx = re.match(r'^\[([^\]]+)\](?::(\d+))?$', host_and_port)
        if mx is not None:
            host = mx.group(1)
            port_str = mx.group(2)
            if port_str is not None:
                port = int(port_str)
        else:
            s = host_and_port.split(':')
            if len(s) == 2:
                host = s[0]
                if len(s[1]) > 0:
                    port = int(s[1])

        return host, port

    @staticmethod
    def is_ipv4_address(address: str) -> bool:
        '''Returns True if address is an IPv4 address, otherwise False.'''
        is_ipv4 = True
        try:
            ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            is_ipv4 = False

        return is_ipv4

    @staticmethod
    def is_ipv6_address(address: str) -> bool:
        '''Returns True if address is an IPv6 address, otherwise False.'''
        is_ipv6 = True
        try:
            ipaddress.IPv6Address(address)
        except ipaddress.AddressValueError:
            is_ipv6 = False

        return is_ipv6

    @staticmethod
    def is_windows() -> bool:
        return sys.platform in ['win32', 'cygwin']
