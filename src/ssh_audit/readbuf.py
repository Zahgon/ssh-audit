import io
import struct

from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class ReadBuf:
    def __init__(self, data: Optional[bytes] = None) -> None:
        super(ReadBuf, self).__init__()
        self._buf = io.BytesIO(data) if data is not None else io.BytesIO()
        self._len = len(data) if data is not None else 0

    @property
    def unread_len(self) -> int:
        pass

    def read(self, size: int) -> bytes:
        return self._buf.read(size)

    def read_byte(self) -> int:
        v: int = struct.unpack('B', self.read(1))[0]
        return v

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_int(self) -> int:
        v: int = struct.unpack('>I', self.read(4))[0]
        return v

    def read_list(self) -> List[str]:
        list_size = self.read_int()
        return self.read(list_size).decode('utf-8', 'replace').split(',')

    def read_string(self) -> bytes:
        pass

    @classmethod
    def _parse_mpint(cls, v: bytes, pad: bytes, f: str) -> int:
        pass

    def read_mpint1(self) -> int:
        pass

    def read_mpint2(self) -> int:
        pass

    def read_line(self) -> str:
        return self._buf.readline().rstrip().decode('utf-8', 'replace')

    def reset(self) -> None:
        self._buf = io.BytesIO()
        self._len = 0
