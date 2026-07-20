from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class SSH2_KexParty:
    def __init__(self, enc: List[str], mac: List[str], compression: List[str], languages: List[str]) -> None:
        self.__enc = enc
        self.__mac = mac
        self.__compression = compression
        self.__languages = languages

    @property
    def encryption(self) -> List[str]:
        pass

    @property
    def mac(self) -> List[str]:
        pass

    @property
    def compression(self) -> List[str]:
        pass

    @property
    def languages(self) -> List[str]:
        pass

    def __str__(self) -> str:
        ret = "Ciphers: " + ", ".join(self.__enc)
        ret += "\nMACs: " + ", ".join(self.__mac)
        ret += "\nCompressions: " + ", ".join(self.__compression)
        ret += "\nLanguages: " + ", ".join(self.__languages)
        return ret
