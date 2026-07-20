import base64
import hashlib


class Fingerprint:
    def __init__(self, fpd: bytes) -> None:
        self.__fpd = fpd

    @property
    def md5(self) -> str:
        pass

    @property
    def sha256(self) -> str:
        pass
