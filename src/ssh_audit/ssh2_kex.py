from typing import Dict, List
from typing import Union

from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.readbuf import ReadBuf
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.writebuf import WriteBuf


class SSH2_Kex:
    def __init__(self, outputbuffer: 'OutputBuffer', cookie: bytes, kex_algs: List[str], key_algs: List[str], cli: 'SSH2_KexParty', srv: 'SSH2_KexParty', follows: bool, unused: int = 0) -> None:  # pylint: disable=too-many-arguments
        self.__outputbuffer = outputbuffer
        self.__cookie = cookie
        self.__kex_algs = kex_algs
        self.__key_algs = key_algs
        self.__client = cli
        self.__server = srv
        self.__follows = follows
        self.__unused = unused

        self.__dh_modulus_sizes: Dict[str, int] = {}
        self.__host_keys: Dict[str, Dict[str, Union[bytes, str, int]]] = {}

    @property
    def cookie(self) -> bytes:
        pass

    @property
    def kex_algorithms(self) -> List[str]:
        pass

    @property
    def key_algorithms(self) -> List[str]:
        pass

    @property
    def client(self) -> 'SSH2_KexParty':
        pass

    @property
    def server(self) -> 'SSH2_KexParty':
        pass

    @property
    def follows(self) -> bool:
        pass

    @property
    def unused(self) -> int:
        pass

    def set_dh_modulus_size(self, gex_alg: str, modulus_size: int) -> None:
        self.__dh_modulus_sizes[gex_alg] = modulus_size

    def dh_modulus_sizes(self) -> Dict[str, int]:
        return self.__dh_modulus_sizes

    def set_host_key(self, key_type: str, raw_hostkey_bytes: bytes, hostkey_size: int, ca_key_type: str, ca_key_size: int) -> None:

        if key_type not in self.__host_keys:
            self.__host_keys[key_type] = {'raw_hostkey_bytes': raw_hostkey_bytes, 'hostkey_size': hostkey_size, 'ca_key_type': ca_key_type, 'ca_key_size': ca_key_size}
        else:  # A host key may only have one CA signature...
            self.__outputbuffer.d("WARNING: called SSH2_Kex.set_host_key() multiple times with the same host key type (%s)!  Existing info: %r, %r, %r; Duplicate (ignored) info: %r, %r, %r" % (key_type, self.__host_keys[key_type]['hostkey_size'], self.__host_keys[key_type]['ca_key_type'], self.__host_keys[key_type]['ca_key_size'], hostkey_size, ca_key_type, ca_key_size))

    def host_keys(self) -> Dict[str, Dict[str, Union[bytes, str, int]]]:
        return self.__host_keys

    def write(self, wbuf: 'WriteBuf') -> None:
        wbuf.write(self.cookie)
        wbuf.write_list(self.kex_algorithms)
        wbuf.write_list(self.key_algorithms)
        wbuf.write_list(self.client.encryption)
        wbuf.write_list(self.server.encryption)
        wbuf.write_list(self.client.mac)
        wbuf.write_list(self.server.mac)
        wbuf.write_list(self.client.compression)
        wbuf.write_list(self.server.compression)
        wbuf.write_list(self.client.languages)
        wbuf.write_list(self.server.languages)
        wbuf.write_bool(self.follows)
        wbuf.write_int(self.__unused)

    @property
    def payload(self) -> bytes:
        pass

    @classmethod
    def parse(cls, outputbuffer: 'OutputBuffer', payload: bytes) -> 'SSH2_Kex':
        buf = ReadBuf(payload)
        cookie = buf.read(16)
        kex_algs = buf.read_list()
        key_algs = buf.read_list()
        cli_enc = buf.read_list()
        srv_enc = buf.read_list()
        cli_mac = buf.read_list()
        srv_mac = buf.read_list()
        cli_compression = buf.read_list()
        srv_compression = buf.read_list()
        cli_languages = buf.read_list()
        srv_languages = buf.read_list()
        follows = buf.read_bool()
        unused = buf.read_int()
        cli = SSH2_KexParty(cli_enc, cli_mac, cli_compression, cli_languages)
        srv = SSH2_KexParty(srv_enc, srv_mac, srv_compression, srv_languages)
        kex = cls(outputbuffer, cookie, kex_algs, key_algs, cli, srv, follows, unused)
        return kex

    def __str__(self) -> str:
        ret = "----\nSSH2_Kex object:"
        ret += "\nHost keys: "
        ret += ", ".join(self.__key_algs)
        ret += "\nKey exchanges: "
        ret += ", ".join(self.__kex_algs)
        ret += "\nClient SSH2_KexParty:"
        ret += "\n" + str(self.__client)
        ret += "\nServer SSH2_KexParty:"
        ret += "\n" + str(self.__server)
        ret += "\n----"
        return ret
