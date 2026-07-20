from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.algorithm import Algorithm
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.timeframe import Timeframe
from ssh_audit.utils import Utils


class Algorithms:
    def __init__(self, kex: Optional[SSH2_Kex]) -> None:
        self.__ssh2kex = kex

    @property
    def ssh2kex(self) -> Optional[SSH2_Kex]:
        pass

    @property
    def ssh2(self) -> Optional['Algorithms.Item']:
        pass

    @property
    def values(self) -> Iterable['Algorithms.Item']:
        for item in [self.ssh2]:
            if item is not None:
                yield item

    @property
    def maxlen(self) -> int:
        pass

    def get_ssh_timeframe(self, for_server: Optional[bool] = None) -> 'Timeframe':
        timeframe = Timeframe()
        for alg_pair in self.values:
            alg_db = alg_pair.db
            for alg_type, alg_list in alg_pair.items():
                for alg_name in alg_list:
                    alg_name_native = Utils.to_text(alg_name)
                    alg_desc = alg_db[alg_type].get(alg_name_native)
                    if alg_desc is None:
                        continue
                    versions = alg_desc[0]
                    timeframe.update(versions, for_server)
        return timeframe

    def get_recommendations(self, software: Optional['Software'], for_server: bool = True) -> Tuple[Optional['Software'], Dict[int, Dict[str, Dict[str, Dict[str, int]]]]]:
        vproducts = [Product.OpenSSH,
                     Product.DropbearSSH,
                     Product.LibSSH,
                     Product.TinySSH]
        unknown_software = False
        if software is not None:
            if software.product not in vproducts:
                unknown_software = True

        rec: Dict[int, Dict[str, Dict[str, Dict[str, int]]]] = {}
        if software is None:
            unknown_software = True
        for alg_pair in self.values:
            sshv, alg_db = alg_pair.sshv, alg_pair.db
            rec[sshv] = {}
            for alg_type, alg_list in alg_pair.items():
                rec[sshv][alg_type] = {'add': {}, 'del': {}, 'chg': {}}
                for n, alg_desc in alg_db[alg_type].items():
                    versions = alg_desc[0]
                    empty_version = False
                    if len(versions) == 0 or versions[0] is None:
                        empty_version = True
                    else:
                        matches = False
                        if unknown_software:
                            matches = True
                        for v in versions[0].split(','):
                            ssh_prefix, ssh_version, is_cli = Algorithm.get_ssh_version(v)
                            if not ssh_version:
                                continue
                            if (software is not None) and (ssh_prefix != software.product):
                                continue
                            if is_cli and for_server:
                                continue
                            if (software is not None) and (software.compare_version(ssh_version) < 0):
                                continue
                            matches = True
                            break
                        if not matches:
                            continue
                    adl, faults = len(alg_desc), 0
                    for i in range(1, 3):
                        if not adl > i:
                            continue
                        fc = len(alg_desc[i])
                        if fc > 0:
                            faults += pow(10, 2 - i) * fc
                    if n not in alg_list:
                        if faults > 0 or \
                           (alg_type == 'key' and (('-cert-' in n) or (n.startswith('sk-')))) or \
                           (alg_type == 'kex' and (n.startswith('ext-info-') or n.startswith('kex-strict-'))) or \
                           empty_version:
                            continue
                        rec[sshv][alg_type]['add'][n] = 0
                    else:
                        if faults == 0:
                            continue
                        if n in ['diffie-hellman-group-exchange-sha256', 'rsa-sha2-256', 'rsa-sha2-512', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com']:
                            rec[sshv][alg_type]['chg'][n] = faults
                        else:
                            rec[sshv][alg_type]['del'][n] = faults
                if unknown_software:
                    rec[sshv][alg_type]['add'] = {}
                add_count = len(rec[sshv][alg_type]['add'])
                del_count = len(rec[sshv][alg_type]['del'])
                chg_count = len(rec[sshv][alg_type]['chg'])

                if add_count == 0:
                    del rec[sshv][alg_type]['add']
                if del_count == 0:
                    del rec[sshv][alg_type]['del']
                if chg_count == 0:
                    del rec[sshv][alg_type]['chg']
                if len(rec[sshv][alg_type]) == 0:
                    del rec[sshv][alg_type]
            if len(rec[sshv]) == 0:
                del rec[sshv]
        return software, rec

    class Item:
        def __init__(self, sshv: int, db: Dict[str, Dict[str, List[List[Optional[str]]]]]) -> None:
            self.__sshv = sshv
            self.__db = db
            self.__storage: Dict[str, List[str]] = {}

        @property
        def sshv(self) -> int:
            pass

        @property
        def db(self) -> Dict[str, Dict[str, List[List[Optional[str]]]]]:
            pass

        def add(self, key: str, value: List[str]) -> None:
            self.__storage[key] = value

        def items(self) -> Iterable[Tuple[str, List[str]]]:
            return self.__storage.items()
