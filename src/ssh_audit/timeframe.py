from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.algorithm import Algorithm


class Timeframe:
    def __init__(self) -> None:
        self.__storage: Dict[str, List[Optional[str]]] = {}

    def __contains__(self, product: str) -> bool:
        return product in self.__storage

    def __getitem__(self, product: str) -> Sequence[Optional[str]]:
        return tuple(self.__storage.get(product, [None] * 4))

    def __str__(self) -> str:
        return self.__storage.__str__()

    def __repr__(self) -> str:
        return self.__str__()

    def get_from(self, product: str, for_server: bool = True) -> Optional[str]:
        return self[product][0 if bool(for_server) else 2]

    def get_till(self, product: str, for_server: bool = True) -> Optional[str]:
        return self[product][1 if bool(for_server) else 3]

    def _update(self, versions: Optional[str], pos: int) -> None:
        ssh_versions: Dict[str, str] = {}
        for_srv, for_cli = pos < 2, pos > 1
        for v in (versions or '').split(','):
            ssh_prod, ssh_ver, is_cli = Algorithm.get_ssh_version(v)
            if not ssh_ver or (is_cli and for_srv) or (not is_cli and for_cli and ssh_prod in ssh_versions):
                continue
            ssh_versions[ssh_prod] = ssh_ver
        for ssh_product, ssh_version in ssh_versions.items():
            if ssh_product not in self.__storage:
                self.__storage[ssh_product] = [None] * 4
            prev = self[ssh_product][pos]
            if (prev is None or (prev < ssh_version and pos % 2 == 0) or (prev > ssh_version and pos % 2 == 1)):
                self.__storage[ssh_product][pos] = ssh_version

    def update(self, versions: List[Optional[str]], for_server: Optional[bool] = None) -> 'Timeframe':
        for_cli = for_server is None or for_server is False
        for_srv = for_server is None or for_server is True
        vlen = len(versions)
        for i in range(min(3, vlen)):
            if for_srv and i < 2:
                self._update(versions[i], i)
            if for_cli and (i % 2 == 0 or vlen == 2):
                self._update(versions[i], 3 - 0**i)
        return self
