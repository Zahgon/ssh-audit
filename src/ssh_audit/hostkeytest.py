
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

import traceback

from ssh_audit.kexdh import KexDH, KexDHException, KexGroup1, KexGroup14_SHA1, KexGroup14_SHA256, KexCurve25519_SHA256, KexGroup16_SHA512, KexGroup18_SHA512, KexGroupExchange_SHA1, KexGroupExchange_SHA256, KexNISTP256, KexNISTP384, KexNISTP521
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.outputbuffer import OutputBuffer


class HostKeyTest:
    RSA_FAMILY = ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']

    HOST_KEY_TYPES = {
        'ssh-rsa':      {'cert': False, 'variable_key_len': True},
        'rsa-sha2-256': {'cert': False, 'variable_key_len': True},
        'rsa-sha2-512': {'cert': False, 'variable_key_len': True},

        'ssh-rsa-cert-v01@openssh.com':      {'cert': True, 'variable_key_len': True},
        'rsa-sha2-256-cert-v01@openssh.com': {'cert': True, 'variable_key_len': True},
        'rsa-sha2-512-cert-v01@openssh.com': {'cert': True, 'variable_key_len': True},

        'ssh-ed25519':                      {'cert': False, 'variable_key_len': False},
        'ssh-ed25519-cert-v01@openssh.com': {'cert': True, 'variable_key_len': False},

        'ssh-ed448':                      {'cert': False, 'variable_key_len': False},

        'ecdsa-sha2-nistp256': {'cert': False, 'variable_key_len': False},
        'ecdsa-sha2-nistp384': {'cert': False, 'variable_key_len': False},
        'ecdsa-sha2-nistp521': {'cert': False, 'variable_key_len': False},

        'ecdsa-sha2-nistp256-cert-v01@openssh.com': {'cert': True, 'variable_key_len': False},
        'ecdsa-sha2-nistp384-cert-v01@openssh.com': {'cert': True, 'variable_key_len': False},
        'ecdsa-sha2-nistp521-cert-v01@openssh.com': {'cert': True, 'variable_key_len': False},

        'ssh-dss':                      {'cert': False, 'variable_key_len': True},
        'ssh-dss-cert-v01@openssh.com': {'cert': True,  'variable_key_len': True},
    }

    TWO2K_MODULUS_WARNING = '2048-bit modulus only provides 112-bits of symmetric strength'
    SMALL_ECC_MODULUS_WARNING = '224-bit ECC modulus only provides 112-bits of symmetric strength'


    @staticmethod
    def run(out: 'OutputBuffer', s: 'SSH_Socket', server_kex: 'SSH2_Kex') -> None:
        KEX_TO_DHGROUP = {
            'diffie-hellman-group1-sha1': KexGroup1,
            'diffie-hellman-group14-sha1': KexGroup14_SHA1,
            'diffie-hellman-group14-sha256': KexGroup14_SHA256,
            'curve25519-sha256': KexCurve25519_SHA256,
            'curve25519-sha256@libssh.org': KexCurve25519_SHA256,
            'diffie-hellman-group16-sha512': KexGroup16_SHA512,
            'diffie-hellman-group18-sha512': KexGroup18_SHA512,
            'diffie-hellman-group-exchange-sha1': KexGroupExchange_SHA1,
            'diffie-hellman-group-exchange-sha256': KexGroupExchange_SHA256,
            'ecdh-sha2-nistp256': KexNISTP256,
            'ecdh-sha2-nistp384': KexNISTP384,
            'ecdh-sha2-nistp521': KexNISTP521,
        }

        kex_str = None
        kex_group = None
        for server_kex_alg in server_kex.kex_algorithms:
            if server_kex_alg in KEX_TO_DHGROUP:
                kex_str = server_kex_alg
                kex_group = KEX_TO_DHGROUP[kex_str](out)
                break

        if kex_str is not None and kex_group is not None:
            HostKeyTest.perform_test(out, s, server_kex, kex_str, kex_group, HostKeyTest.HOST_KEY_TYPES)

    @staticmethod
    def perform_test(out: 'OutputBuffer', s: 'SSH_Socket', server_kex: 'SSH2_Kex', kex_str: str, kex_group: 'KexDH', host_key_types: Dict[str, Dict[str, bool]]) -> None:
        hostkey_modulus_size = 0
        ca_modulus_size = 0
        parsed_host_key_types = set()

        if s.is_connected():
            s.close()

        for host_key_type in host_key_types:
            key_fail_comments = []
            key_warn_comments = []

            if host_key_type in parsed_host_key_types:
                continue

            if host_key_type in server_kex.key_algorithms:
                out.d('Preparing to obtain ' + host_key_type + ' host key...', write_now=True)

                cert = host_key_types[host_key_type]['cert']

                if not s.is_connected():
                    err = s.connect()
                    if err is not None:
                        out.v(err, write_now=True)
                        return

                    _, _, err = s.get_banner()
                    if err is not None:
                        out.v(err, write_now=True)
                        s.close()
                        return

                    s.send_kexinit(key_exchanges=[kex_str], hostkeys=[host_key_type], ciphers=server_kex.server.encryption, macs=server_kex.server.mac, compressions=server_kex.server.compression, languages=server_kex.server.languages)

                    try:
                        _, payload = s.read_packet()
                        SSH2_Kex.parse(out, payload)
                    except Exception:
                        msg = "Failed to parse server's kex."
                        if not out.debug:
                            msg += "  Re-run in debug mode to see stack trace."

                        out.v(msg, write_now=True)
                        out.d("Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)
                        return

                kex_group.send_init(s)
                raw_hostkey_bytes = b''
                try:
                    kex_reply = kex_group.recv_reply(s)
                    raw_hostkey_bytes = kex_reply if kex_reply is not None else b''
                except KexDHException:
                    msg = "Failed to parse server's host key."
                    if not out.debug:
                        msg += "  Re-run in debug mode to see stack trace."

                    out.v(msg, write_now=True)
                    out.d("Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)

                    s.close()
                    continue

                hostkey_modulus_size = kex_group.get_hostkey_size()
                ca_key_type = kex_group.get_ca_type()
                ca_modulus_size = kex_group.get_ca_size()
                out.d("Hostkey type: [%s]; hostkey size: %u; CA type: [%s]; CA modulus size: %u" % (host_key_type, hostkey_modulus_size, ca_key_type, ca_modulus_size), write_now=True)
                out.d("Raw hostkey bytes (%d): [%s]" % (len(raw_hostkey_bytes), raw_hostkey_bytes.hex()), write_now=True)

                server_kex.set_host_key(host_key_type, raw_hostkey_bytes, hostkey_modulus_size, ca_key_type, ca_modulus_size)

                if cert is False and host_key_type in HostKeyTest.RSA_FAMILY:
                    for rsa_type in HostKeyTest.RSA_FAMILY:
                        server_kex.set_host_key(rsa_type, raw_hostkey_bytes, hostkey_modulus_size, ca_key_type, ca_modulus_size)

                s.close()

                if hostkey_modulus_size > 0 or ca_modulus_size > 0:
                    hostkey_min_good = cakey_min_good = 3072
                    hostkey_min_warn = cakey_min_warn = 2048
                    hostkey_warn_str = cakey_warn_str = HostKeyTest.TWO2K_MODULUS_WARNING
                    if host_key_type.startswith('ssh-ed25519') or host_key_type.startswith('ecdsa-sha2-nistp'):
                        hostkey_min_good = 256
                        hostkey_min_warn = 224
                        hostkey_warn_str = HostKeyTest.SMALL_ECC_MODULUS_WARNING
                    if ca_key_type.startswith('ssh-ed25519') or ca_key_type.startswith('ecdsa-sha2-nistp'):
                        cakey_min_good = 256
                        cakey_min_warn = 224
                        cakey_warn_str = HostKeyTest.SMALL_ECC_MODULUS_WARNING

                    if (cert is False) and (hostkey_modulus_size < hostkey_min_good) and (host_key_type != 'ssh-dss'):  # Skip ssh-dss, otherwise we get duplicate failure messages (SSH2_KexDB will always flag it).

                        if hostkey_modulus_size < hostkey_min_warn:
                            key_fail_comments.append('using small %d-bit modulus' % hostkey_modulus_size)
                        elif hostkey_warn_str not in key_warn_comments:  # Issue a warning about 2048-bit moduli.
                            key_warn_comments.append(hostkey_warn_str)

                    elif (cert is True) and ((hostkey_modulus_size < hostkey_min_good) or (0 < ca_modulus_size < cakey_min_good)):
                        if hostkey_modulus_size < hostkey_min_warn:
                            key_fail_comments.append('using small %d-bit hostkey modulus' % hostkey_modulus_size)
                        elif (hostkey_modulus_size < hostkey_min_good) and (hostkey_warn_str not in key_warn_comments):
                            key_warn_comments.append(hostkey_warn_str)

                        if 0 < ca_modulus_size < cakey_min_warn:
                            key_fail_comments.append('using small %d-bit CA key modulus' % ca_modulus_size)
                        elif (0 < ca_modulus_size < cakey_min_good) and (cakey_warn_str not in key_warn_comments):
                            key_warn_comments.append(cakey_warn_str)

                    if ca_key_type.startswith('ecdsa-sha2-nistp'):
                        key_fail_comments.append('CA key uses elliptic curves that are suspected as being backdoored by the U.S. National Security Agency')

                if host_key_type in HostKeyTest.RSA_FAMILY:
                    for rsa_type in HostKeyTest.RSA_FAMILY:
                        parsed_host_key_types.add(rsa_type)

                        db = SSH2_KexDB.get_db()
                        while len(db['key'][rsa_type]) < 3:
                            db['key'][rsa_type].append([])

                        db['key'][rsa_type][1].extend(key_fail_comments)
                        db['key'][rsa_type][2].extend(key_warn_comments)

                else:
                    parsed_host_key_types.add(host_key_type)
                    db = SSH2_KexDB.get_db()
                    while len(db['key'][host_key_type]) < 3:
                        db['key'][host_key_type].append([])

                    db['key'][host_key_type][1].extend(key_fail_comments)
                    db['key'][host_key_type][2].extend(key_warn_comments)
