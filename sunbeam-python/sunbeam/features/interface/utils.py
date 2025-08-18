# SPDX-FileCopyrightText: 2023 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import logging
import re
import typing

import click

from sunbeam.lazy import LazyImport

if typing.TYPE_CHECKING:
    import cryptography.hazmat.backends as backends
    import cryptography.exceptions as crypto_exceptions
    import cryptography.hazmat.primitives as primitives
    import cryptography.x509 as x509
    import cryptography.x509.oid as x509_oid
else:
    backends = LazyImport("cryptography.hazmat.backends")
    crypto_exceptions = LazyImport("cryptography.exceptions")
    primitives = LazyImport("cryptography.hazmat.primitives")
    x509 = LazyImport("cryptography.x509")
    x509_oid = LazyImport("cryptography.x509.oid")
    

LOG = logging.getLogger()


def get_all_registered_groups(cli: click.Group) -> dict:
    """Get all the registered groups from cli object.

    :param cli: Click group
    :returns: Dict of <group name>: <Group function>

    In case of recursive groups, group name will be <parent>.<group>
    Example of output format:
    {
        "init": <click.Group cli>,
        "enable": <click.Group enable>,
        "enable.tls": <click.Group tls>
    }
    """

    def _get_all_groups(group):
        groups = {}
        for cmd in group.list_commands({}):
            obj = group.get_command({}, cmd)
            if isinstance(obj, click.Group):
                # cli group name is init
                if group.name == "init":
                    groups[cmd] = obj
                else:
                    # TODO(hemanth): Should have all parents in the below key
                    groups[f"{group.name}.{cmd}"] = obj

                groups.update(_get_all_groups(obj))

        return groups

    groups = _get_all_groups(cli)
    groups["init"] = cli
    return groups


def is_certificate_valid(certificate: bytes) -> bool:
    try:
        certificate_bytes = base64.b64decode(certificate)
        x509.load_pem_x509_certificate(certificate_bytes)
    except (binascii.Error, TypeError, ValueError) as e:
        LOG.debug(e)
        return False

    return True


def validate_ca_certificate(
    ctx: click.core.Context, param: click.core.Option, value: str
) -> str:
    try:
        ca_bytes = base64.b64decode(value)
        x509.load_pem_x509_certificate(ca_bytes)
        return value
    except (binascii.Error, TypeError, ValueError) as e:
        LOG.debug(e)
        raise click.BadParameter(str(e))


def validate_ca_chain(
    ctx: click.core.Context, param: click.core.Option, value: str
) -> str:
    try:
        chain_bytes = base64.b64decode(value)
        chain_list = re.findall(
            pattern=(
                "(?=-----BEGIN CERTIFICATE-----)(.*?)(?<=-----END CERTIFICATE-----)"
            ),
            string=chain_bytes.decode(),
            flags=re.DOTALL,
        )
        if len(chain_list) == 0:
            LOG.debug("Empty CA Chain provided by user")
            return value

        if len(chain_list) < 2:
            raise ValueError(
                "Invalid CA chain: It must contain at least 2 certificates."
            )

        for cert in chain_list:
            cert_bytes = cert.encode()
            x509.load_pem_x509_certificate(cert_bytes)

        for ca_cert, cert in zip(chain_list, chain_list[1:]):
            ca_cert_object = x509.load_pem_x509_certificate(ca_cert.encode("utf-8"))
            cert_object = x509.load_pem_x509_certificate(cert.encode("utf-8"))
            try:
                # function available from cryptography 40.0.0
                # Antelope upper constraints has cryptography < 40.0.0
                cert_object.verify_directly_issued_by(ca_cert_object)
            except AttributeError:
                LOG.debug("CA Chain certs not verified")

        return value
    except (
        binascii.Error,
        TypeError,
        ValueError,
        crypto_exceptions.InvalidSignature,
    ) as e:
        LOG.debug(e)
        raise click.BadParameter(str(e))


def get_subject_from_csr(csr: str) -> str | None:
    try:
        req = x509.load_pem_x509_csr(bytes(csr, "utf-8"))
        uid = req.subject.get_attributes_for_oid(
            x509_oid.NameOID.X500_UNIQUE_IDENTIFIER
        )
        LOG.debug(f"UID for requested csr: {uid}")
        # Pick the first available ID
        return str(uid[0].value)
    except (binascii.Error, TypeError, ValueError) as e:
        LOG.debug(e)
        return None


def encode_base64_as_string(data: str) -> str | None:
    try:
        return base64.b64encode(bytes(data, "utf-8")).decode()
    except (binascii.Error, TypeError) as e:
        LOG.debug(f"Error in encoding data {data} : {str(e)}")
        return None


def decode_base64_as_string(data: str) -> str | None:
    try:
        return base64.b64decode(data).decode()
    except (binascii.Error, TypeError) as e:
        LOG.debug(f"Error in decoding data {data} : {str(e)}")
        return None


def cert_and_key_match(certificate: bytes, key: bytes) -> bool:
    """Checks if the supplied cert is derived from the supplied key."""
    crt = x509.load_pem_x509_certificate(certificate, backends.default_backend())
    cert_pub_key = crt.public_key()
    private_key = primitives.serialization.load_pem_private_key(
        key, password=None, backend=backends.default_backend()
    )
    private_public_key = private_key.public_key()
    return cert_pub_key.public_numbers() == private_public_key.public_numbers()
