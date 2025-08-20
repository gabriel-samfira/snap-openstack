
from typing import Mapping

from sunbeam.core.common import (
    BaseStep,
    Result,
    ResultType,
    read_config,
    update_config,
    update_status_background,
)
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.core.juju import (
    JujuHelper,
    JujuStepHelper,
    JujuWaitException,
    ActionFailedException,
    JujuSecretNotFound,
    LeaderNotFoundException,
)
from sunbeam.core.deployment import Deployment
from sunbeam.core.terraform import (
    TerraformException,
    TerraformHelper,
)
from sunbeam.features.interface.utils import (
    cert_and_key_match
)
from sunbeam.core.manifest import Manifest
from rich.status import Status
from sunbeam.steps.openstack import CONFIG_KEY
from sunbeam.steps.sso import (
    APPLICATION_REMOVE_TIMEOUT,
)

_SAML2_CERT_KEY_SECRET = "keystone-saml2-x509-key-cert"


class SetKeystoneSAMLCertAndKeyStep(BaseStep, JujuStepHelper):
    """Deploy identity providers on bootstrap."""

    def __init__(
        self,
        deployment: Deployment,
        tfhelper: TerraformHelper,
        jhelper: JujuHelper,
        manifest: Manifest,
        x509_cert: str,
        x509_key: str,
    ):
        super().__init__(
            "Identity",
            "Setting Keystone SP SAML2 certificate and key",
        )
        self.client = deployment.get_client()
        self.manifest = manifest
        self.tfhelper = tfhelper
        self.jhelper = jhelper
        self.x509_cert = x509_cert
        self.x509_key = x509_key

    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        if not self.manifest and not all(self.x509_cert, self.x509_key):
            return Result(ResultType.SKIPPED)
        
        if all(self.x509_cert, self.x509_key):
            return Result(ResultType.COMPLETED)
        
        if not self._cert_and_key_from_manifest():
            return Result(ResultType.SKIPPED)
        return Result(ResultType.COMPLETED)

    def has_prompts(self) -> bool:
        """Returns true if the step has prompts that it can ask the user.

        :return: True if the step can ask the user for prompts,
                 False otherwise
        """
        return False

    def _cert_and_key_from_manifest(self) -> Mapping[str, str]:
        if not self.manifest:
            return {}

        has_manifest = all(
            self.manifest.saml2_x509.certificate,
            self.manifest.saml2_x509.key,
        )
        if not has_manifest:
            return {}
        
        return {
                "cert": self.manifest.saml2_x509.certificate,
                "key": self.manifest.saml2_x509.key,
            } 

    def _get_cert_and_key_from_params(self) -> Mapping[str, str]:
        if all(self.x509_cert, self.x509_key):
            return {
                "cert": self.x509_cert,
                "key": self.x509_key,
            }
        cert_details = self._cert_and_key_from_manifest()
        return cert_details

    def run(self, status: Status | None) -> Result:
        """Run the step to completion.

        Invoked when the step is run and returns a ResultType to indicate
        :return:
        """

        cert_and_key = self._get_cert_and_key_from_params()
        try:
            cert_data = open(cert_and_key["cert"]).read()
            key_data = open(cert_and_key["key"]).read()
        except Exception as e:
            return Result(ResultType.FAILED, str(e))

        if not cert_and_key_match(cert_data.encode(), key_data.encode()):
            raise ValueError(
                f"Certificate {cert_and_key["cert"]} is not derived from {cert_and_key["key"]}"
            )
        
        try:
            k_secret = self.jhelper.get_secret_by_name(
                OPENSTACK_MODEL,
                _SAML2_CERT_KEY_SECRET,
            )
        except JujuSecretNotFound:
            secret_id = self.jhelper.add_secret(
                model=OPENSTACK_MODEL,
                name=_SAML2_CERT_KEY_SECRET,
                data={
                    "certificate#file": cert_and_key["cert"],
                    "key#file": cert_and_key["key"],
                }
            )
            k_secret = self.jhelper.get_secret(
                OPENSTACK_MODEL,
                secret_id,
            )
        except Exception as e:
            return Result(ResultType.FAILED, str(e))
        
        k_cert = k_secret.get("certificate", None)
        k_key = k_secret.get("key", None)
        if cert_data != k_cert or key_data != k_key:
            self.jhelper.update_secret(
                model=OPENSTACK_MODEL,
                name=_SAML2_CERT_KEY_SECRET,
                data={
                    "certificate#file": cert_and_key["cert"],
                    "key#file": cert_and_key["key"],
                }
            )

        # Grant secret access to the vault application
        self.jhelper.grant_secret(
            OPENSTACK_MODEL, _SAML2_CERT_KEY_SECRET, "keystone"
        )

        try:
            tfvars = read_config(self.client, CONFIG_KEY)
        except ConfigItemNotFoundException:
            tfvars = {}

        if tfvars.get("keystone-config"):
            tfvars["keystone-config"]["saml-x509-keypair"] = _SAML2_CERT_KEY_SECRET
        else:
            tfvars["keystone-config"] = {
                "saml-x509-keypair": _SAML2_CERT_KEY_SECRET,
            }
        self.tfhelper.write_tfvars(tfvars)
        try:
            self.tfhelper.apply()
        except TerraformException as e:
            return Result(ResultType.FAILED, str(e))

        try:
            self.jhelper.wait_until_active(
                OPENSTACK_MODEL,
                ["keystone"],
                timeout=APPLICATION_REMOVE_TIMEOUT,
            )
        except (JujuWaitException, TimeoutError) as e:
            return Result(ResultType.FAILED, str(e))

        return Result(ResultType.COMPLETED)