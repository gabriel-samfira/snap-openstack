import yaml
import queue
import click
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.core.common import (
    FORMAT_TABLE,
    FORMAT_YAML,
    BaseStep,
    Result,
    ResultType,
    read_config,
    update_config,
    update_status_background,
)
from sunbeam.core.juju import (
    JujuHelper,
    JujuStepHelper,
    JujuWaitException,
)
from sunbeam.core.terraform import TerraformException
from sunbeam.core.deployment import Deployment
from sunbeam.core.manifest import FeatureConfig
from sunbeam.core import questions
from rich.status import Status
from rich.console import Console
from sunbeam.features.interface.v1.openstack import (
    OpenStackControlPlaneFeature,
)
from sunbeam.clusterd.service import (
    ConfigItemNotFoundException,
)

_GOOGLE_ISSUER_URL = "https://accounts.google.com"
_ENTRA_ISSUER_URL = "https://login.microsoftonline.com/%s/v2.0"
_OKTA_ISSUER_URL = "https://%s.okta.com"
APPLICATION_DEPLOY_TIMEOUT = 900  # 15 minutes
APPLICATION_REMOVE_TIMEOUT = 300  # 5 minutes

console = Console()


class RemoveExternalProviderStep(BaseStep, JujuStepHelper):

    _CONFIG = "FeatureSSOExternalIDPConfig-%s"

    def __init__(
        self,
        deployment: Deployment,
        config: FeatureConfig,
        jhelper: JujuHelper,
        feature: OpenStackControlPlaneFeature,
        provider_name,
    ):
        super().__init__("Remove external IDP", f"Removing external IDP {provider_name}")
        self.client = deployment.get_client()
        self.jhelper = jhelper
        self.config = config
        self.feature = feature
        self.deployment = deployment
        self.tfhelper = deployment.get_tfhelper(self.feature.tfplan)
        self._provider_name = provider_name

    def run(self, status: Status | None = None) -> Result:
        """Apply terraform configuration to deploy openstack application."""
        config_key = self.feature.get_tfvar_config_key()
        try:
            tfvars = read_config(self.client, config_key)
        except ConfigItemNotFoundException:
            tfvars = {}
        tfvars.update(self.feature.set_tfvars_on_enable(self.deployment, self.config))

        feature_key = self.feature.SSO_CONFIG_KEY
        try:
            cfg = read_config(self.client, feature_key)
        except ConfigItemNotFoundException:
            cfg = {}

        if self._provider_name in tfvars.get("sso-providers", {}):
            del tfvars["sso-providers"][self._provider_name]
            self.tfhelper.write_tfvars(tfvars)
            update_config(self.client, config_key, tfvars)
        else:
            return Result(ResultType.FAILED, "Provider not found")

        if self._provider_name in cfg:
            del cfg[self._provider_name]
            update_config(self.client, feature_key, cfg)
        
        try:
            self.tfhelper.apply()
        except TerraformException as e:
            return Result(ResultType.FAILED, str(e))
        
        try:
            self.jhelper.wait_application_gone(
                [f"keystone-idp-{self._provider_name}"],
                OPENSTACK_MODEL,
                timeout=APPLICATION_REMOVE_TIMEOUT,
            )
            self.jhelper.wait_until_active(
                OPENSTACK_MODEL,
                ["keystone"],
                timeout=APPLICATION_REMOVE_TIMEOUT,
            )
        except (JujuWaitException, TimeoutError) as e:
            return Result(ResultType.FAILED, str(e))

        return Result(ResultType.COMPLETED)
    

class UpdateExternalProviderStep(BaseStep, JujuStepHelper):

    _CONFIG = "FeatureSSOExternalIDPConfig-%s"

    def __init__(
        self,
        deployment: Deployment,
        config: FeatureConfig,
        jhelper: JujuHelper,
        feature: OpenStackControlPlaneFeature,
        provider_name,
        secrets_file,
    ):
        super().__init__("Update external IDP", f"Updating external IDP {provider_name}")
        self.client = deployment.get_client()
        self.jhelper = jhelper
        self.config = config
        self.feature = feature
        self.deployment = deployment
        self.tfhelper = deployment.get_tfhelper(self.feature.tfplan)
        self._provider_name = provider_name
        self._secrets_file = secrets_file

    def _load_secrets_file(self, cfgFile: str) -> dict:
        data = {}
        with open(cfgFile) as fd:
            try:
                data = yaml.safe_load(fd)
            except Exception as err:
                raise click.ClickException(f"Invalid config supplied: {err}")

        if not data or type(data) is not dict:
            raise click.ClickException(
                "Invalid config supplied. Config must contain key/value pairs")
        
        required_configs = {
            "client_id": None,
            "client_secret": None,
        }

        for key, _ in required_configs.items():
            val = data.get(
                key,
                data.get(
                    key.replace("_", "-"),
                    None,
                )
            )
            if not val:
                raise click.ClickException(f"Missing {key} in secrets file")
            required_configs[key] = val
        return required_configs

    def run(self, status: Status | None = None) -> Result:
        """Apply terraform configuration to deploy openstack application."""
        config_key = self.feature.get_tfvar_config_key()
        try:
            tfvars = read_config(self.client, config_key)
        except ConfigItemNotFoundException:
            tfvars = {}
        tfvars.update(self.feature.set_tfvars_on_enable(self.deployment, self.config))

        feature_key = self.feature.SSO_CONFIG_KEY
        try:
            cfg = read_config(self.client, feature_key)
        except ConfigItemNotFoundException:
            cfg = {}

        if self._provider_name not in cfg:
            return Result(ResultType.FAILED, "Provider not found")
        
        provider_type = cfg[self._provider_name].get("provider_type", None)
        if not provider_type or provider_type == "canonical":
            return Result(
                ResultType.FAILED,
                (f"Provider {self._provider_name} of type "
                 "{provider_type} cannot be updated"))

        if "config" not in cfg[self._provider_name]:
            return Result(
                ResultType.FAILED,
                f"Provider {self._provider_name} is in an invalid state")

        try:
            secrets = self._load_secrets_file(self._secrets_file)
        except Exception as e:
            return Result(ResultType.FAILED, str(e))

        cfg[self._provider_name]["config"]["client_id"] = secrets["client_id"]
        cfg[self._provider_name]["config"]["client_secret"] = secrets["client_secret"]
        update_config(self.client, feature_key, cfg)

        if tfvars.get("sso-providers"):
            tfvars["sso-providers"][self._provider_name] = cfg[self._provider_name]["config"]
        else:
            tfvars["sso-providers"] = {
                self._provider_name: cfg[self._provider_name]["config"]
            }
        self.tfhelper.write_tfvars(tfvars)
        update_config(self.client, config_key, tfvars)
        try:
            self.tfhelper.apply()
        except TerraformException as e:
            return Result(ResultType.FAILED, str(e))
        
        charm_name = "keystone-idp-{}".format(self._provider_name)
        apps = ["keystone", "horizon", charm_name]
        app_queue: queue.Queue[str] = queue.Queue(maxsize=len(apps))
        task = update_status_background(self, apps, app_queue, status)
        try:
            self.jhelper.wait_until_active(
                OPENSTACK_MODEL,
                apps,
                timeout=APPLICATION_DEPLOY_TIMEOUT,
                queue=app_queue,
            )
        except (JujuWaitException, TimeoutError) as e:
            return Result(ResultType.FAILED, str(e))
        finally:
            task.stop()

        return Result(ResultType.COMPLETED)


class AddExternalProviderStep(BaseStep, JujuStepHelper):

    _CONFIG = "FeatureSSOExternalIDPConfig-%s"

    def __init__(
        self,
        deployment: Deployment,
        config: FeatureConfig,
        jhelper: JujuHelper,
        feature: OpenStackControlPlaneFeature,
        provider_type,
        provider_protocol,
        provider_name,
        configFile,
    ):
        super().__init__("Add external IDP", f"Adding external IDP {provider_name}")
        self.client = deployment.get_client()
        self.jhelper = jhelper
        self.config = config
        self.feature = feature
        self.deployment = deployment
        self.tfhelper = deployment.get_tfhelper(self.feature.tfplan)

        self._provider_name = provider_name
        self._provider_type = provider_type
        self._provider_protocol = provider_protocol
        self._questions = {
            "okta_org": questions.PromptQuestion(
                "Your Okta org (eg: dev-123456)"
            ),
            "client_id": questions.PromptQuestion(
                "OAuth client-id"
            ),
            "client_secret": questions.PromptQuestion(
                "OAuth client-secret"
            ),
            "label": questions.PromptQuestion(
                "Label for this provider"
            ),
            "microsoft_tenant": questions.PromptQuestion(
                "Microsoft tenant ID"
            ),
        }
        self._preseed = self._compose_preseed_from_config(configFile)

        self._issuer_url = None
        self._client_id = None
        self._client_secret = None
        self._label = None
    
    def _compose_preseed_from_config(self, config: str):
        preseed = {
            "okta_org": None,
            "client_id": None,
            "client_secret": None,
            "label": None,
            "microsoft_tenant": None,
        }
        if not config:
            return preseed
        data = {}
        with open(config) as fd:
            try:
                data = yaml.safe_load(fd)
            except Exception as err:
                raise click.ClickException(f"Invalid config supplied: {err}")
        
        if not data or type(data) is not dict:
            return preseed
        
        for key, val in preseed.items():
            preseed[key] = data.get(
                key,
                data.get(
                    key.replace("_", "-"),
                    None,
                )
            )
        return preseed

    def has_prompts(self) -> bool:
        """Returns true if the step has prompts that it can ask the user."""
        return True
    
    def is_skip(self, status: Status | None = None) -> Result:
        """Determines if the step should be skipped or not.

        :return: ResultType.SKIPPED if the Step should be skipped,
                ResultType.COMPLETED or ResultType.FAILED otherwise
        """
        return Result(ResultType.COMPLETED)
    
    @property
    def _charm_config(self):
        if not all([
            self._issuer_url,
            self._client_id,
            self._client_secret,
            self._label,
            self._provider_name,
        ]):
            raise click.ClickException(
                "invalid state for external provider step"
            )
        return {
            "provider": "generic",
            "provider_id": self._provider_name,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "label": self._label,
            "issuer_url": self._issuer_url,
        }

    def _ask_common(self, q_bank: questions.QuestionBank, variables: dict):
        self._client_id = q_bank.client_id.ask()
        self._client_secret = q_bank.client_secret.ask()
        self._label = q_bank.label.ask()

        if not all([self._client_id, self._client_secret]):
            raise click.ClickException(
                "client_id and client_secret are mandatory"
            )
        
        if not self._label:
            label_name = self._provider_name.capitalize()
            self._label = f"Log in with {label_name}"

        variables["label"] = self._label
        variables["client_id"] = self._client_id
        variables["client_secret"] = self._client_secret
        return variables
    
    def _ask_okta(self, q_bank: questions.QuestionBank, variables: dict):
        variables = self._ask_common(q_bank, variables)
        okta_org = q_bank.okta_org.ask()

        if not okta_org:
            raise click.ClickException(
                "okta_org is mandatory"
            )
        
        self._issuer_url = _OKTA_ISSUER_URL % okta_org
        
        variables["okta_org"] = okta_org
        return variables

    def _ask_google(self, q_bank: questions.QuestionBank, variables: dict):
        variables = self._ask_common(q_bank, variables)
        self._issuer_url = _GOOGLE_ISSUER_URL
        return variables
    
    def _ask_entra(self, q_bank: questions.QuestionBank, variables: dict):
        variables = self._ask_common(q_bank, variables)
        tenant_id = q_bank.microsoft_tenant.ask()

        if not tenant_id:
            raise click.ClickException(
                "microsoft_tenant is mandatory"
            )
        
        self._issuer_url = _ENTRA_ISSUER_URL % tenant_id
        
        variables["microsoft_tenant"] = tenant_id
        return variables
    
    def _ask_canonical(self, q_bank: questions.QuestionBank, variables: dict):
        pass

    def prompt(
        self,
        console: Console | None = None,
        show_hint: bool = False,
    ) -> None:
        """Prompt the user for any data not in the config.

        Based on the provider type, prompt the user for any options
        that are not specified in the config.

        :param console: the console to prompt on
        :type console: rich.console.Console (Optional)
        """

        variables = questions.load_answers(
            self.client,
            self._CONFIG % self._provider_name)

        sso_bank = questions.QuestionBank(
            questions=self._questions,
            console=console,
            preseed=self._preseed,
            previous_answers=variables,
            show_hint=show_hint,
        )

        ask_fn = getattr(self, f"_ask_{self._provider_type}", None)
        if not ask_fn:
            raise click.ClickException(
                f"Unknown external provider type {self._provider_type}"
            )
        variables = ask_fn(sso_bank, variables)

        questions.write_answers(
            self.client,
            self._CONFIG % self._provider_name,
            variables)

    def run(self, status: Status | None = None) -> Result:
        config_key = self.feature.get_tfvar_config_key()
        try:
            tfvars = read_config(self.client, config_key)
        except ConfigItemNotFoundException:
            tfvars = {}
        tfvars.update(self.feature.set_tfvars_on_enable(self.deployment, self.config))

        feature_key = self.feature.SSO_CONFIG_KEY
        try:
            cfg = read_config(self.client, feature_key)
        except ConfigItemNotFoundException:
            cfg = {}

        idp = cfg.get(self._provider_name)
        if idp:
            cfg[self._provider_name]["config"] = self._charm_config
        else:
            cfg[self._provider_name] = {
                "config": self._charm_config,
                "provider_type": self._provider_type,
                "provider_proto": self._provider_protocol,
            }
        
        for provider, data in cfg.items():
            if tfvars.get("sso-providers"):
                tfvars["sso-providers"][provider] = data["config"]
            else:
                tfvars["sso-providers"] = {provider : data["config"]}
        self.tfhelper.write_tfvars(tfvars)
        update_config(self.client, feature_key, cfg)
        update_config(self.client, config_key, tfvars)

        try:
            self.tfhelper.apply()
        except TerraformException as e:
            return Result(ResultType.FAILED, str(e))

        charm_name = "keystone-idp-{}".format(self._provider_name)
        apps = ["keystone", "horizon", charm_name]
        app_queue: queue.Queue[str] = queue.Queue(maxsize=len(apps))
        task = update_status_background(self, apps, app_queue, status)
        try:
            self.jhelper.wait_until_active(
                OPENSTACK_MODEL,
                apps,
                timeout=APPLICATION_DEPLOY_TIMEOUT,
                queue=app_queue,
            )
        except (JujuWaitException, TimeoutError) as e:
            return Result(ResultType.FAILED, str(e))
        finally:
            task.stop()

        return Result(ResultType.COMPLETED)