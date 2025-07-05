import click
import pydantic
import yaml

from rich.console import Console
from sunbeam.core.manifest import CharmManifest, FeatureConfig, SoftwareConfig
from sunbeam.features.interface.v1.base import (
    FeatureRequirement,
)
from rich.table import Table
from sunbeam.core.deployment import Deployment
from packaging.version import Version
from sunbeam.core.terraform import TerraformInitStep
from sunbeam.utils import pass_method_obj, click_option_show_hints
from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.features.interface.v1.base import BaseFeatureGroup
from sunbeam.steps.juju import RemoveSaasApplicationsStep
from sunbeam.features.interface.v1.openstack import (
    OpenStackControlPlaneFeature,
    TerraformPlanLocation,
)
from sunbeam.core.common import (
    FORMAT_TABLE,
    FORMAT_YAML,
    read_config,
    run_plan,
    update_config,
    str_presenter,
)
from sunbeam.core.juju import (
    ActionFailedException,
    JujuHelper,
    LeaderNotFoundException,
)
from .providers import (
    AddCanonicalProviderStep,
    AddGenericProviderStep,
    AddGoogleProviderStep,
    AddOktaProviderStep,
    AddEntraProviderStep,
    RemoveExternalProviderStep,
    UpdateExternalProviderStep,
    APPLICATION_REMOVE_TIMEOUT,
)

console = Console()

class SSOFeatureGroup(BaseFeatureGroup):
    name = "tls"

    @click.group()
    @pass_method_obj
    def enable_group(self, deployment: Deployment) -> None:
        """Enable tls group."""

    @click.group()
    @pass_method_obj
    def disable_group(self, deployment: Deployment) -> None:
        """Disable TLS group."""


class SSOFeature(OpenStackControlPlaneFeature):
    version = Version("0.0.1")
    name = "sso"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO
    requires = {
        FeatureRequirement('tls.ca'),
    }
    SSO_CONFIG_KEY = "SSOFeatureConfigKey"
    
    def provider_config(self, deployment: Deployment, cfg: str = "") -> dict:
        """Return stored provider configuration."""
        try:
            cfg = cfg or self.get_tfvar_config_key()
            provider_config = read_config(deployment.get_client(), cfg)
        except ConfigItemNotFoundException:
            provider_config = {}
        return provider_config
    
    def default_software_overrides(self) -> SoftwareConfig:
        """Feature software configuration."""
        return SoftwareConfig(
            charms={
                "kratos-external-idp-integrator": CharmManifest(channel="latest/edge"),
            }
        )

    def manifest_attributes_tfvar_map(self) -> dict:
        """Manifest attributes terraformvars map."""
        return {
            self.tfplan: {
                "charms": {
                    "kratos-external-idp-integrator": {
                        "channel": "kratos-idp-channel",
                        "revision": "kratos-idp-revision",
                    }
                }
            }
        }

    def set_application_names(self, deployment: Deployment) -> list:
        """Application names handled by the terraform plan."""
        return []
    
    def set_tfvars_on_enable(
        self, deployment: Deployment, config: pydantic.BaseModel
    ) -> dict:
        """Set terraform variables to enable the application."""
        tfvars: dict[str, None | bool] = {"keystone-to-trusted-dashboard": True}
        return tfvars
    
    def set_tfvars_on_disable(self, deployment: Deployment) -> dict:
        """Set terraform variables to disable the application."""
        tfvars: dict[str, None | bool | dict] = {
            "keystone-to-trusted-dashboard": False,
            "sso-providers": {},
        }
        return tfvars
    
    def set_tfvars_on_resize(
        self, deployment: Deployment, config: FeatureConfig
    ) -> dict:
        """Set terraform variables to resize the application."""
        return {}
    
    @click.command()
    @click_option_show_hints
    @pass_method_obj
    def enable_cmd(
        self, deployment: Deployment, show_hints: bool
    ) -> None:
        """Enable SSO."""
        self.enable_feature(deployment, FeatureConfig(), show_hints)
    
    @click.command()
    @click_option_show_hints
    @click.option(
        "--no-prompt",
        is_flag=True,
        help="Do not prompt for confirmation.",
    )
    @pass_method_obj
    def disable_cmd(
        self,
        deployment: Deployment,
        show_hints: bool,
        no_prompt: bool,
    ) -> None:
        """Disable SSO."""
        config = self.provider_config(deployment, self.SSO_CONFIG_KEY)
        if not no_prompt and config:
            msg = ("You have one or more SSO providers enabled. "
            "This action will disable all of them. Are you sure?")
            click.confirm(msg, abort=True)
        saas_to_remove = []
        jhelper = JujuHelper(deployment.juju_controller)
        for provider, cfg in config.items():
            if cfg.get("provider_type", None) == "canonical":
                saas_to_remove.append(provider)
                saas_to_remove.append(f"{provider}-cert")

        tfhelper = deployment.get_tfhelper(self.tfplan)
        remove_saas_plan = [
            TerraformInitStep(tfhelper),
            RemoveSaasApplicationsStep(
                jhelper,
                OPENSTACK_MODEL,
                saas_apps_to_delete=saas_to_remove,
                offering_interfaces=["oauth", "certificate_transfer"],
                wait_timeout=APPLICATION_REMOVE_TIMEOUT,
            ),
        ]
        run_plan(remove_saas_plan, console, show_hints)
        self.disable_feature(deployment, show_hints)
        update_config(deployment.get_client(), self.SSO_CONFIG_KEY, {})
    
    @click.command()
    @click.option(
        "--format",
        type=click.Choice([FORMAT_TABLE, FORMAT_YAML]),
        default=FORMAT_TABLE,
        help="Output format",
    )
    @pass_method_obj
    def list_providers(self, deployment: Deployment, format: str) -> None:
        """List SSO providers."""
        try:
            cfg = self.provider_config(deployment, self.SSO_CONFIG_KEY)
        except ConfigItemNotFoundException:
            cfg = {}

        results = {}
        for k, v in cfg.items():
            results[k] = {
                "type": v.get("provider_type", "unknown"),
                "protocol": v.get("provider_proto", "unknown"),
                "issuer_url": v.get("config", {}).get("issuer_url", "unknown"),
            }
        
        if format == FORMAT_TABLE:
            table = Table()
            table.add_column("Provider ID")
            table.add_column("Type")
            table.add_column("Protocol")
            for provider, data in results.items():
                table.add_row(
                    provider,
                    data["type"],
                    data["protocol"],
                )
            console.print(table)
        elif format == FORMAT_YAML:
            yaml.add_representer(str, str_presenter)
            console.print(yaml.dump(results))

    @click.command()
    @click.argument(
        "provider-type",
        type=click.Choice(
            ["canonical", "google", "entra", "okta", "generic"],
            case_sensitive=False,
        ),
    )
    @click.argument(
        "provider-protocol",
        type=click.Choice(
            ["openid",],
            case_sensitive=False,
        ),
    )
    @click.argument("name", type=str)
    @click.option(
        "--config",
        type=str,
        required=False,
        help="SSO provider configuration",
    )
    @click_option_show_hints
    @pass_method_obj
    def add_provider(
        self,
        deployment: Deployment,
        provider_type: str,
        provider_protocol: str,
        name: str,
        config: str,
        show_hints: bool,
    ) -> None:
        """Add a new SSO Provider."""
        try:
            cfg = self.provider_config(deployment, self.SSO_CONFIG_KEY)
        except ConfigItemNotFoundException:
            cfg = {}

        if name in cfg:
            click.echo(f"{name} is already enabled.")
            return
        
        jhelper = JujuHelper(deployment.juju_controller)

        step_map = {
            "google": AddGoogleProviderStep,
            "entra": AddEntraProviderStep,
            "okta": AddOktaProviderStep,
            "generic": AddGenericProviderStep,
            "canonical": AddCanonicalProviderStep,
        }

        stepCls = step_map.get(provider_type)
        if not stepCls:
            raise click.ClickException(f"Cannot handle {provider_type}")

        step = stepCls(
            deployment,
            FeatureConfig(),
            jhelper,
            self,
            provider_protocol,
            name,
            config,
        )

        plan = [
            TerraformInitStep(deployment.get_tfhelper(self.tfplan)),
            step,
        ]
        run_plan(plan, console, show_hints)
        click.echo(f"{name} added.")

    @click.command()
    @click.argument("name", type=str)
    @click_option_show_hints
    @pass_method_obj
    def remove_provider(self, deployment: Deployment, name: str, show_hints: bool):
        """Remove a SSO provider."""
        try:
            cfg = self.provider_config(deployment, self.SSO_CONFIG_KEY)
        except ConfigItemNotFoundException:
            cfg = {}

        provider = cfg.get(name)
        if not provider:
            click.echo(f"{name} does not exist.")
            return
        jhelper = JujuHelper(deployment.juju_controller)
        prov_type = provider.get("provider_type", None)
        if prov_type == "canonical":
            step = RemoveSaasApplicationsStep(
                jhelper,
                OPENSTACK_MODEL,
                saas_apps_to_delete=[name, f"{name}-cert"],
                offering_interfaces=["oauth", "certificate_transfer"],
                wait_timeout=APPLICATION_REMOVE_TIMEOUT,
            )
        else:
            step = RemoveExternalProviderStep(
                deployment=deployment,
                config=FeatureConfig(),
                jhelper=jhelper,
                feature=self,
                provider_name=name,
            )
        plan = [
            TerraformInitStep(deployment.get_tfhelper(self.tfplan)),
            step,
        ]

        run_plan(plan, console, show_hints)
        if prov_type == "canonical":
            del cfg[name]
            update_config(deployment.get_client(), self.SSO_CONFIG_KEY, cfg)
        click.echo(f"{name} removed.")

    @click.command()
    @click.argument("name", type=str)
    @click.option(
        "--secrets-file",
        type=str,
        required=True,
        help="Secrets file containing client_id and client_secret",
    )
    @click_option_show_hints
    @pass_method_obj
    def update_provider(
        self,
        deployment: Deployment,
        name: str,
        secrets_file: str,
        show_hints: bool
    ):
        """Update external provider client secrets."""
        try:
            cfg = self.provider_config(deployment, self.SSO_CONFIG_KEY)
        except ConfigItemNotFoundException:
            cfg = {}

        if name not in cfg:
            click.echo(f"{name} does not exist.")
            return
        
        jhelper = JujuHelper(deployment.juju_controller)
        plan = [
            TerraformInitStep(deployment.get_tfhelper(self.tfplan)),
            UpdateExternalProviderStep(
                deployment=deployment,
                config=FeatureConfig(),
                jhelper=jhelper,
                feature=self,
                provider_name=name,
                secrets_file=secrets_file,
            ),
        ]
        run_plan(plan, console, show_hints)
        click.echo(f"{name} updated.")

    @click.command()
    @pass_method_obj
    def get_openid_redirect_uri(self, deployment: Deployment):
        """Get the OpenID redirect URI."""
        jhelper = JujuHelper(deployment.juju_controller)
        redirect_uri = self._get_openid_redirect_uri(jhelper)
        click.echo(f"{redirect_uri}")

    def _get_openid_redirect_uri(self, jhelper):
        app = "keystone"
        action_cmd = "get-admin-account"

        try:
            unit = jhelper.get_leader_unit(app, OPENSTACK_MODEL)
        except LeaderNotFoundException:
            raise click.ClickException(f"Unable to get {app} leader")
        
        try:
            action_result = jhelper.run_action(unit, OPENSTACK_MODEL, action_cmd)
        except ActionFailedException as e:
            raise click.ClickException(
                "Unable to retrieve admin account data from Keystone service"
            )
        public_url = action_result.get("public-endpoint", "").rstrip("/")
        if not public_url:
            raise click.ClickException("Could not determine keystone public URL")
        return f"{public_url}/OS-FEDERATION/protocols/openid/redirect_uri"

    @click.group()
    def sso_groups(self):
        """Manage sso."""

    def enabled_commands(self) -> dict[str, list[dict]]:
        """Dict of clickgroup along with commands.

        Return the commands available once the feature is enabled.
        """
        return {
            "init": [{"name": "sso", "command": self.sso_groups}],
            "init.sso": [
                {"name": "list", "command": self.list_providers},
                {"name": "add", "command": self.add_provider},
                {"name": "remove", "command": self.remove_provider},
                {"name": "update", "command": self.update_provider},
                {"name": "get-oidc-redirect-uri", "command": self.get_openid_redirect_uri},
            ],
        }