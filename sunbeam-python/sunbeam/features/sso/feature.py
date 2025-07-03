import click
import pydantic

from sunbeam.clusterd.client import Client
from rich.console import Console
from sunbeam.core.manifest import CharmManifest, FeatureConfig, SoftwareConfig
from sunbeam.features.interface.v1.base import (
    BaseFeatureGroup,
    FeatureRequirement,
)
from sunbeam.core.deployment import Deployment
from packaging.version import Version
from sunbeam.core.terraform import TerraformException, TerraformInitStep
from sunbeam.utils import pass_method_obj, click_option_show_hints
from sunbeam.clusterd.service import ConfigItemNotFoundException
from sunbeam.core.openstack import OPENSTACK_MODEL
from sunbeam.features.interface.v1.openstack import (
    OpenStackControlPlaneFeature,
    WaitForApplicationsStep,
    TerraformPlanLocation,
)
from sunbeam.core.common import (
    BaseStep,
    Result,
    ResultType,
    read_config,
    run_plan,
    update_config,
)
from sunbeam.core.juju import (
    ActionFailedException,
    JujuHelper,
    LeaderNotFoundException,
    run_sync,
)
from .providers import AddExternalProviderStep

console = Console()

class SSOFeature(OpenStackControlPlaneFeature):
    version = Version("0.0.1")
    name = "sso"
    tf_plan_location = TerraformPlanLocation.SUNBEAM_TERRAFORM_REPO
    requires = {
        FeatureRequirement('tls.ca'),
    }
    SSO_CONFIG_KEY = "SSOFeatureConfigKey"
    
    def provider_config(self, deployment: Deployment, cfg: str) -> dict:
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
        tfvars: dict[str, None | bool] = {"keystone-to-trusted-dashboard": False}
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
        config = self.provider_config(deployment)
        print(config)
        providers = config.get("sso-providers", {})
        if not no_prompt and providers:
            msg = ("You have multiple SSO providers enabled. "
            "This will disable all of them. Are you sure?")
            click.confirm(msg, abort=True)
        self.disable_feature(deployment, show_hints)
    
    @click.command()
    @pass_method_obj
    def list_providers(self, deployment: Deployment) -> None:
        """List SSO providers."""
        try:
            tfvars = self.provider_config(deployment)
        except ConfigItemNotFoundException:
            tfvars = {}
        click.echo(" ".join(tfvars.get("sso-providers", {}).keys()))

    @click.command()
    @click.argument(
        "provider-type",
        type=click.Choice(
            ["canonical", "google", "entra", "okta"],
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
        jhelper = JujuHelper(deployment.get_connected_controller())
        if provider_type != "canonical":
            step = AddExternalProviderStep(
                deployment=deployment,
                config=FeatureConfig(),
                jhelper=jhelper,
                feature=self,
                provider_type=provider_type,
                provider_protocol=provider_protocol,
                provider_name=name,
                configFile=config,
            )
        else:
            click.echo(f"not yet.")
            return
        plan = [
            TerraformInitStep(deployment.get_tfhelper(self.tfplan)),
            step,
        ]
        run_plan(plan, console, show_hints)
        click.echo(f"{name} added.")

    @click.command()
    @pass_method_obj
    def get_openid_redirect_uri(self, deployment: Deployment):
        """Get the OpenID redirect URI."""
        jhelper = JujuHelper(deployment.get_connected_controller())
        redirect_uri = self._get_openid_redirect_uri(jhelper)
        click.echo(f"{redirect_uri}")

    def _get_openid_redirect_uri(self, jhelper):
        app = "keystone"
        action_cmd = "get-admin-account"

        try:
            unit = run_sync(jhelper.get_leader_unit(app, OPENSTACK_MODEL))
        except LeaderNotFoundException:
            raise click.ClickException(f"Unable to get {app} leader")
        
        try:
            action_result = run_sync(
                jhelper.run_action(unit, OPENSTACK_MODEL, action_cmd)
            )
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
                {"name": "list-providers", "command": self.list_providers},
                {"name": "add-provider", "command": self.add_provider},
                {"name": "get-oidc-redirect-uri", "command": self.get_openid_redirect_uri},
            ],
        }