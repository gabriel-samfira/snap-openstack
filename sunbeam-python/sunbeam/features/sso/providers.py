import yaml
import click
from sunbeam.clusterd.client import Client
from sunbeam.core.common import (
    FORMAT_TABLE,
    FORMAT_YAML,
    BaseStep,
    Result,
    ResultType,
    read_config,
    run_plan,
    str_presenter,
)
from sunbeam.core.juju import (
    JujuHelper,
    JujuStepHelper,
    JujuWaitException,
    TimeoutException,
    run_sync,
)
from sunbeam.core import questions
from rich.status import Status
from rich.console import Console

_GOOGLE_ISSUER_URL = "https://accounts.google.com"
_ENTRA_ISSUER_URL = "https://login.microsoftonline.com/%s/v2.0"
_OKTA_ISSUER_URL = "https://%s.okta.com"

console = Console()


class AddExternalProviderStep(BaseStep, JujuStepHelper):

    _CONFIG = "FeatureSSOExternalIDPConfig-%s"

    def __init__(
        self,
        client: Client,
        jhelper: JujuHelper,
        provider_type,
        provider_protocol,
        provider_name,
        config,
    ):
        self.client = client
        self.jhelper = jhelper
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
        self._preseed = self._compose_preseed_from_config(config)

        self._issuer_url = None
        self._client_id = None
        self._client_secret = None
        self._label = None
        self._charm_provider = None
    
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
        data = None
        with open(config) as fd:
            try:
                data = yaml.safe_load(fd)
            except Exception as err:
                raise click.ClickException(f"Invalid config supplied: {err}")
        
        if not data:
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
            self._label = f"Log in with {self._provider_name}"

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
        pass
