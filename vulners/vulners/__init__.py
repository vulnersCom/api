from functools import cached_property
from typing import Any

from ..base import VulnersApiBase, deprecated
from .archive import ArchiveApi
from .audit import AuditApi
from .misc import MiscApi
from .report import ReportApi
from .search import SearchApi
from .subscription import SubscriptionApi
from .webhook import WebhookApi


class VulnersApi(VulnersApiBase):
    @cached_property
    def search(self) -> SearchApi:
        return SearchApi(self)

    @deprecated(
        "VulnersApi.find() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.search_bulletins() instead."
    )
    def find(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.search_bulletins(*args, **kwargs)

    @deprecated(
        "VulnersApi.find_all() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.search_bulletins_all() instead."
    )
    def find_all(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.search_bulletins_all(*args, **kwargs)

    @deprecated(
        "VulnersApi.find_exploit() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.search_exploits() instead."
    )
    def find_exploit(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.search_exploits(*args, **kwargs)

    @deprecated(
        "VulnersApi.find_exploit_all() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.search_exploits_all() instead."
    )
    def find_exploit_all(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.search_exploits_all(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_multiple_bulletins() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_multiple_bulletins() instead."
    )
    def get_multiple_bulletins(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_multiple_bulletins(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_bulletin() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_bulletin() instead."
    )
    def get_bulletin(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_bulletin(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_multiple_bulletin_references() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_multiple_bulletin_references() instead."
    )
    def get_multiple_bulletin_references(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_multiple_bulletin_references(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_bulletin_references() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_bulletin_references() instead."
    )
    def get_bulletin_references(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_bulletin_references(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_multiple_documents_with_references() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_multiple_bulletins_with_references() instead."
    )
    def get_multiple_documents_with_references(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_multiple_bulletins_with_references(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_document_with_references() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_bulletin_with_references() instead."
    )
    def get_document_with_references(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_bulletin_with_references(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_kb_seeds() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_kb_seeds() instead."
    )
    def get_kb_seeds(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_kb_seeds(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_kb_updates() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_kb_updates() instead."
    )
    def get_kb_updates(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_kb_updates(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_bulletin_history() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.search.get_bulletin_history() instead."
    )
    def get_bulletin_history(self, *args: Any, **kwargs: Any) -> Any:
        return self.search.get_bulletin_history(*args, **kwargs)

    @cached_property
    def misc(self) -> MiscApi:
        return MiscApi(self)

    @deprecated(
        "VulnersApi.get_web_application_rules() is deprecated and will be removed in future releases.\n"
    )
    def get_web_application_rules(self, *args: Any, **kwargs: Any) -> Any:
        return self.misc.get_web_application_rules(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_suggestion() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.misc.get_suggestion() instead."
    )
    def get_suggestion(self, *args: Any, **kwargs: Any) -> Any:
        return self.misc.get_suggestion(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_ai_score() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.misc.get_ai_score() instead."
    )
    def get_ai_score(self, *args: Any, **kwargs: Any) -> Any:
        return self.misc.get_ai_score(*args, **kwargs)

    @deprecated(
        "VulnersApi.query_autocomplete() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.misc.query_autocomplete() instead."
    )
    def query_autocomplete(self, *args: Any, **kwargs: Any) -> Any:
        return self.misc.query_autocomplete(*args, **kwargs)

    @deprecated(
        "VulnersApi.search_cpe() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.misc.search_cpe() instead."
    )
    def search_cpe(self, *args: Any, **kwargs: Any) -> Any:
        return self.misc.search_cpe(*args, **kwargs)

    @cached_property
    def audit(self) -> AuditApi:
        return AuditApi(self)

    @deprecated(
        "VulnersApi.audit_software() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.audit.software() instead."
    )
    def audit_software(self, *args: Any, **kwargs: Any) -> Any:
        return self.audit.software(*args, **kwargs)

    @deprecated(
        "VulnersApi.audit_host() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.audit.host() instead."
    )
    def audit_host(self, *args: Any, **kwargs: Any) -> Any:
        return self.audit.host(*args, **kwargs)

    @deprecated(
        "VulnersApi.os_audit() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.audit.os_audit() instead."
    )
    def os_audit(self, *args: Any, **kwargs: Any) -> Any:
        return self.audit.os_audit(*args, **kwargs)

    @deprecated(
        "VulnersApi.kb_audit() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.audit.kb_audit() instead."
    )
    def kb_audit(self, *args: Any, **kwargs: Any) -> Any:
        return self.audit.kb_audit(*args, **kwargs)

    @deprecated(
        "VulnersApi.winaudit() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.audit.win_audit() instead."
    )
    def winaudit(self, *args: Any, **kwargs: Any) -> Any:
        return self.audit.win_audit(*args, **kwargs)

    @cached_property
    def webhook(self) -> WebhookApi:
        return WebhookApi(self)

    @deprecated(
        "VulnersApi.get_webhooks() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.webhook.list() instead."
    )
    def get_webhooks(self, *args: Any, **kwargs: Any) -> Any:
        return self.webhook.list(*args, **kwargs)

    @deprecated(
        "VulnersApi.add_webhook() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.webhook.add() instead."
    )
    def add_webhook(self, *args: Any, **kwargs: Any) -> Any:
        return self.webhook.add(*args, **kwargs)

    @deprecated(
        "VulnersApi.enable_webhook() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.webhook.enable() instead."
    )
    def enable_webhook(self, *args: Any, **kwargs: Any) -> Any:
        return self.webhook.enable(*args, **kwargs)

    @deprecated(
        "VulnersApi.delete_webhook() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.webhook.delete() instead."
    )
    def delete_webhook(self, *args: Any, **kwargs: Any) -> Any:
        return self.webhook.delete(*args, **kwargs)

    @deprecated(
        "VulnersApi.read_webhook() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.webhook.read() instead."
    )
    def read_webhook(self, *args: Any, **kwargs: Any) -> Any:
        return self.webhook.read(*args, **kwargs)

    @cached_property
    def subscription(self) -> SubscriptionApi:
        return SubscriptionApi(self)

    @deprecated(
        "VulnersApi.get_subscriptions() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.subscription.list() instead."
    )
    def get_subscriptions(self, *args: Any, **kwargs: Any) -> Any:
        return self.subscription.list(*args, **kwargs)

    @deprecated(
        "VulnersApi.add_subscription() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.subscription.add() instead."
    )
    def add_subscription(self, *args: Any, **kwargs: Any) -> Any:
        return self.subscription.add(*args, **kwargs)

    @deprecated(
        "VulnersApi.edit_subscription() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.subscription.edit() instead."
    )
    def edit_subscription(self, *args: Any, **kwargs: Any) -> Any:
        return self.subscription.edit(*args, **kwargs)

    @deprecated(
        "VulnersApi.delete_subscription() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.subscription.delete() instead."
    )
    def delete_subscription(self, *args: Any, **kwargs: Any) -> Any:
        return self.subscription.delete(*args, **kwargs)

    @cached_property
    def report(self) -> ReportApi:
        return ReportApi(self)

    @deprecated(
        "VulnersApi.vulnssummary_report() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.report.vulns_summary() instead."
    )
    def vulnssummary_report(self, *args: Any, **kwargs: Any) -> Any:
        return self.report.vulns_summary(*args, **kwargs)

    @deprecated(
        "VulnersApi.vulnslist_report() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.report.vulns_list() instead."
    )
    def vulnslist_report(self, *args: Any, **kwargs: Any) -> Any:
        return self.report.vulns_list(*args, **kwargs)

    @deprecated(
        "VulnersApi.ipsummary_report() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.report.ip_summary() instead."
    )
    def ipsummary_report(self, *args: Any, **kwargs: Any) -> Any:
        return self.report.ip_summary(*args, **kwargs)

    @deprecated(
        "VulnersApi.scanlist_report() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.report.scan_list() instead."
    )
    def scanlist_report(self, *args: Any, **kwargs: Any) -> Any:
        return self.report.scan_list(*args, **kwargs)

    @deprecated(
        "VulnersApi.hostvulns_report() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.report.host_vulns() instead."
    )
    def hostvulns_report(self, *args: Any, **kwargs: Any) -> Any:
        return self.report.host_vulns(*args, **kwargs)

    @cached_property
    def archive(self) -> ArchiveApi:
        return ArchiveApi(self)

    @deprecated(
        "VulnersApi.get_collection() is deprecated and will be removed in future releases.\n"
        "Use VulnersApi.archive.fetch_collection() and VulnersApi.archive.fetch_collection_update() instead"
    )
    def get_collection(self, *args: Any, **kwargs: Any) -> Any:
        return self.archive.get_collection(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_distributive() is deprecated and will be removed in future releases.\n"
    )
    def get_distributive(self, *args: Any, **kwargs: Any) -> Any:
        return self.archive.get_distributive(*args, **kwargs)

    @deprecated(
        "VulnersApi.get_distributive() is deprecated and will be removed in future releases.\n"
    )
    def getsploit(self, *args: Any, **kwargs: Any) -> Any:
        return self.archive.getsploit(*args, **kwargs)
