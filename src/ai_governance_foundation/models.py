"""定义基础服务在模块边界使用的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Actor:
    """表示具有明确角色的后台操作者。"""

    actor_id: str
    display_name: str
    role: str
    organization_id: str
    active: bool


@dataclass(frozen=True)
class Site:
    """表示科研创新机构下的业务场所。"""

    site_id: str
    organization_id: str
    name: str
    timezone_name: str
    version: int


@dataclass(frozen=True)
class DomainRecord:
    """表示已经持久化的领域资料记录。"""

    record_id: str
    site_id: str
    category: str
    external_key: str
    payload: dict[str, Any]
    created_by: str
    created_at: str


@dataclass(frozen=True)
class WriteReceipt:
    """描述一次幂等写入的稳定结果。"""

    request_id: str
    resource_type: str
    resource_id: str
    replayed: bool
    extra: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        data = {"request_id": self.request_id, "resource_type": self.resource_type,
                "resource_id": self.resource_id, "replayed": self.replayed}
        if self.extra:
            data.update(self.extra)
        return data


@dataclass(frozen=True)
class IncidentVersion:
    """描述同一风险事件一个不可变的修订版本。"""

    version: int
    sanitized_summary: str
    summary_hash: str
    content_hash: str
    category: str
    proposed_level: str
    revision_note: str
    created_by_actor_id: str
    organization_id: str
    created_at: str


@dataclass(frozen=True)
class LocalReference:
    """描述一家机构对某事件版本的本地编号与本地敏感级别映射。"""

    reference_id: str
    incident_id: str
    version: int
    organization_id: str
    local_number: str
    local_label: str
    mapped_by_actor_id: str
    created_at: str


@dataclass(frozen=True)
class LevelProposal:
    """描述一家机构对某事件版本的统一等级主张。"""

    proposal_id: str
    incident_id: str
    version: int
    organization_id: str
    proposed_level: str
    note: str
    proposed_by_actor_id: str
    created_at: str


@dataclass(frozen=True)
class Advisory:
    """描述一个事件版本发往某家机构的通告及处置义务。"""

    advisory_id: str
    incident_id: str
    version: int
    target_organization_id: str
    status: str
    after_withdrawal: bool
    sequence_number: int
    created_at: str


@dataclass(frozen=True)
class DeliveryItem:
    """描述接收方按顺序拉取到的一条待办/通告。"""

    sequence_number: int
    incident_id: str
    advisory_id: str
    version: int
    kind: str
    status: str
    after_withdrawal: bool
    acknowledged: bool
    created_at: str
