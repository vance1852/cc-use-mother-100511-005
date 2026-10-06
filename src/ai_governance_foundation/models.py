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
    response: dict[str, Any] | None = None


@dataclass(frozen=True)
class RiskRevision:
    """描述同一风险事件的一个不可变修订版本。"""

    revision: int
    summary: str
    content_hash: str
    change_note: str
    proposed_level: str | None
    created_by: str
    created_at: str


@dataclass(frozen=True)
class RiskEventView:
    """风险事件的跨机构视图，原始敏感内容不以明文回流给无权机构。"""

    event_id: str
    origin_organization_id: str
    current_revision: int
    status: str
    agreed_level: str | None
    latest_summary: str | None
    revisions: list[RiskRevision]
    participants: list[str]
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RiskReceiptView:
    """描述一家机构对某个修订版本的接收回执。"""

    event_id: str
    organization_id: str
    revision: int
    content_hash: str
    note: str | None
    received_by: str
    created_at: str


@dataclass(frozen=True)
class PendingDelivery:
    """描述接收方离线期间积压、重连后按顺序补齐的一条待办。"""

    seq: int
    event_id: str
    kind: str
    revision: int
    enqueued_at: str
