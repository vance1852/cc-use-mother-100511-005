"""定义基础服务允许登记的资料类别。"""

ALLOWED_CATEGORIES = frozenset({
    "institution_profile",
    "innovation_node_registry",
    "research_resource",
    "project_assignment",
})


def is_allowed_category(value: str) -> bool:
    return value in ALLOWED_CATEGORIES


# 跨机构风险沟通允许协商的统一风险等级（由低到高）。
ALLOWED_RISK_LEVELS = frozenset({"info", "low", "medium", "high", "critical"})


def is_allowed_risk_level(value: str) -> bool:
    return value in ALLOWED_RISK_LEVELS


# 服务端坚持数据最小化：这些字段若出现在请求体中一律拒绝，
# 保证原始敏感内容根本不进入服务边界。
FORBIDDEN_CONTENT_FIELDS = frozenset({
    "raw_content",
    "original_content",
    "sensitive_content",
    "secret_content",
    "secret_text",
})
