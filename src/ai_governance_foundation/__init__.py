"""科技战略协作基础服务的服务端基础包。"""

from .risk_service import RiskService
from .service import DomainService

__all__ = ["DomainService", "RiskService"]
