"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .risk_service import RiskService
from .service import DomainService
from .storage import Database


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None,
          risk_service: RiskService | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    risk_service = risk_service or RiskService(service.database)
    parsed = urlparse(path)
    segments = [segment for segment in parsed.path.split("/") if segment]
    actor_id = headers.get("X-Actor-Id", "")
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            return _receipt_status(service.register_organization(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/actors":
            return _receipt_status(service.register_actor(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/sites":
            return _receipt_status(service.register_site(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/domain-records":
            return _receipt_status(service.record_domain_data(actor_id=actor_id, **body))
        if method == "GET" and parsed.path == "/domain-records":
            query = parse_qs(parsed.query)
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            query = parse_qs(parsed.query)
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}
        status, payload = _risk_routes(risk_service, method, segments, parsed.query, body, actor_id)
        if status is not None:
            return status, payload
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


def _receipt_status(receipt) -> tuple[int, dict[str, Any]]:
    """构造幂等写入的 HTTP 响应，并带上业务响应体中的额外字段。"""

    payload = receipt.__dict__.copy()
    response = payload.pop("response", None)
    if response:
        for key, value in response.items():
            payload.setdefault(key, value)
    return 200 if receipt.replayed else 201, payload


def _risk_routes(risk_service: RiskService, method: str, segments: list[str],
                 query_string: str, body: dict[str, Any], actor_id: str
                 ) -> tuple[int | None, dict[str, Any]]:
    """分派 /risk 前缀的跨机构风险沟通接口。"""

    if not segments or segments[0] != "risk":
        return None, {}
    query = parse_qs(query_string)
    path = segments[1:]

    if path == ["capabilities"] and method == "POST":
        return _receipt_status(risk_service.grant_capability(actor_id=actor_id, **body))
    if path == ["capabilities"] and method == "GET":
        target = query.get("actor_id", [actor_id])[0]
        return 200, {"actor_id": target,
                     "capabilities": risk_service.list_capabilities(actor_id, target)}
    if path == ["events"] and method == "POST":
        return _receipt_status(risk_service.submit_risk_event(actor_id=actor_id, **body))
    if path == ["events", "revise"] and method == "POST":
        return _receipt_status(risk_service.revise_risk_event(actor_id=actor_id, **body))
    if path == ["mappings"] and method == "POST":
        return _receipt_status(risk_service.map_local_reference(actor_id=actor_id, **body))
    if path == ["level-proposals"] and method == "POST":
        return _receipt_status(risk_service.propose_level(actor_id=actor_id, **body))
    if path == ["withdrawals"] and method == "POST":
        return _receipt_status(risk_service.withdraw_event(actor_id=actor_id, **body))
    if path == ["receipts"] and method == "POST":
        return 200, asdict(risk_service.acknowledge_revision(actor_id=actor_id, **body))
    if path == ["obligations", "discharge"] and method == "POST":
        return 200, risk_service.discharge_obligation(actor_id=actor_id, **body)
    if path == ["pending"] and method == "GET":
        limit = int(query.get("limit", ["100"])[0])
        return 200, {"items": [asdict(item) for item in risk_service.list_pending(actor_id, limit)]}
    if path == ["obligations"] and method == "GET":
        include = query.get("include_discharged", ["false"])[0] == "true"
        return 200, {"items": risk_service.list_obligations(actor_id, include)}
    if len(path) == 2 and path[0] == "events" and method == "GET":
        return 200, asdict(risk_service.get_risk_event(actor_id, path[1]))
    if len(path) == 3 and path[0] == "events" and path[2] == "status" and method == "GET":
        return 200, risk_service.communication_status(actor_id, path[1])
    return 404, {"error": "route_not_found", "message": "接口不存在"}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService
    risk_service: RiskService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")},
                                risk_service=self.risk_service)
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动科技战略协作基础服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    service = DomainService(database)
    Handler.service = service
    Handler.risk_service = RiskService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
