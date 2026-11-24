"""Operational APIs for NetworkSec operators and integrations."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta
from pathlib import Path as FilePath
from tempfile import TemporaryDirectory
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.schemas.api import AlertRecord, ErrorResponse
from app.schemas.backend import (
    CATEGORIES,
    AuditRecord,
    Category,
    DashboardSummary,
    DeviceActivity,
    DeviceCreate,
    DevicePatch,
    DeviceRecord,
    EventDetail,
    EventId,
    EventRelations,
    GrafanaLink,
    IndexedEvent,
    Login,
    Page,
    Principal,
    Role,
    SessionResponse,
    TopologyGraph,
    TopologyLink,
    TopologyNode,
    UserCreate,
    UserRecord,
    UserUpdate,
)
from app.schemas.correlation import (
    CorrelationConfig,
    CorrelationResult,
    CorrelationRule,
    OspfCorrelationConfig,
    RuleId,
)
from app.schemas.event import EventSeverity, EventType, EventVendor, NormalizedEvent
from app.services.backend import EventFilters, Period, date_range, redact
from app.services.correlation import CorrelationEngine, CorrelationStore
from app.services.grafana import dashboard_link
from app.services.managed_rules import (
    RuleCreate,
    RuleOutcome,
    RulePatch,
    RuleRecord,
    RuleTest,
    test_rule,
)
from app.services.topology import TopologyInventory, build_topology
from app.storage.backend import PostgresBackendStorage
from app.storage.base import EventQuery, LogStorage, StorageError, StorageUnavailableError
from app.web.accounts import ApiAccounts, consume_login_attempt, principal, require_bearer, roles
from app.web.api import API_ERRORS, BODY_ERRORS, NOT_FOUND

Analyst = Annotated[Principal, Depends(roles(Role.ADMIN, Role.ANALYST))]
Admin = Annotated[Principal, Depends(roles(Role.ADMIN))]
Reader = Annotated[Principal, Depends(principal)]
PageNumber = Annotated[int, Query(ge=1, le=1000)]
PageSize = Annotated[int, Query(ge=1, le=200)]
ShortQuery = Annotated[str | None, Query(min_length=1, max_length=255, pattern=r"^[^\x00]+$")]
CONFLICT: dict[int | str, dict[str, Any]] = {
    409: {"model": ErrorResponse, "description": "Resource conflicts with existing state"}
}
_CSV_FORMULA = re.compile(r"^[\s\ufeff\u200b]*[=+@-]")


class BuiltinRule(BaseModel):
    id: str
    enabled: bool
    origin: Literal["built_in"] = "built_in"
    definition: CorrelationRule | OspfCorrelationConfig


class RuleValidation(BaseModel):
    valid: bool
    reason: str | None = None


def _storage(request: Request) -> PostgresBackendStorage:
    storage: PostgresBackendStorage | None = request.app.state.backend
    if storage is None:
        raise StorageUnavailableError("PostgreSQL is unavailable")
    return storage


Store = Annotated[PostgresBackendStorage, Depends(_storage)]


def _accounts(request: Request) -> ApiAccounts:
    accounts: ApiAccounts | None = request.app.state.accounts
    if accounts is None:
        raise StorageUnavailableError("PostgreSQL is unavailable")
    return accounts


Accounts = Annotated[ApiAccounts, Depends(_accounts)]


def _filters(
    start: datetime | None = None,
    end: datetime | None = None,
    period: Period = "daily",
    device_id: UUID | None = None,
    device_name: ShortQuery = None,
    severity: EventSeverity | None = None,
    category: Category | None = None,
    event_type: EventType | None = None,
    vendor: EventVendor | None = None,
    search: ShortQuery = None,
) -> EventFilters:
    try:
        range_start, range_end = date_range(start, end, period)
    except (ValueError, OverflowError) as exc:
        raise HTTPException(
            422, "Invalid time range. Use explicit offsets and at most 90 days."
        ) from exc
    return EventFilters(
        range_start,
        range_end,
        device_id,
        device_name,
        severity,
        category,
        event_type,
        vendor,
        search,
    )


Filters = Annotated[EventFilters, Depends(_filters)]


def _require[T](value: T | None, resource: str) -> T:
    if value is None:
        raise HTTPException(404, f"{resource} not found")
    return value


def _csv_cell(value: object) -> object:
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False)
    if isinstance(value, str) and (
        value.startswith(("\t", "\r", "\n")) or _CSV_FORMULA.match(value)
    ):
        return "'" + value
    return value


def _export_csv(value: BaseModel, columns: tuple[str, ...]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    if isinstance(value, Page):
        writer.writerow(columns)
        for item in value.items:
            writer.writerow(_csv_cell(cell) for cell in item.model_dump(mode="json").values())
    else:
        writer.writerow(["metric", "value"])
        for key, cell in value.model_dump(mode="json").items():
            writer.writerow([key, _csv_cell(cell)])
    return output.getvalue()


def create_backend_router(
    logs: LogStorage,
    settings: Settings,
    config: CorrelationConfig,
    inventory: TopologyInventory,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["operations"], responses=API_ERRORS)
    builtin = {
        rule.id: BuiltinRule(id=rule.id, enabled=rule.enabled, definition=rule)
        for rule in config.rules
    }
    if config.ospf:
        builtin["ospf-adjacency"] = BuiltinRule(
            id="ospf-adjacency", enabled=config.ospf.enabled, definition=config.ospf
        )

    def graph(storage: PostgresBackendStorage, actor: Principal) -> TopologyGraph:
        return build_topology(
            storage, config.ospf, inventory, include_addresses=actor.role is not Role.VIEWER
        )

    def summary(
        storage: PostgresBackendStorage, actor: Principal, filters: EventFilters
    ) -> DashboardSummary:
        data = storage.summary(filters)
        if actor.role is Role.VIEWER:
            data["significant_events"] = []
        topology = graph(storage, actor)
        links = topology.links
        if filters.device_id is not None or filters.device_name is not None:
            nodes = {
                node.id
                for node in topology.nodes
                if node.id == str(filters.device_id)
                or (filters.device_id is None and node.name == filters.device_name)
            }
            links = [link for link in links if link.source in nodes or link.target in nodes]
        return DashboardSummary(**data, links=[link for link in links if link.protocol == "ospf"])

    @router.post(
        "/auth/login",
        response_model=SessionResponse,
        responses={
            **BODY_ERRORS,
            429: {
                "model": ErrorResponse,
                "description": "Too many login attempts",
                "headers": {"Retry-After": {"schema": {"type": "integer"}}},
            },
        },
    )
    def login(body: Login, request: Request, accounts: Accounts) -> SessionResponse:
        consume_login_attempt(request)
        if result := accounts.login(body):
            return result
        raise HTTPException(
            401, "Invalid username or password", headers={"WWW-Authenticate": "Bearer"}
        )

    @router.get("/auth/me", response_model=Principal)
    def me(actor: Reader) -> Principal:
        return actor

    @router.post("/auth/logout", status_code=204, responses={**BODY_ERRORS})
    def logout(
        actor: Reader,
        accounts: Accounts,
        token: Annotated[str, Depends(require_bearer)],
    ) -> Response:
        accounts.logout(token, actor.username)
        return Response(status_code=204)

    @router.get("/users", response_model=list[UserRecord])
    def users(
        _actor: Admin,
        accounts: Accounts,
        page: PageNumber = 1,
        page_size: PageSize = 50,
    ) -> list[UserRecord]:
        return accounts.users(page, page_size)

    @router.post(
        "/users",
        status_code=201,
        response_model=UserRecord,
        responses={**BODY_ERRORS, **CONFLICT},
    )
    def create_user(body: UserCreate, actor: Admin, accounts: Accounts) -> UserRecord:
        return accounts.create_user(body, actor.username)

    @router.patch(
        "/users/{username}",
        response_model=UserRecord,
        responses={**BODY_ERRORS, **NOT_FOUND},
    )
    def update_user(
        username: Annotated[
            str, Path(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$")
        ],
        body: UserUpdate,
        actor: Admin,
        accounts: Accounts,
    ) -> UserRecord:
        return _require(accounts.update_user(username, body, actor.username), "User")

    @router.get("/events/catalog", response_model=Page[IndexedEvent])
    def catalog_events(
        _actor: Analyst,
        storage: Store,
        filters: Filters,
        sort: Literal["desc", "asc"] = "desc",
        page: PageNumber = 1,
        page_size: PageSize = 50,
    ) -> Page[IndexedEvent]:
        return storage.events(filters, page, page_size, sort)

    async def payload(
        event_id: str, filters: EventFilters, row: dict | None
    ) -> NormalizedEvent | None:
        start, end = filters.start, filters.end
        if row:
            start = row["event_timestamp"]
            end = start + timedelta(microseconds=1)
        try:
            page = await logs.query_events(EventQuery(start, end, 1, event_id=event_id))
        except StorageError:
            if row is None:
                raise
            return None
        return next((item for item in page.items if item.event_id == event_id), None)

    @router.get("/events/{event_id}", response_model=EventDetail, responses={**NOT_FOUND})
    async def event_detail(
        event_id: EventId,
        actor: Analyst,
        storage: Store,
        filters: Filters,
        include_raw: bool = False,
    ) -> EventDetail:
        if include_raw and actor.role is not Role.ADMIN:
            raise HTTPException(403, "Permission denied")
        row = await run_in_threadpool(storage.event, event_id)
        event = await payload(event_id, filters, row)
        if row is None and event is None:
            raise HTTPException(404, "Event not found")
        relations = await run_in_threadpool(storage.relations, event_id)
        fallback = event.model_dump() if event else {}
        raw_message = event.raw_message if event and include_raw else None
        if raw_message and row and row["raw_prefix"]:
            raw_message = f"<{row['syslog_priority']}>{raw_message}"
        indexed = row or {
            **fallback,
            "event_timestamp": fallback.get("timestamp"),
            "message": redact(event.message) if event else "",
            "device_id": None,
            "collector_ip": None,
            "category": CATEGORIES[event.event_type] if event else None,
        }
        return EventDetail(
            event_id=event_id,
            event=IndexedEvent.model_validate(indexed),
            correlation_status="correlated"
            if relations.incident_ids
            else ("unmatched" if row else "unknown"),
            related_incident_ids=relations.incident_ids,
            raw_message=redact(raw_message) if raw_message else None,
            facility=row["syslog_priority"] // 8
            if row and row["syslog_priority"] is not None
            else None,
            payload_status="available" if event else "unavailable",
            metadata={
                key: redact(value) if isinstance(value, str) else value
                for key, value in fallback.items()
                if key not in IndexedEvent.model_fields
                and key not in {"raw_message", "timestamp", "session", "username"}
                and value is not None
            },
        )

    @router.get(
        "/events/{event_id}/related", response_model=EventRelations, responses={**NOT_FOUND}
    )
    async def related_events(
        event_id: EventId,
        _actor: Analyst,
        storage: Store,
        filters: Filters,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> EventRelations:
        row = await run_in_threadpool(storage.event, event_id)
        if not row:
            _require(await payload(event_id, filters, None), "Event")
        return await run_in_threadpool(storage.relations, event_id, limit)

    @router.get("/topology", response_model=TopologyGraph)
    def topology(actor: Reader, storage: Store) -> TopologyGraph:
        return graph(storage, actor)

    @router.get("/topology/nodes", response_model=list[TopologyNode])
    def topology_nodes(actor: Reader, storage: Store) -> list[TopologyNode]:
        return graph(storage, actor).nodes

    @router.get("/topology/links", response_model=list[TopologyLink])
    def topology_links(actor: Reader, storage: Store) -> list[TopologyLink]:
        return graph(storage, actor).links

    @router.get("/topology/nodes/{device_id}", response_model=TopologyNode, responses={**NOT_FOUND})
    def topology_node(device_id: str, actor: Reader, storage: Store) -> TopologyNode:
        return _require(
            next((node for node in graph(storage, actor).nodes if node.id == device_id), None),
            "Node",
        )

    @router.get("/devices", response_model=Page[DeviceRecord])
    def devices(
        _actor: Analyst,
        storage: Store,
        page: PageNumber = 1,
        page_size: PageSize = 50,
        search: ShortQuery = None,
        enabled: bool | None = None,
    ) -> Page[DeviceRecord]:
        return storage.devices(page, page_size, search, enabled)

    @router.post(
        "/devices",
        status_code=201,
        response_model=DeviceRecord,
        responses={**BODY_ERRORS, **CONFLICT},
    )
    def create_device(body: DeviceCreate, actor: Admin, storage: Store) -> DeviceRecord:
        return _require(storage.save_device(body, actor.username), "Device")

    @router.get("/devices/{device_id}", response_model=DeviceRecord, responses={**NOT_FOUND})
    def get_device(device_id: UUID, _actor: Analyst, storage: Store) -> DeviceRecord:
        return _require(storage.device(device_id), "Device")

    @router.patch(
        "/devices/{device_id}",
        response_model=DeviceRecord,
        responses={**BODY_ERRORS, **CONFLICT, **NOT_FOUND},
    )
    def update_device(
        device_id: UUID, body: DevicePatch, actor: Admin, storage: Store
    ) -> DeviceRecord:
        try:
            return _require(storage.save_device(body, actor.username, device_id), "Device")
        except ValidationError as exc:
            raise HTTPException(422, "Invalid device update") from exc

    @router.delete(
        "/devices/{device_id}",
        status_code=204,
        responses={**BODY_ERRORS, **NOT_FOUND},
    )
    def deactivate_device(device_id: UUID, actor: Admin, storage: Store) -> Response:
        _require(
            storage.save_device(DevicePatch(enabled=False), actor.username, device_id), "Device"
        )
        return Response(status_code=204)

    @router.get(
        "/devices/{device_id}/events", response_model=Page[IndexedEvent], responses={**NOT_FOUND}
    )
    def device_events(
        device_id: UUID,
        _actor: Analyst,
        storage: Store,
        filters: Filters,
        page: PageNumber = 1,
        page_size: PageSize = 50,
        sort: Literal["desc", "asc"] = "desc",
    ) -> Page[IndexedEvent]:
        _require(storage.device(device_id), "Device")
        return storage.events(
            EventFilters(
                filters.start,
                filters.end,
                device_id,
                severity=filters.severity,
                category=filters.category,
                event_type=filters.event_type,
                vendor=filters.vendor,
                search=filters.search,
            ),
            page,
            page_size,
            sort,
        )

    @router.get(
        "/devices/{device_id}/incidents", response_model=Page[AlertRecord], responses={**NOT_FOUND}
    )
    def device_incidents(
        device_id: UUID,
        _actor: Analyst,
        storage: Store,
        filters: Filters,
        page: PageNumber = 1,
        page_size: PageSize = 50,
    ) -> Page[AlertRecord]:
        _require(storage.device(device_id), "Device")
        return storage.incidents(
            EventFilters(
                filters.start,
                filters.end,
                device_id,
                severity=filters.severity,
                category=filters.category,
            ),
            page,
            page_size,
        )

    def get_rule(storage: PostgresBackendStorage, rule_id: str) -> RuleRecord | BuiltinRule:
        if rule_id in builtin:
            return builtin[rule_id]
        return _require(
            next((rule for rule in storage.rules() if rule.id == rule_id), None),
            "Rule",
        )

    @router.get("/rules", response_model=list[RuleRecord | BuiltinRule])
    def rules(_actor: Admin, storage: Store) -> list[RuleRecord | BuiltinRule]:
        return [*builtin.values(), *storage.rules()]

    @router.post(
        "/rules",
        status_code=201,
        response_model=RuleRecord,
        responses={**BODY_ERRORS, **CONFLICT},
    )
    def create_rule(body: RuleCreate, actor: Admin, storage: Store) -> RuleRecord:
        return _require(storage.update_rule(body, config, body.id, actor.username), "Rule")

    @router.get(
        "/rules/{rule_id}", response_model=RuleRecord | BuiltinRule, responses={**NOT_FOUND}
    )
    def read_rule(rule_id: RuleId, _actor: Admin, storage: Store) -> RuleRecord | BuiltinRule:
        return get_rule(storage, rule_id)

    @router.patch(
        "/rules/{rule_id}",
        response_model=RuleRecord,
        responses={**BODY_ERRORS, **CONFLICT, **NOT_FOUND},
    )
    def update_rule(rule_id: RuleId, body: RulePatch, actor: Admin, storage: Store) -> RuleRecord:
        return _require(storage.update_rule(body, config, rule_id, actor.username), "Rule")

    @router.delete(
        "/rules/{rule_id}",
        status_code=204,
        responses={**BODY_ERRORS, **CONFLICT, **NOT_FOUND},
    )
    def deactivate_rule(rule_id: RuleId, actor: Admin, storage: Store) -> Response:
        _require(
            storage.update_rule(RulePatch(enabled=False), config, rule_id, actor.username), "Rule"
        )
        return Response(status_code=204)

    @router.post(
        "/rules/{rule_id}/validate",
        response_model=RuleValidation,
        responses={**BODY_ERRORS, **NOT_FOUND},
    )
    def validate_rule(rule_id: RuleId, _actor: Admin, storage: Store) -> RuleValidation:
        rule = get_rule(storage, rule_id)
        reason = rule.definition.activation_error(config) if isinstance(rule, RuleRecord) else None
        return RuleValidation(valid=reason is None, reason=reason)

    @router.post(
        "/rules/{rule_id}/test",
        response_model=list[RuleOutcome] | list[CorrelationResult],
        responses={**BODY_ERRORS, **NOT_FOUND},
    )
    def simulate_rule(
        rule_id: RuleId,
        body: RuleTest,
        _actor: Admin,
        storage: Store,
    ) -> list[RuleOutcome] | list[CorrelationResult]:
        rule = get_rule(storage, rule_id)
        if isinstance(rule, RuleRecord):
            return test_rule(rule, body.events)
        with TemporaryDirectory(prefix="networksec-rule-test-") as directory:
            store = CorrelationStore(FilePath(directory) / "case.db")
            store.initialize()
            if isinstance(rule.definition, CorrelationRule):
                isolated = CorrelationConfig(rules=(rule.definition,))
                samples = body.events
            else:
                isolated = config
                samples = [event for event in body.events if event.routing_protocol == "ospf"]
            engine = CorrelationEngine(store, isolated)
            return [engine.process(event) for event in samples]

    @router.get("/grafana/link", response_model=GrafanaLink, responses={**NOT_FOUND})
    def grafana_link(
        _actor: Reader,
        storage: Store,
        filters: Filters,
        incident_id: EventId | None = None,
    ) -> GrafanaLink:
        device_name = (
            _require(storage.device(filters.device_id), "Device").name
            if filters.device_id
            else None
        )
        try:
            url = dashboard_link(settings, filters, incident_id, device_name)
        except ValueError as exc:
            raise HTTPException(503, "Grafana link configuration is invalid") from exc
        if not url:
            raise HTTPException(503, "Grafana link configuration is unavailable")
        return GrafanaLink(url=url)

    @router.get("/audit-logs", response_model=Page[AuditRecord])
    def audit_log(
        _actor: Admin,
        storage: Store,
        filters: Filters,
        page: PageNumber = 1,
        page_size: PageSize = 50,
        action: ShortQuery = None,
        actor: ShortQuery = None,
        outcome: Literal["success", "failure"] | None = None,
    ) -> Page[AuditRecord]:
        return storage.audit_log(
            page, page_size, filters.start, filters.end, action, actor, outcome
        )

    @router.get("/reports/summary", response_model=DashboardSummary)
    def report_summary(actor: Reader, storage: Store, filters: Filters) -> DashboardSummary:
        result = summary(storage, actor, filters)
        storage.audit_event("report.generate", "report", "summary", actor.username)
        return result

    @router.get("/reports/events", response_model=Page[IndexedEvent])
    def report_events(
        actor: Analyst,
        storage: Store,
        filters: Filters,
        page: PageNumber = 1,
        page_size: PageSize = 50,
    ) -> Page[IndexedEvent]:
        result = storage.events(filters, page, page_size)
        storage.audit_event("report.generate", "report", "events", actor.username)
        return result

    @router.get("/reports/incidents", response_model=Page[AlertRecord])
    def report_incidents(
        actor: Analyst,
        storage: Store,
        filters: Filters,
        page: PageNumber = 1,
        page_size: PageSize = 50,
        ospf_only: bool = False,
    ) -> Page[AlertRecord]:
        result = storage.incidents(filters, page, page_size, ospf_only=ospf_only)
        storage.audit_event("report.generate", "report", "incidents", actor.username)
        return result

    @router.get("/reports/devices", response_model=Page[DeviceActivity])
    def report_devices(
        actor: Analyst,
        storage: Store,
        filters: Filters,
        page: PageNumber = 1,
        page_size: PageSize = 50,
        enabled: bool | None = None,
    ) -> Page[DeviceActivity]:
        result = storage.device_activity(filters, page, page_size, enabled)
        storage.audit_event("report.generate", "report", "devices", actor.username)
        return result

    @router.get(
        "/reports/export",
        response_model=(
            DashboardSummary | Page[IndexedEvent] | Page[AlertRecord] | Page[DeviceActivity]
        ),
        responses={
            200: {
                "content": {"text/csv": {"schema": {"type": "string"}}},
                "headers": {
                    "Content-Disposition": {"schema": {"type": "string"}},
                    "X-Report-Truncated": {"schema": {"type": "string", "enum": ["true", "false"]}},
                },
            },
        },
    )
    def export_report(
        actor: Reader,
        storage: Store,
        filters: Filters,
        report: Literal["summary", "events", "incidents", "devices"] = "summary",
        output: Annotated[Literal["json", "csv"], Query(alias="format")] = "json",
        limit: Annotated[int, Query(ge=1, le=1000)] = 500,
        ospf_only: bool = False,
        enabled: bool | None = None,
    ) -> Response:
        if report != "summary" and actor.role is Role.VIEWER:
            raise HTTPException(403, "Permission denied")
        result: BaseModel
        if report == "summary":
            result = summary(storage, actor, filters)
        elif report == "events":
            result = storage.events(filters, 1, limit)
        elif report == "incidents":
            result = storage.incidents(filters, 1, limit, ospf_only=ospf_only)
        else:
            result = storage.device_activity(filters, 1, limit, enabled)
        csv_fields = {
            "events": IndexedEvent.model_fields,
            "incidents": AlertRecord.model_fields,
            "devices": DeviceActivity.model_fields,
        }
        data = (
            _export_csv(result, tuple(csv_fields.get(report, {})))
            if output == "csv"
            else result.model_dump_json()
        )
        storage.audit_event("report.generate", "report", report, actor.username)
        return Response(
            data,
            media_type="text/csv" if output == "csv" else "application/json",
            headers={
                "Content-Disposition": f'attachment; filename="networksec-{report}.{output}"',
                "X-Report-Truncated": str(
                    isinstance(result, Page) and result.total > limit
                ).lower(),
            },
        )

    return router
