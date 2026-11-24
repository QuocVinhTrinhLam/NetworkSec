"""Recovery projection for the YAML interface link-state aggregation rule."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from psycopg.types.json import Jsonb

from app.schemas.event import EventType, NormalizedEvent


def record_interface_observation(
    connection: Any, event: NormalizedEvent, device_identity: str | None
) -> None:
    """Use a strictly later same-interface Up as technical evidence for a Down window."""
    if (
        event.event_type not in {EventType.LINK_DOWN, EventType.LINK_UP}
        or not event.device_name
        or not event.interface_name
    ):
        return

    logical_group = {"device_name": event.device_name, "interface_name": event.interface_name}
    aggregate = connection.execute(
        """
        SELECT ref.aggregate_id FROM alert_event_refs AS ref
        JOIN aggregated_alerts AS alert USING (aggregate_id)
        WHERE ref.event_id = %s AND alert.rule_id = 'interface-link-state'
          AND alert.event_family = 'link_state' AND alert.group_key @> %s
        """,
        (event.event_id, Jsonb(logical_group)),
    ).fetchone()
    if aggregate is None:
        return

    # Existing YAML groups by hostname, while a registered device can report multiple hostnames.
    # Lock both in a fixed order to serialize claims that touch either group.
    connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        ("networksec:interface-window:" + json.dumps(logical_group),),
    )
    endpoint_key = None
    if device_identity is not None:
        endpoint = json.dumps((device_identity, event.interface_name))
        endpoint_key = hashlib.sha256(endpoint.encode()).hexdigest()
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            ("networksec:interface-endpoint:" + endpoint_key,),
        )

    is_down = event.event_type is EventType.LINK_DOWN
    aggregate_id = aggregate["aggregate_id"]
    connection.execute(
        """
        INSERT INTO interface_link_observations
            (event_id, aggregate_id, endpoint_key, observed_at, is_down)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (event.event_id, aggregate_id, endpoint_key, event.timestamp, is_down),
    )
    changes = connection.execute(
        """
        WITH candidates AS (
            SELECT %s::char(64) AS aggregate_id
            UNION
            SELECT earlier.aggregate_id FROM interface_link_observations AS earlier
            LEFT JOIN interface_link_recoveries AS current USING (aggregate_id)
            LEFT JOIN interface_link_observations AS chosen ON chosen.event_id = current.event_id
            WHERE %s AND earlier.endpoint_key = %s AND earlier.is_down
              AND earlier.observed_at < %s
              AND (chosen.event_id IS NULL OR (chosen.observed_at, chosen.event_id) > (%s, %s))
        ), downs AS (
            SELECT aggregate_id, max(observed_at) AS down_at,
                   CASE WHEN count(DISTINCT endpoint_key) = 1 AND count(endpoint_key) = count(*)
                        THEN min(endpoint_key) END AS endpoint_key
            FROM interface_link_observations JOIN candidates USING (aggregate_id)
            WHERE is_down GROUP BY aggregate_id
        )
        SELECT downs.aggregate_id, recovery.event_id
        FROM downs
        LEFT JOIN LATERAL (
            SELECT event_id FROM interface_link_observations AS observed
            WHERE NOT observed.is_down AND observed.endpoint_key = downs.endpoint_key
              AND observed.observed_at > downs.down_at
            ORDER BY observed.observed_at, observed.event_id LIMIT 1
        ) AS recovery ON true
        WHERE NOT EXISTS (
            SELECT 1 FROM alert_event_refs AS ref
            LEFT JOIN interface_link_observations AS observed USING (event_id)
            WHERE ref.aggregate_id = downs.aggregate_id AND observed.event_id IS NULL
              AND (ref.event_type = 'link_down' OR ref.event_type IS NULL)
        )
        ORDER BY downs.aggregate_id
        """,
        (
            aggregate_id,
            not is_down and endpoint_key is not None,
            endpoint_key,
            event.timestamp,
            event.timestamp,
            event.event_id,
        ),
    ).fetchall()
    for change in changes:
        _project_interface_recovery(connection, change["aggregate_id"], change["event_id"])


def _project_interface_recovery(connection: Any, aggregate_id: str, event_id: str | None) -> None:
    if event_id is not None:
        assigned = connection.execute(
            """
            INSERT INTO interface_link_recoveries (aggregate_id, event_id) VALUES (%s, %s)
            ON CONFLICT (aggregate_id) DO UPDATE SET event_id = EXCLUDED.event_id
            WHERE interface_link_recoveries.event_id <> EXCLUDED.event_id
            RETURNING aggregate_id
            """,
            (aggregate_id, event_id),
        ).fetchone()
        if assigned is None:
            return
        connection.execute(
            """
            UPDATE aggregated_alerts
               SET status = 'resolved', status_change_source = 'interface_recovery',
                   status_changed_by = 'interface-correlation',
                   status_changed_at = now(), updated_at = now()
             WHERE aggregate_id = %s AND status <> 'resolved'
            """,
            (aggregate_id,),
        )
        return

    removed = connection.execute(
        "DELETE FROM interface_link_recoveries WHERE aggregate_id = %s RETURNING aggregate_id",
        (aggregate_id,),
    ).fetchone()
    if removed is None:
        return
    connection.execute(
        """
        UPDATE aggregated_alerts AS alert
           SET status = COALESCE((
                   SELECT previous_status FROM alert_status_history AS history
                   WHERE history.aggregate_id = alert.aggregate_id AND source = 'interface_recovery'
                   ORDER BY change_id DESC LIMIT 1
               ), 'new'),
               status_change_source = 'interface_reassessment',
               status_changed_by = 'interface-correlation',
               status_changed_at = now(), updated_at = now()
         WHERE aggregate_id = %s AND status = 'resolved'
           AND status_change_source = 'interface_recovery'
        """,
        (aggregate_id,),
    )
