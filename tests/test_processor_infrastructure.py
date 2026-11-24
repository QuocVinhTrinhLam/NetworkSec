"""Static safeguards for the production processor wiring."""

from __future__ import annotations

from pathlib import Path

import yaml


def test_compose_wires_hardened_processor_to_required_volumes_and_services() -> None:
    document = yaml.safe_load(Path("compose.yaml").read_text(encoding="utf-8"))
    processor = document["services"]["processor"]

    assert processor["command"] == ["python", "-m", "app.processor"]
    assert processor["build"]["dockerfile"] == "docker/Dockerfile"
    assert processor["read_only"] is True
    assert processor["cap_drop"] == ["ALL"]
    assert processor["security_opt"] == ["no-new-privileges:true"]
    assert processor["mem_limit"] == "256m"
    assert processor["cpus"] == 0.75
    assert "processor-state:/app/processor-state" in processor["volumes"]
    assert "syslog-raw:/var/log/networksec:ro" in processor["volumes"]
    assert set(processor["depends_on"]) == {"loki", "postgres", "rsyslog"}
    assert processor["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "app.processor.healthcheck",
    ]


def test_compose_keeps_grafana_and_legacy_notification_storage_wired() -> None:
    services = yaml.safe_load(Path("compose.yaml").read_text(encoding="utf-8"))["services"]
    assert "dashboard" not in services
    assert services["api"]["volumes"] == []
    assert services["api"]["ports"][0].startswith("${BIND_HOST:-127.0.0.1}:")
    assert services["grafana"]["ports"][0].startswith("${GRAFANA_BIND_HOST:-127.0.0.1}:")
    assert services["grafana"]["environment"]["GF_AUTH_ANONYMOUS_ENABLED"] == "false"
    assert set(services["bot"]["depends_on"]) == {"processor"}
    assert "GRAFANA_PUBLIC_URL" in services["bot"]["environment"]
    for service in ("bot", "mock"):
        assert "monitor-data:/app/data" in services[service]["volumes"]


def test_rsyslog_preserves_raw_and_emits_versioned_json_envelope() -> None:
    template = Path("infra/rsyslog/rsyslog.conf.template").read_text(encoding="utf-8")

    assert 'property(name="rawmsg")' in template
    assert 'option.jsonf="on"' in template
    assert 'property(name="rawmsg" outname="raw_message" format="jsonf")' in template
    assert 'property(name="rawmsg-after-pri" outname="parse_message" format="jsonf")' in template
    assert 'file="/var/log/networksec/processor.jsonl"' in template
    assert 'queue.filename="networksec_raw"' in template
    assert 'queue.filename="networksec_processor"' in template
    assert 'addLF="on"' in template


def test_rsyslog_publishes_both_5514_ports_on_loopback_by_default() -> None:
    document = yaml.safe_load(Path("compose.yaml").read_text(encoding="utf-8"))
    published_ports = document["services"]["rsyslog"]["ports"]
    assert set(published_ports) == {
        "${SYSLOG_BIND_HOST:-127.0.0.1}:${SYSLOG_TCP_PORT:-5514}:5514/tcp",
        "${SYSLOG_BIND_HOST:-127.0.0.1}:${SYSLOG_UDP_PORT:-5514}:5514/udp",
    }


def test_production_image_does_not_use_development_reload() -> None:
    dockerfile = Path("docker/Dockerfile").read_text(encoding="utf-8")

    assert "--reload" not in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "COPY --link --chown=10001:10001 migrations ./migrations" in dockerfile
