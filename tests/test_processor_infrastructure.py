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


def test_production_image_does_not_use_development_reload() -> None:
    dockerfile = Path("docker/Dockerfile").read_text(encoding="utf-8")

    assert "--reload" not in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "COPY --link --chown=10001:10001 migrations ./migrations" in dockerfile
