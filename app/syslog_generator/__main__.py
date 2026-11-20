"""Command-line entry point for generated and Loghub Syslog events."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from app.syslog_generator.generator import (
    GeneratorConfig,
    Protocol,
    SyslogSendError,
    iter_generated_events,
    iter_loghub_messages,
    send_messages,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send generated or Loghub events to rsyslog")
    parser.add_argument("--host", default=os.getenv("SYSLOG_TARGET_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=os.getenv("SYSLOG_TARGET_PORT", "5514"))
    parser.add_argument(
        "--protocol",
        type=Protocol,
        choices=list(Protocol),
        default=os.getenv("SYSLOG_PROTOCOL", Protocol.TCP.value),
    )
    parser.add_argument("--rate", type=float, default=os.getenv("SYSLOG_EVENT_RATE", "10"))
    parser.add_argument("--count", type=int, default=os.getenv("SYSLOG_EVENT_COUNT", "100"))
    parser.add_argument("--retries", type=int, default=os.getenv("SYSLOG_SEND_RETRIES", "3"))
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=os.getenv("SYSLOG_RETRY_DELAY_SECONDS", "0.5"),
    )
    parser.add_argument("--start-sequence", type=int, default=1)
    parser.add_argument("--hostname", default="networksec-generator")
    parser.add_argument("--app-name", default="syslog-generator")
    parser.add_argument(
        "--loghub-file",
        type=Path,
        help="Replay this line-oriented Loghub file instead of generating RFC 5424 events",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        config = GeneratorConfig(
            host=args.host,
            port=args.port,
            protocol=args.protocol,
            rate=args.rate,
            retries=args.retries,
            retry_delay=args.retry_delay,
        )
        if args.loghub_file:
            limit = args.count if args.count > 0 else None
            messages = iter_loghub_messages(args.loghub_file, limit=limit)
            source = str(args.loghub_file)
        else:
            messages = iter_generated_events(
                args.count,
                start_sequence=args.start_sequence,
                hostname=args.hostname,
                app_name=args.app_name,
            )
            source = "generated"
        sent = send_messages(messages, config)
    except (OSError, ValueError, SyslogSendError) as error:
        parser.exit(1, f"syslog generator failed: {error}\n")
    print(
        f"sent={sent} source={source} protocol={config.protocol.value} "
        f"target={config.host}:{config.port} rate={config.rate:g}/s"
    )


if __name__ == "__main__":
    main()
