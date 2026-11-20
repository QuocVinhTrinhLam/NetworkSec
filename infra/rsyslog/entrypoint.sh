#!/bin/sh
set -eu

umask 027

RSYSLOG_QUEUE_SIZE="${RSYSLOG_QUEUE_SIZE:-10000}"
RSYSLOG_QUEUE_HIGH_WATERMARK="${RSYSLOG_QUEUE_HIGH_WATERMARK:-8000}"
RSYSLOG_QUEUE_LOW_WATERMARK="${RSYSLOG_QUEUE_LOW_WATERMARK:-2000}"
RSYSLOG_QUEUE_DISK_MB="${RSYSLOG_QUEUE_DISK_MB:-256}"
RSYSLOG_QUEUE_WORKERS="${RSYSLOG_QUEUE_WORKERS:-1}"
RSYSLOG_QUEUE_CHECKPOINT_INTERVAL="${RSYSLOG_QUEUE_CHECKPOINT_INTERVAL:-100}"
RSYSLOG_RETRY_SECONDS="${RSYSLOG_RETRY_SECONDS:-2}"
RSYSLOG_MAX_MESSAGE_KB="${RSYSLOG_MAX_MESSAGE_KB:-32}"

validate_uint() {
    setting_name="$1"
    setting_value="$2"
    setting_min="$3"
    setting_max="$4"
    case "$setting_value" in
        ''|*[!0-9]*)
            echo "$setting_name must be an integer" >&2
            exit 64
            ;;
    esac
    if [ "$setting_value" -lt "$setting_min" ] || [ "$setting_value" -gt "$setting_max" ]; then
        echo "$setting_name must be between $setting_min and $setting_max" >&2
        exit 64
    fi
}

validate_uint RSYSLOG_QUEUE_SIZE "$RSYSLOG_QUEUE_SIZE" 100 1000000
validate_uint RSYSLOG_QUEUE_HIGH_WATERMARK "$RSYSLOG_QUEUE_HIGH_WATERMARK" 2 999999
validate_uint RSYSLOG_QUEUE_LOW_WATERMARK "$RSYSLOG_QUEUE_LOW_WATERMARK" 1 999998
validate_uint RSYSLOG_QUEUE_DISK_MB "$RSYSLOG_QUEUE_DISK_MB" 16 4096
validate_uint RSYSLOG_QUEUE_WORKERS "$RSYSLOG_QUEUE_WORKERS" 1 8
validate_uint RSYSLOG_QUEUE_CHECKPOINT_INTERVAL "$RSYSLOG_QUEUE_CHECKPOINT_INTERVAL" 1 100000
validate_uint RSYSLOG_RETRY_SECONDS "$RSYSLOG_RETRY_SECONDS" 1 300
validate_uint RSYSLOG_MAX_MESSAGE_KB "$RSYSLOG_MAX_MESSAGE_KB" 1 64

if [ "$RSYSLOG_QUEUE_LOW_WATERMARK" -ge "$RSYSLOG_QUEUE_HIGH_WATERMARK" ] || \
   [ "$RSYSLOG_QUEUE_HIGH_WATERMARK" -ge "$RSYSLOG_QUEUE_SIZE" ]; then
    echo "queue watermarks must satisfy low < high < size" >&2
    exit 64
fi

mkdir -p /var/spool/rsyslog /var/log/networksec
chgrp 10001 /var/log/networksec
chmod 0750 /var/log/networksec

sed \
    -e "s/@@QUEUE_SIZE@@/$RSYSLOG_QUEUE_SIZE/g" \
    -e "s/@@HIGH_WATERMARK@@/$RSYSLOG_QUEUE_HIGH_WATERMARK/g" \
    -e "s/@@LOW_WATERMARK@@/$RSYSLOG_QUEUE_LOW_WATERMARK/g" \
    -e "s/@@QUEUE_DISK_MB@@/$RSYSLOG_QUEUE_DISK_MB/g" \
    -e "s/@@QUEUE_WORKERS@@/$RSYSLOG_QUEUE_WORKERS/g" \
    -e "s/@@CHECKPOINT_INTERVAL@@/$RSYSLOG_QUEUE_CHECKPOINT_INTERVAL/g" \
    -e "s/@@RETRY_SECONDS@@/$RSYSLOG_RETRY_SECONDS/g" \
    -e "s/@@MAX_MESSAGE_KB@@/$RSYSLOG_MAX_MESSAGE_KB/g" \
    /etc/networksec/rsyslog.conf.template > /tmp/rsyslog.conf

rsyslogd -N1 -f /tmp/rsyslog.conf
exec rsyslogd -n -f /tmp/rsyslog.conf
