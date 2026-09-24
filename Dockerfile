FROM python:3.12.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MIKROTIK_REPORT_NOTIFIER=/usr/local/bin/send-mail

RUN groupadd --gid 10001 mikrotik-report \
    && useradd --uid 10001 --gid mikrotik-report --no-create-home --no-log-init \
        --home-dir /nonexistent --shell /usr/sbin/nologin mikrotik-report \
    && mkdir -p /var/lib/mikrotik-report \
    && chown 10001:10001 /var/lib/mikrotik-report

WORKDIR /app

COPY mikrotik_report.py ./
COPY mikrotik_reporting ./mikrotik_reporting
COPY --chmod=0555 send_mail.py /usr/local/bin/send-mail

USER 10001:10001

VOLUME ["/var/lib/mikrotik-report"]
STOPSIGNAL SIGTERM

ENTRYPOINT ["python3", "/app/mikrotik_report.py"]
CMD ["run"]
