"""Logging estruturado em JSON. Nunca loga segredos, tokens, cookies ou captcha."""
from __future__ import annotations

import logging
import sys

from pythonjsonlogger import jsonlogger

_REDACTED_KEYS = {"password", "secret", "token", "captcha", "cookie", "authorization"}


class RedactingJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record.setdefault("level", record.levelname)
        log_record.setdefault("logger", record.name)
        for key in list(log_record.keys()):
            if any(redacted in key.lower() for redacted in _REDACTED_KEYS):
                log_record[key] = "***redacted***"


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        RedactingJsonFormatter("%(timestamp)s %(level)s %(logger)s %(message)s")
    )

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # httpx logs complete request URLs at INFO. Some APIs (including
    # PageSpeed Insights) authenticate through a query parameter, so logging
    # those URLs would expose credentials.
    for noisy in ("werkzeug", "gunicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
