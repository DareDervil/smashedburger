"""Centralised logging configuration for smashedburger.

Call configure_logging() once at app startup (main.py).
All other modules do: logger = logging.getLogger(__name__)

Why logging over print:
- Levels (DEBUG/INFO/WARNING/ERROR) let you filter noise without touching code.
  Set LOG_LEVEL=DEBUG locally; leave it INFO on Fly.io.
- __name__ as logger name gives you the module hierarchy:
  smashedburger.main, smashedburger.sources.nvd, etc.
  You can silence noisy subsystems without turning off everything.
- Timestamps and level in every line — essential when reading fly logs.
- gunicorn's own logger uses the same framework, so log lines interleave cleanly.
"""
import logging
import os
import sys


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    fmt = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        stream=sys.stdout,
        level=level,
        format=fmt,
        datefmt=datefmt,
    )

    # Quiet noisy third-party loggers
    for noisy in ("httpx", "httpcore", "anthropic", "urllib3", "werkzeug"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        "Logging configured — level=%s", level_name
    )
