"""Keeps the CRL that /crl/<id>.crl serves current, for CAs whose certificates name this
server as their distribution point. Clients cache a CRL until its next update, so the
served one is short-lived and re-signed on every revocation and before it runs out."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from . import crypto_engine, db

log = logging.getLogger("cert-generator")

PUBLISHED_CRL_DAYS = 7
RENEW_WHEN_LEFT = timedelta(days=PUBLISHED_CRL_DAYS / 2)
RENEW_CHECK_SECONDS = 3600


def publish(ca_id: int) -> str | None:
    """Sign and serve a fresh CRL for a CA that opted in; its next update, or None for any
    other CA. Raises db.DatabaseLocked while an encrypted database is locked."""
    if not db.is_crl_public(ca_id):
        return None
    db.require_unlocked()
    ca = db.get_ca(ca_id)
    if ca is None:
        return None
    crl_der = crypto_engine.generate_crl(
        ca_cert_pem=ca["cert_pem"],
        ca_key_pem=ca["key_pem"],
        revoked_serials=db.list_revoked_serials(ca_id),
        crl_lifetime_days=PUBLISHED_CRL_DAYS,
    )
    db.publish_crl(ca_id, crl_der)
    next_update = crypto_engine.crl_next_update(crl_der)
    log.info("CRL published for CA %d (next update %s)", ca_id, next_update)
    return next_update


def _due(crl_der: bytes | None, now: datetime) -> bool:
    if crl_der is None:
        return True
    next_update = datetime.strptime(crypto_engine.crl_next_update(crl_der), "%Y-%m-%dT%H:%M:%SZ")
    return next_update.replace(tzinfo=timezone.utc) - now <= RENEW_WHEN_LEFT


def renew_due(now: datetime | None = None) -> list[int]:
    """Re-sign every served CRL that is missing or within RENEW_WHEN_LEFT of its next update."""
    now = now or datetime.now(timezone.utc)
    renewed = []
    for ca_id, crl_der in db.list_public_crls():
        if not _due(crl_der, now):
            continue
        try:
            publish(ca_id)
        except db.DatabaseLocked:
            log.warning("Served CRLs can't be renewed while the database is locked; unlock it to resume")
            break
        renewed.append(ca_id)
    return renewed


def start_renewer() -> threading.Thread:
    """Check every RENEW_CHECK_SECONDS, starting now, for the life of the process."""
    def loop() -> None:
        while True:
            try:
                renew_due()
            except Exception:  # keep the renewer alive; the next pass retries
                log.exception("CRL renewal failed")
            threading.Event().wait(RENEW_CHECK_SECONDS)

    thread = threading.Thread(target=loop, name="crl-renewer", daemon=True)
    thread.start()
    return thread
