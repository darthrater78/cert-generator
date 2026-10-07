"""Keeps a CA's published CRL current: the one /crl/<id>.crl serves, for CAs whose
certificates name this server as their distribution point, and the one its Cloudflare
Worker serves (crl_worker). Clients cache a CRL until its next update, so the published
one is short-lived (7 days unless the CA is set otherwise) and re-signed on every
revocation and at half its life."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from . import crypto_engine, db

log = logging.getLogger("cert-generator")

PUBLISHED_CRL_DAYS = 7  # the default; a CA can be set to any of CRL_DAYS_CHOICES
CRL_DAYS_CHOICES = (1, 2, 3, 7, 14)
RENEW_WHEN_LEFT = timedelta(days=PUBLISHED_CRL_DAYS / 2)  # for a default CRL: every CRL is renewed at half its own life
RENEW_CHECK_SECONDS = 3600


def publish(ca_id: int) -> str | None:
    """Sign a fresh CRL for a CA whose CRL the app publishes, and push it to the CA's
    Cloudflare Worker if it has one; the CRL's next update, or None for any other CA.
    Raises db.DatabaseLocked while an encrypted database is locked. A failed push doesn't
    raise: it is recorded on the CA and retried by the next renewal pass."""
    next_update = sign(ca_id)
    if next_update is not None:
        from . import crl_worker  # imported here: crl_worker imports this module

        crl_worker.push(ca_id)
    return next_update


def sign(ca_id: int) -> str | None:
    """Sign and store a fresh CRL for a CA whose CRL the app publishes (see publish)."""
    if not db.is_crl_maintained(ca_id):
        return None
    db.require_unlocked()
    ca = db.get_ca(ca_id)
    if ca is None:
        return None
    crl_der = crypto_engine.generate_crl(
        ca_cert_pem=ca["cert_pem"],
        ca_key_pem=ca["key_pem"],
        revoked_serials=db.list_revoked_serials(ca_id),
        crl_lifetime_days=db.get_crl_days(ca_id),
    )
    db.publish_crl(ca_id, crl_der)
    next_update = crypto_engine.crl_next_update(crl_der)
    log.info("CRL published for CA %d (next update %s)", ca_id, next_update)
    return next_update


def _due(crl_der: bytes | None, now: datetime) -> bool:
    if crl_der is None:
        return True
    issued, next_update = crypto_engine.crl_validity(crl_der)
    return next_update - now <= (next_update - issued) / 2


def renew_due(now: datetime | None = None) -> list[int]:
    """Re-sign every published CRL that is missing or has half its life or less left, and
    retry Cloudflare pushes that failed."""
    from . import crl_worker

    now = now or datetime.now(timezone.utc)
    renewed = []
    for ca_id, crl_der in db.list_public_crls():
        if not _due(crl_der, now):
            worker = db.get_ca_worker(ca_id)
            if worker and worker["cf_push_error"]:
                crl_worker.push(ca_id)
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
