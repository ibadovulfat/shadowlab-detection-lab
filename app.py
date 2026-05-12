from __future__ import annotations

import logging
import os
import ssl

import uvicorn


TRUE_VALUES = {"1", "true", "yes", "on"}


def configure_logging() -> None:
    level_name = (os.environ.get("SHADOWLAB_LOG_LEVEL", "INFO") or "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )


def _tls_kwargs() -> dict[str, object]:
    """Translate `SHADOWLAB_TLS_*` env vars into uvicorn kwargs.

    Server-side TLS:
      * `SHADOWLAB_TLS_CERT_FILE` (PEM, required)
      * `SHADOWLAB_TLS_KEY_FILE` (PEM, required)
      * `SHADOWLAB_TLS_KEY_PASSWORD` (optional)

    Mutual TLS (client certificate verification):
      * `SHADOWLAB_MTLS_CA_FILE` — PEM CA bundle that signs every
        accepted client certificate. When set, uvicorn binds with
        `ssl.CERT_REQUIRED`, rejecting any connection that doesn't
        present a chain rooted at this CA.

    Returns `{}` when no TLS settings are configured so the call site
    falls back to plain HTTP (the lab default).
    """
    cert = (os.environ.get("SHADOWLAB_TLS_CERT_FILE", "") or "").strip()
    key = (os.environ.get("SHADOWLAB_TLS_KEY_FILE", "") or "").strip()
    if not cert and not key:
        return {}
    if not (cert and key):
        raise RuntimeError("SHADOWLAB_TLS_CERT_FILE and SHADOWLAB_TLS_KEY_FILE must be set together")
    kwargs: dict[str, object] = {
        "ssl_certfile": cert,
        "ssl_keyfile": key,
    }
    password = (os.environ.get("SHADOWLAB_TLS_KEY_PASSWORD", "") or "").strip()
    if password:
        kwargs["ssl_keyfile_password"] = password
    ca_file = (os.environ.get("SHADOWLAB_MTLS_CA_FILE", "") or "").strip()
    if ca_file:
        # uvicorn passes these through to the underlying TLS context;
        # `ssl.CERT_REQUIRED` (=2) is the strict-mTLS posture.
        kwargs["ssl_ca_certs"] = ca_file
        kwargs["ssl_cert_reqs"] = int(ssl.CERT_REQUIRED)
        logging.getLogger(__name__).info(
            "Mutual TLS enabled — clients must present a certificate signed by %s",
            ca_file,
        )
    return kwargs


def main() -> None:
    configure_logging()
    host = os.environ.get("SHADOWLAB_HOST", "127.0.0.1")
    port = int(os.environ.get("SHADOWLAB_PORT", "8000"))
    uvicorn.run("api.main:app", host=host, port=port, reload=False, **_tls_kwargs())


if __name__ == "__main__":
    main()
