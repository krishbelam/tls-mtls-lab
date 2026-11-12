import logging
import os
import ssl
import time
from pathlib import Path

from flask import Flask, g, jsonify, request
from werkzeug.serving import WSGIRequestHandler, run_simple

# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

# Experiment knobs (environment variables):
#   VERIFY=none|optional|required   client certificate policy (default: required)
#   STRICT=1                        enable ssl.VERIFY_X509_STRICT on the server context
#   PORT=8000
VERIFY_MODES = {
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
    "required": ssl.CERT_REQUIRED,
}
VERIFY = os.getenv("VERIFY", "required").lower()
PORT = int(os.getenv("PORT", "8000"))


def get_file_path(relative_path: str) -> str:
    return str((BASE_DIR / relative_path).resolve())


def subject_dict(cert):
    """Flatten getpeercert()['subject'] into {'commonName': 'alice', 'organizationName': 'engineers'}."""
    if not cert:
        return {}
    return {key: value for rdn in cert.get("subject", ()) for key, value in rdn}


# --------------------------------------------------
# CUSTOM WERKZEUG HANDLER
# --------------------------------------------------

class MTLSRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()

        # Peer certificate from the TLS connection. Empty ({}) when the client sent none
        # or the server did not request one (VERIFY=none).
        getpeercert = getattr(self.connection, "getpeercert", None)
        environ["peercert"] = getpeercert() if getpeercert else None

        return environ


# --------------------------------------------------
# REQUEST HOOKS
# --------------------------------------------------

@app.before_request
def request_logger():
    g.start_time = time.perf_counter()
    g.client_certificate = request.environ.get("peercert")

    logger.info(
        "Incoming request: %s %s | client: %s",
        request.method,
        request.path,
        subject_dict(g.client_certificate) or "anonymous",
    )


# after_request hooks run in reverse registration order:
# response_logger (registered second) runs first, then add_response_headers.
@app.after_request
def add_response_headers(response):
    # Lab only: a wildcard CORS header on an authenticated service is not something to ship.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.after_request
def response_logger(response):
    start_time = getattr(g, "start_time", None)

    if start_time is not None:
        duration = time.perf_counter() - start_time
        logger.info("Response: %s | Duration: %.4fs", response.status_code, duration)
        response.headers["X-Execution-Time"] = f"{duration:.4f}s"

    return response


@app.teardown_request
def teardown_request(exception=None):
    if exception:
        logger.error("Request teardown with exception: %s", exception)


# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@app.route("/")
def home():
    # Invalid values fall back to the default
    sleep_time = request.args.get("timeout", default=2.0, type=float)

    # Prevent excessively long sleeps in this experiment
    sleep_time = max(0.0, min(sleep_time, 10.0))

    logger.info("Sleeping for %.2f seconds", sleep_time)
    time.sleep(sleep_time)
    logger.info("Sleep completed")

    return jsonify({
        "message": "Hello World",
        "client_certificate": g.client_certificate,
    })


@app.route("/whoami")
def whoami():
    """Authentication (cert verified by TLS) versus authorization (decided here)."""
    who = subject_dict(g.client_certificate)

    if not who:
        return jsonify({"error": "no client certificate"}), 401

    if who.get("organizationName") != "engineers":
        return jsonify({"error": "forbidden", "subject": who}), 403

    return jsonify({
        "user": who.get("commonName"),
        "group": who.get("organizationName"),
    })


@app.route("/error")
def error():
    raise ValueError("Intentional test exception")


# --------------------------------------------------
# SSL CONTEXT
# --------------------------------------------------

def create_context():
    # Note: a bare SSLContext does not enable VERIFY_X509_STRICT, unlike
    # ssl.create_default_context() on Python 3.13+. Use STRICT=1 to turn it on.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Who I am: presented to clients, key signs the handshake
    ctx.load_cert_chain(
        certfile=get_file_path("server/server.crt"),
        keyfile=get_file_path("server/server.key"),
    )

    # Whom I trust for client certificates: the public CA cert only, never ca.key
    ctx.load_verify_locations(cafile=get_file_path("ca/ca.crt"))

    ctx.verify_mode = VERIFY_MODES[VERIFY]

    if os.getenv("STRICT") == "1":
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT

    return ctx


def inspect_context(ctx):
    logger.info("Protocol: %s", ctx.protocol)
    logger.info("Verify mode: %s", ctx.verify_mode)
    logger.info("Verify flags: %r", ctx.verify_flags)
    logger.info("Strict: %s", bool(ctx.verify_flags & ssl.VERIFY_X509_STRICT))
    logger.info("Partial chain: %s", bool(ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN))
    logger.info("Trusted CA certificates: %s", len(ctx.get_ca_certs()))


# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------

def main():
    if VERIFY not in VERIFY_MODES:
        raise SystemExit(f"VERIFY must be one of {sorted(VERIFY_MODES)}, got {VERIFY!r}")

    ctx = create_context()
    inspect_context(ctx)

    run_simple(
        hostname="0.0.0.0",
        port=PORT,
        application=app,
        ssl_context=ctx,
        request_handler=MTLSRequestHandler,
        threaded=True,
    )


if __name__ == "__main__":
    main()