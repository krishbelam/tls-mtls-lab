import argparse
import ssl

import requests
from requests.adapters import HTTPAdapter

CLIENT_CERT = "client/client.crt"
CLIENT_KEY = "client/client.key"
CA_CERT = "ca/ca.crt"


class ContextAdapter(HTTPAdapter):
    """Lets requests use our own SSLContext (needed to control verify_flags)."""

    def __init__(self, ctx, **kwargs):
        self._ctx = ctx
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        super().init_poolmanager(*args, **kwargs)


def build_session(ctx_mode: str, send_cert: bool) -> requests.Session:
    session = requests.Session()
    session.verify = CA_CERT                      # whom I trust (ca.crt only)
    if send_cert:
        session.cert = (CLIENT_CERT, CLIENT_KEY)  # who I am

    if ctx_mode != "default":
        ctx = ssl.create_default_context(cafile=CA_CERT)
        if send_cert:
            ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
        if ctx_mode == "strict":
            ctx.verify_flags |= ssl.VERIFY_X509_STRICT
        elif ctx_mode == "lax":
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        session.mount("https://", ContextAdapter(ctx))

    return session


def main():
    parser = argparse.ArgumentParser(description="mTLS test client")
    parser.add_argument("--url", default="https://127.0.0.1:8000/?timeout=1")
    parser.add_argument("--no-cert", action="store_true", help="do not present a client certificate")
    parser.add_argument(
        "--ctx",
        choices=["default", "strict", "lax"],
        default="default",
        help="default: plain requests; strict/lax: custom SSLContext with VERIFY_X509_STRICT on/off",
    )
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()

    try:
        session = build_session(args.ctx, send_cert=not args.no_cert)
        response = session.get(args.url, timeout=args.timeout)
        response.raise_for_status()
        print(
            f"response.status_code: {response.status_code}\n"
            f"response.json: {response.json()}\n"
        )

    except requests.exceptions.ConnectTimeout:
        print("Connection timed out")

    except requests.exceptions.ReadTimeout:
        print("Server took too long to respond")

    except requests.exceptions.SSLError as exc:
        # e.g. CERTIFICATE_VERIFY_FAILED (client does not trust the server),
        # or the server rejected our cert (unknown ca / certificate required)
        print("TLS error:", exc)

    except requests.exceptions.RequestException as exc:
        print("Request error:", exc)

    except OSError as exc:
        # Raised by requests/ssl when a cert or key file is missing or unreadable
        print("File error (did you run scripts/gen_certs.sh?):", exc)


if __name__ == "__main__":
    main()