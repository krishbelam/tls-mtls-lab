# tls-mtls-lab

Hands-on lab for learning TLS and mutual TLS (mTLS) with OpenSSL and Python.

## What's inside
- `docs/tls-mtls-lab.html`: interactive guide. Open it in a browser. It covers cert and CSR
  generation, X.509 extensions, the `SSLContext` to file map, and the TLS vs mTLS flow.
- `scripts/gen_certs.sh`: creates a CA, a server cert and a client cert with strict-safe extensions.
- `server.py`: Flask server using `ssl.SSLContext`, with environment knobs for experiments.
- `client.py`: `requests` client with switches to break things on purpose.

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

bash scripts/gen_certs.sh        # writes ca/, server/ and client/ certs and keys
python server.py                 # mTLS required on :8000

# another terminal
python client.py
curl --cacert ca/ca.crt --cert client/client.crt --key client/client.key https://localhost:8000/whoami
```

## Experiments
| Command | Expected |
|---|---|
| `python client.py` | 200, server shows the client subject |
| `python client.py --no-cert` | Fails: `certificate required` |
| `VERIFY=none python server.py`, then `python client.py` | 200, but `client_certificate` is empty |
| `VERIFY=optional python server.py`, then `--no-cert` | 200 on `/`, 401 on `/whoami` |
| `python client.py --ctx strict` / `--ctx lax` | Toggles `VERIFY_X509_STRICT` on the client |
| `STRICT=1 python server.py` | Server enforces strict verification of client certs |
| Remove an extension in `gen_certs.sh`, regenerate | Strict mode fails with `Missing Authority Key Identifier` |

The guide's "SSLContext map" tab predicts each outcome.

## Notes
- Lab only. Keys are generated locally and git-ignored. Never commit them.
- Requires OpenSSL 3.x and Python 3.10+. Python 3.13+ enables `VERIFY_X509_STRICT`
  in `ssl.create_default_context()`, which is why the cert extensions matter.


## License
Licensed under the [Apache License 2.0](LICENSE).