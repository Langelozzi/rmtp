# Companion App for UDP Reliability Project

This companion app receives live log messages from the client, proxy and server over TCP, stores them in SQLite, serves a browser UI for real-time visualization, and can send control commands to the proxy to adjust drop/delay parameters.

Quick start (from this folder):

1. Create a virtualenv and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the app (defaults to listening for logs on port 9000 and web UI on 5000):

```bash
python server.py
```

3. In your client/proxy/server, send JSON log lines (newline-terminated) to the log TCP server. Example message:

```json
{"source": "client", "type": "sent", "seq": 1, "ts": 1690000000.0, "msg": "SYN"}
```

4. Open the browser at `http://localhost:5000` to view live graphs.

Control API:
- POST `/control/proxy` with JSON `{ "host": "proxy-host", "port": 6000, "command": { ... } }` to send a command to the proxy control port over TCP.

Notes:
- The proxy must implement a small control interface (TCP) that accepts JSON commands. If your C proxy doesn't have that yet, you can run a small control stub to test.
