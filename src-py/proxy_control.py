import socket
import json
import logging

logger = logging.getLogger(__name__)

def send_proxy_command(host, port, command, timeout=3.0):
    """Send a JSON command to the proxy control TCP port and return response (if any)."""
    data = (json.dumps(command) + "\n").encode('utf-8')
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(data)
        # try to read a line response
        s.settimeout(0.5)
        try:
            resp = s.recv(4096)
            return resp.decode('utf-8').strip()
        except socket.timeout:
            return None
