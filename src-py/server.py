from flask import Flask, render_template, request, jsonify, Response
import threading
import json
from tcp_server import TCPServer
import db
from proxy_control import send_proxy_command
from logs import (
    ServerLog, ProxyLog, ClientLog,
    ClientLogType, ProxyLogType, ServerLogType
)

app = Flask(__name__, static_folder='static', template_folder='templates')

# SSE subscribers
subs = []

# Raw logs (for UI display)
client_logs = []
proxy_logs = []
server_logs = []

# Accurate message-level state
message_state = {}  # seq_num → {attempted, acked, retrans, timeouts}

# Accurate proxy running stats
proxy_state = {
    'total_received': 0,
    'dropped': 0,
    'forwarded': 0,
    'delayed': 0
}


# ---------------------------------------------------------------------------
# Incoming Log Handling
# ---------------------------------------------------------------------------

def on_new_message(data, conn):
    text = data.decode().strip() if isinstance(data, (bytes, bytearray)) else str(data).strip()

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        print("Received non-JSON:", text)
        return

    prefix = obj.get("prefix")
    parsed_log = None

    if prefix == "server":
        parsed_log = on_server_log(obj)
    elif prefix == "proxy":
        parsed_log = on_proxy_log(obj)
    elif prefix == "client":
        parsed_log = on_client_log(obj)
    else:
        print("Unknown prefix in log")
        return

    # Send through SSE
    if parsed_log:
        try:
            s = json.dumps(parsed_log.to_dict())
            for q in list(subs):
                try:
                    q.put(s)
                except Exception:
                    pass
        except Exception:
            pass


# ---------------------- SERVER LOG -------------------------

def on_server_log(raw):
    log = ServerLog(raw)
    server_logs.append(log)
    print(log)
    return log


# ---------------------- PROXY LOG --------------------------

def on_proxy_log(raw):
    log = ProxyLog(raw)
    proxy_logs.append(log)
    print(log)

    t = log.type

    if t in [ProxyLogType.DATA_RECVD, ProxyLogType.ACK_RECVD]:
        proxy_state['total_received'] += 1

    elif t in [ProxyLogType.DATA_DROPPED, ProxyLogType.ACK_DROPPED]:
        proxy_state['dropped'] += 1

    elif t in [ProxyLogType.DATA_FORWARDED, ProxyLogType.ACK_FORWARDED]:
        proxy_state['forwarded'] += 1

    elif t in [ProxyLogType.DATA_DELAYED, ProxyLogType.ACK_DELAYED]:
        proxy_state['delayed'] += 1

    return log


# ---------------------- CLIENT LOG ------------------------

def on_client_log(raw):
    log = ClientLog(raw)
    client_logs.append(log)
    print(log)

    seq = log.seq_num
    if seq is None:
        return log

    # create per-sequence state if not exists
    state = message_state.setdefault(seq, {
        'attempted': False,
        'acked': False,
        'retrans': 0,
        'timeouts': 0
    })

    if log.type == ClientLogType.MSG_SENT:
        if not state['attempted']:
            state['attempted'] = True
        else:
            state['retrans'] += 1

    elif log.type == ClientLogType.ACK_RECVD:
        state['acked'] = True  # Only do this once; duplicates ignored

    elif log.type == ClientLogType.TIMEOUT_REACHED:
        state['timeouts'] += 1

    return log


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


# ---------------- STATS: SIMPLE MESSAGE COUNTS --------------------

@app.route('/api/message-counts')
def message_counts():
    result = {
        'client': {'sent': 0, 'received': 0},
        'proxy': {'forwarded': proxy_state['forwarded'], 'dropped': proxy_state['dropped']},
        'server': {'sent': 0, 'received': 0}
    }

    # client counts (log-based)
    for log in client_logs:
        if log.type == ClientLogType.MSG_SENT:
            result['client']['sent'] += 1
        elif log.type == ClientLogType.ACK_RECVD:
            result['client']['received'] += 1

    # server counts (log-based)
    for log in server_logs:
        if log.type == ServerLogType.MSG_RECVD:
            result['server']['received'] += 1
        elif log.type == ServerLogType.ACK_SENT:
            result['server']['sent'] += 1

    return jsonify(result)


# -------------------- PROXY + RELIABILITY STATS --------------------

@app.route('/api/proxy-stats')
def proxy_stats():

    attempted = sum(1 for s in message_state.values() if s['attempted'])
    acked = sum(1 for s in message_state.values() if s['acked'])
    retrans = sum(s['retrans'] for s in message_state.values())
    lost = sum(1 for s in message_state.values()
               if not s['acked'] and s['timeouts'] > 0)

    total = proxy_state['total_received'] or (proxy_state['dropped'] + proxy_state['forwarded'])

    drop_rate = (proxy_state['dropped'] / total * 100) if total > 0 else 0
    delay_rate = (proxy_state['delayed'] / total * 100) if total > 0 else 0

    round_trip_success = (acked / attempted * 100) if attempted > 0 else 100.0

    return jsonify({
        'drop_rate': round(drop_rate, 2),
        'delay_rate': round(delay_rate, 2),
        'round_trip_success_rate': round(round_trip_success, 2),

        'total_packets': total,
        'dropped': proxy_state['dropped'],
        'forwarded': proxy_state['forwarded'],
        'delayed': proxy_state['delayed'],

        'messages_attempted': attempted,
        'messages_acknowledged': acked,
        'retransmissions': retrans,
        'lost_packets': lost
    })


# ------------------ RETRANSMISSION STATS ------------------------

@app.route('/api/retransmission-stats')
def retransmission_stats():

    timeouts = sum(s['timeouts'] for s in message_state.values())
    retrans = sum(s['retrans'] for s in message_state.values())
    max_retry = max((s['retrans'] for s in message_state.values()), default=0)

    return jsonify({
        'timeouts': timeouts,
        'retransmissions': retrans,
        'max_retry_attempts': max_retry
    })


# ------------------ CONTROL ROUTES --------------------------

@app.route('/control/proxy', methods=['POST'])
def control_proxy():
    body = request.get_json()
    if not body:
        return jsonify({'error': 'invalid json'}), 400

    host = body.get('host')
    port = int(body.get('port'))
    command = body.get('command')

    if not host or not port or not command:
        return jsonify({'error': 'missing host/port/command'}), 400

    resp = send_proxy_command(host, port, command)
    return jsonify({'response': resp})


@app.route('/control/proxy/update-config', methods=['POST'])
def update_proxy_config():
    body = request.get_json()
    if not body:
        return jsonify({'error': 'invalid json'}), 400

    host = body.get('host', '127.0.0.1')
    port = int(body.get('port', 9100))

    config = {
        'client_drop': body.get('client_drop', 0),
        'server_drop': body.get('server_drop', 0),
        'client_delay': body.get('client_delay', 0),
        'server_delay': body.get('server_delay', 0),
        'client_delay_time_min': body.get('client_delay_time_min', 0),
        'client_delay_time_max': body.get('client_delay_time_max', 0),
        'server_delay_time_min': body.get('server_delay_time_min', 0),
        'server_delay_time_max': body.get('server_delay_time_max', 0)
    }

    try:
        resp = send_proxy_command(host, port, config)
        return jsonify({'success': True, 'response': resp})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ------------------ CLEAR STATS ----------------------------

@app.route('/api/clear-stats', methods=['POST'])
def clear_stats():
    global client_logs, proxy_logs, server_logs, message_state, proxy_state

    client_logs.clear()
    proxy_logs.clear()
    server_logs.clear()
    message_state.clear()

    proxy_state = {
        'total_received': 0,
        'dropped': 0,
        'forwarded': 0,
        'delayed': 0
    }

    return jsonify({'success': True, 'message': 'All statistics cleared'})


# ------------------ SSE EVENT STREAM ------------------------

@app.route('/events')
def events():
    def gen():
        from queue import Queue, Empty
        q = Queue()
        subs.append(q)
        try:
            while True:
                try:
                    data = q.get(timeout=15)
                    yield f"data: {data}\n\n"
                except Empty:
                    yield ": keepalive\n\n"
        finally:
            subs.remove(q)

    return Response(gen(), mimetype='text/event-stream')


# ------------------ LOG SERVER STARTUP ----------------------

def start_log_server(host='0.0.0.0', port=9001):
    srv = TCPServer(host=host, port=port, on_message_received=on_new_message)
    srv.start()
    return srv


if __name__ == '__main__':
    log_srv = start_log_server()
    print("Starting web UI on http://0.0.0.0:5001")
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)
    log_srv.stop()
