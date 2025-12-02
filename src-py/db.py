import threading
import time
import json
import os
from collections import deque

# File-based newline-delimited JSON log storage + per-source in-memory buffers.
_lock = threading.Lock()
BUFFER_MAX = 10000
SOURCES = ['client', 'proxy', 'server']
_buffers = {s: deque(maxlen=BUFFER_MAX) for s in SOURCES}

def _logfile_for(source):
    s = (source or 'unknown').lower()
    if s not in SOURCES:
        s = 'unknown'
    fname = f'companion_logs_{s}.jsonl'
    return os.path.join(os.path.dirname(__file__), fname)

def init_db():
    """Ensure per-source logfile exists and load recent entries into memory.

    Unknown sources are ignored for file loading.
    """
    for s in SOURCES:
        path = _logfile_for(s)
        open(path, 'a').close()
        # load recent lines for this source
        try:
            with open(path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                filesize = f.tell()
                blocksize = 4096
                data = b''
                lines = []
                while filesize > 0 and len(lines) < BUFFER_MAX:
                    read_size = min(blocksize, filesize)
                    f.seek(filesize - read_size)
                    chunk = f.read(read_size)
                    data = chunk + data
                    lines = data.split(b"\n")
                    filesize -= read_size
                decoded = [line.decode('utf-8') for line in lines if line.strip()]
                for line in decoded[-BUFFER_MAX:]:
                    try:
                        obj = json.loads(line)
                        _buffers[s].append(obj)
                    except Exception:
                        continue
        except Exception:
            continue

def insert_log(source, ltype, seq, ts, msg):
    """Store a log entry to the per-source JSONL file and in-memory buffer."""
    s = (source or 'unknown').lower()
    if s not in SOURCES:
        s = 'unknown'
    entry = {'source': source, 'type': ltype, 'seq': seq, 'ts': ts, 'msg': msg}
    line = json.dumps(entry, separators=(',', ':'))
    path = _logfile_for(s)
    with _lock:
        if s in _buffers:
            _buffers[s].append(entry)
        try:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            pass

def query_counts(window_seconds=60):
    """Count messages per source and type within the given time window (seconds)."""
    cutoff = time.time() - window_seconds
    counts = {}
    with _lock:
        for s, buf in _buffers.items():
            for e in list(buf):
                try:
                    ts = float(e.get('ts', 0))
                except Exception:
                    continue
                if ts < cutoff:
                    continue
                src = e.get('source') or s
                typ = e.get('type') or 'unknown'
                counts.setdefault(src, {})[typ] = counts.setdefault(src, {}).get(typ, 0) + 1
    return counts
