import socket
import threading

class TCPServer:
    def __init__(self, host, port, on_message_received):
        self.host = host
        self.port = port
        self.on_message_received = on_message_received
        self.running = False

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen()
        print(f"Server listening on {self.host}:{self.port}")

        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            conn, addr = self.sock.accept()
            print(f"Client connected: {addr}")
            threading.Thread(target=self._client_loop, args=(conn,), daemon=True).start()

    def _client_loop(self, conn):
        with conn:
            buf = b''
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break  # client disconnected
                buf += data
                # extract newline-delimited messages
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    if not line:
                        continue
                    try:
                        self.on_message_received(line, conn)
                    except Exception:
                        # handler errors shouldn't bring down the connection
                        pass

    def stop(self):
        self.running = False
        self.sock.close()
        print("Server stopped.")