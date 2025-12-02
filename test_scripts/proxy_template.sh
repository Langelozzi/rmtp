../build/proxy \
    --listen-ip 127.0.0.1 \
    --listen-port 3002 \
    --target-ip 127.0.0.1 \
    --target-port 3003 \
    --client-drop 50 \
    --server-drop 50 \
    --client-delay 0 \
    --server-delay 0 \
    --client-delay-time-min 0 \
    --client-delay-time-max 0 \
    --server-delay-time-min 0 \
    --server-delay-time-max 0
# --log-server-ip 0.0.0.0 \
# --log-server-port 9001 \
# --control-port 9100
