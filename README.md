# RMTP Protocol Implementation

This project implements **RMTP (Reliable Messaging Transfer Protocol)**, a custom protocol designed for reliable message transmission, along with a proxy server for protocol bridging.

## **Overview**

RMTP is a transport layer protocol that ensures reliable delivery of messages with sequence numbering, acknowledgment handling, and round-trip time estimation. The implementation includes a client, server, and proxy for testing and protocol validation.

## **Designed Protocol: RMTP (Reliable Messaging Transfer Protocol)**

### Packet Header

The RMTP packet header consists of the following fields:

| Field | Size (Bits) | Description |
|-------|------------|-------------|
| Reserved | 7 | Reserved for future use, must be set to 0 |
| ACK Flag | 1 | Flag to indicate if packet is an ACK. 1 = ACK, 0 = data message |
| Sequence/ACK Number | 32 | The unique identifying number of that packet |
| Timestamp | 32 | Millisecond timestamp for calculating RTT (round trip time) |
| Payload Length | 16 | The length of the payload in bytes |

### Header Layout

The RMTP packet header is organized as follows:
- **Byte 0**: Reserved (7 bits) + ACK Flag (1 bit)
- **Bytes 1-4**: Sequence Number (32 bits)
- **Bytes 5-8**: Timestamp (32 bits)
- **Bytes 9-10**: Payload Length (16 bits)
- **Bytes 11+**: Payload Data

#### Visual Packet Structure

```
+------------------+---+-------------------------------+---------------------+------------------+---------+
| Reserved (7 bits)| A | Sequence/ACK Number (32 bits) | Timestamp (32 bits) | Payload Len (16) | Payload |
+------------------+---+-------------------------------+---------------------+------------------+---------+
```

## **Proxy Implementation**

The proxy server (`proxy.c`) acts as an intermediary in the RMTP communication chain, forwarding messages between client and server while simulating unreliable network conditions. The proxy:

- Receives RMTP packets from clients
- Forwards packets to the server
- Handles ACK messages from the server back to clients
- Can be configured to randomly drop or delay packets in either direction
- Sends diognostic information to the Companion Logging and Control Server

## **Installation**

### Client, Server and Proxy

#### Building

```bash
./generate-flags.sh
./generate-cmakelists.sh
./change-compiler.sh -c <compiler>
./build.sh
```

Or, if running with GCC:

```bash
./run-build-gcc.sh
```

#### Running

**Terminal A - Server:**
```bash
./build/server --listen-ip 192.168.0.1 \
--listen-port 4000 \
--log-file-path ./logs/server.log \
--log-server-ip 192.168.0.5 \
--log-server-port 6000
```

**Terminal B - Proxy:**
```bash
./build/proxy --listen-ip 192.168.0.1 \
--listen-port 4000 \
--target-ip 192.168.0.3 \
--target-port 5000 \
--client-drop 10 \
--server-drop 5 \
--client-delay 20 \
--server-delay 15 \
--client-delay-time-min 100 \
--client-delay-time-max 200 \
--server-delay-time-min 150 \
--server-delay-time-max 300 \
--log-file-path ./logs/proxy.log \
--log-server-ip 192.168.0.5 \
--log-server-port 6000
```

**Terminal C - Client:**
```bash
./build/client --target-ip 192.168.0.3 \
--target-port 5000 \
--timeout 3 \
--max-retries 5 \
--log-file-path ./logs/client.log \
--log-server-ip 192.168.0.5 \
--log-server-port 6000
```

### Companion Logging + Control Server

This UI can be used to more easily modify proxy parameters and view logs in real time via a concurrent TCP connection from the companion server to the RMTP client, server and proxy.

#### Obtaining

Navigate to the `../source/src-py` folder

#### Building

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Running

```bash
python3 server.py
```
