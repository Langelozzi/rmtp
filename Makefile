CC = gcc
CFLAGS = -Wall -Wextra -O2

COMMON_SRC = src/network_utils.c src/socket.c src/time_utils.c src/rmtp.c src/log.c src/rmtp_log.c

CLIENT_SRC = src/client.c $(COMMON_SRC)
SERVER_SRC = src/server.c $(COMMON_SRC)
PROXY_SRC  = src/proxy.c $(COMMON_SRC) src/poll_multiplex.c

all: client server proxy

client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o ./build/client $(CLIENT_SRC)

server: $(SERVER_SRC)
	$(CC) $(CFLAGS) -o ./build/server $(SERVER_SRC)

proxy: $(PROXY_SRC)
	$(CC) $(CFLAGS) -o ./build/proxy $(PROXY_SRC)

clean:
	rm -f ./build/client ./build/server ./build/proxy
