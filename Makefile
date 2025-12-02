CC = gcc
CFLAGS = -Wall -Wextra -O2

BUILD_DIR = build

COMMON_SRC = src/network_utils.c src/socket.c src/time_utils.c src/rmtp.c src/log.c src/rmtp_log.c

CLIENT_SRC = src/client.c $(COMMON_SRC)
SERVER_SRC = src/server.c $(COMMON_SRC)
PROXY_SRC  = src/proxy.c $(COMMON_SRC) src/poll_multiplex.c

all: $(BUILD_DIR)/client $(BUILD_DIR)/server $(BUILD_DIR)/proxy

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/client: $(CLIENT_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC)

$(BUILD_DIR)/server: $(SERVER_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRC)

$(BUILD_DIR)/proxy: $(PROXY_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(PROXY_SRC)

clean:
	rm -rf $(BUILD_DIR)
