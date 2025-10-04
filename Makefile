CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -I./include
LDFLAGS = -lsodium

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

SERVER_TARGET = server
CLIENT_TARGET = client

SERVER_SOURCES = $(SRC_DIR)/server.c $(SRC_DIR)/crypto.c $(SRC_DIR)/protocol.c $(SRC_DIR)/wg_interface.c $(SRC_DIR)/common.c
CLIENT_SOURCES = $(SRC_DIR)/client.c $(SRC_DIR)/crypto.c $(SRC_DIR)/protocol.c $(SRC_DIR)/wg_interface.c $(SRC_DIR)/common.c

SERVER_OBJECTS = $(SERVER_SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_TARGET): $(SERVER_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(CLIENT_TARGET): $(CLIENT_OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(SERVER_TARGET) $(CLIENT_TARGET)

.PHONY: all clean
