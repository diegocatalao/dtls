PROJECT = liblogger.dylib

CC = gcc
CFLAGS = -g -Wall -fPIC $(shell pkg-config --cflags openssl) -pthread
LDFLAGS = $(shell pkg-config --libs openssl)
TFLAG = $(if $(TARGET),-target $(TARGET),)

SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
LIB_DIR = lib

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(SRC_FILES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

all: $(OBJ_DIR) $(LIB_DIR) $(LIB_DIR)/$(PROJECT)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(LIB_DIR)/$(PROJECT): $(OBJ_FILES)
	$(CC) $(TFLAG) -shared $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(TFLAG) $(CFLAGS) -I$(INCLUDE_DIR) -o $@ -c $<

clean:
	rm -f $(OBJ_DIR)/*.o $(LIB_DIR)/*.dylib $(LIB_DIR)/$(PROJECT)
	rmdir $(OBJ_DIR) $(LIB_DIR) 2>/dev/null || true

.PHONY: all clean
