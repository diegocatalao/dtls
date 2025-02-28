CC = gcc
CFLAGS = -g -Wall $(shell pkg-config --cflags openssl)
LDFLAGS = $(shell pkg-config --libs openssl) -L../bin -llogger
INCLUDE_DIR = ../src
OUT_DIR = ../bin

SRC_FILES = $(wildcard *.c)
BIN_FILES = $(SRC_FILES:%.c=$(OUT_DIR)/%)

LIB_DIR = ../lib
LIB_DEST_DIR = ../bin

all: copy-libs $(BIN_FILES)

$(OUT_DIR)/%: %.c
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -I$(INCLUDE_DIR) -o $@ $<

copy-libs:
	@mkdir -p $(LIB_DEST_DIR)
	find $(LIB_DIR) \( -name "*.so" -o -name "*.dylib" \) -exec cp {} $(LIB_DEST_DIR)/ \;

clean:
	rm -f $(OUT_DIR)/$(notdir $(BIN_FILES))
	rm -rf $(LIB_DEST_DIR)/*.so $(LIB_DEST_DIR)/*.dylib

.PHONY: all clean copy-libs
