CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -Iinclude
LDFLAGS =
LIBS = -lpcap

SRC = src/main.c src/cli.c src/capture.c src/rules.c src/daemon.c src/alerts.c src/config.c
OBJ = $(SRC:src/%.c=build/%.o)
TARGET = build/cids
TEST_BINS = build/tests_rules build/tests_cli build/tests_config

.PHONY: all clean rebuild test test-rules test-cli test-config

all: $(TARGET)

$(TARGET): $(OBJ) | build
	$(CC) $(OBJ) -o $@ $(LDFLAGS) $(LIBS)

build/%.o: src/%.c include/cli.h include/capture.h include/packet.h include/rules.h include/daemon.h include/alerts.h include/config.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_BINS)

rebuild: clean all

test-rules: build/tests_rules
	./build/tests_rules

test: test-rules test-cli test-config

build/tests_rules: tests/rules_test.c src/rules.c include/packet.h include/rules.h | build
	$(CC) $(CFLAGS) tests/rules_test.c src/rules.c -o $@

test-cli: build/tests_cli
	./build/tests_cli

build/tests_cli: tests/cli_test.c src/cli.c include/cli.h include/capture.h include/rules.h include/config.h | build
	$(CC) $(CFLAGS) tests/cli_test.c src/cli.c -o $@ $(LDFLAGS) $(LIBS)

test-config: build/tests_config
	./build/tests_config

build/tests_config: tests/config_test.c src/config.c include/config.h include/cli.h include/capture.h include/rules.h | build
	$(CC) $(CFLAGS) tests/config_test.c src/config.c -o $@
