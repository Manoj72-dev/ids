CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -Iinclude
LDFLAGS =
LIBS = -lpcap

SRC = src/main.c src/cli.c src/capture.c src/rules.c src/daemon.c src/alerts.c src/config.c
OBJ = $(SRC:src/%.c=build/%.o)
TARGET = build/cids

.PHONY: all clean rebuild test-rules

all: $(TARGET)

$(TARGET): $(OBJ) | build
	$(CC) $(OBJ) -o $@ $(LDFLAGS) $(LIBS)

build/%.o: src/%.c include/cli.h include/capture.h include/packet.h include/rules.h include/daemon.h include/alerts.h include/config.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all

test-rules: build/tests_rules
	./build/tests_rules

build/tests_rules: tests/rules_test.c src/rules.c include/packet.h include/rules.h | build
	$(CC) $(CFLAGS) tests/rules_test.c src/rules.c -o $@
