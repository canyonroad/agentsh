# shim/linux/Makefile
# Build the environment variable interception shim for Linux

CC ?= gcc
CFLAGS = -shared -fPIC -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -ldl -lpthread

TARGET = libenvshim.so
SRC = envshim.c

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

# Install to system directory (requires root)
install: $(TARGET)
	install -D -m 755 $(TARGET) /usr/lib/agentsh/$(TARGET)

# Install to user directory
install-user: $(TARGET)
	mkdir -p $(HOME)/.agentsh/lib
	install -m 755 $(TARGET) $(HOME)/.agentsh/lib/$(TARGET)

# Test the shim
test: $(TARGET)
	@echo "Testing getenv interception..."
	@echo "Creating test program..."
	@echo '#include <stdio.h>\n#include <stdlib.h>\nint main() { \
		const char* n = getenv("NORMAL_VAR"); \
		const char* s = getenv("SECRET_VAR"); \
		printf("NORMAL_VAR=%s\\n", n ? n : "(null)"); \
		printf("SECRET_VAR=%s\\n", s ? s : "(null)"); \
		return (n && !s) ? 0 : 1; }' > /tmp/test_getenv.c
	@$(CC) -o /tmp/test_getenv /tmp/test_getenv.c
	@echo "mode=blocklist" > /tmp/test-env-policy.conf
	@echo "blocked=SECRET_*,*_TOKEN,*_KEY" >> /tmp/test-env-policy.conf
	@echo "sensitive=SECRET,TOKEN,KEY,PASSWORD,CREDENTIAL" >> /tmp/test-env-policy.conf
	@echo "log_access=false" >> /tmp/test-env-policy.conf
	@SECRET_VAR=hidden NORMAL_VAR=visible \
		AGENTSH_ENV_POLICY_FILE=/tmp/test-env-policy.conf \
		LD_PRELOAD=./$(TARGET) \
		/tmp/test_getenv && echo "PASS: SECRET_VAR blocked correctly" || echo "FAIL"
	@rm -f /tmp/test-env-policy.conf /tmp/test_getenv /tmp/test_getenv.c

# Debug build with symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)
