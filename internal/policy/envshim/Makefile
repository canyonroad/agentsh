CC?=gcc
CFLAGS?=-fPIC -shared -O2 -Wall
TARGET?=libenvshim.so

all: $(TARGET)

$(TARGET): envshim.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f $(TARGET)

.PHONY: all clean
