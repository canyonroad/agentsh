CC?=gcc
CFLAGS?=-fPIC -shared -Os -Wall
TARGET?=libagentsh-ptracer.so

all: $(TARGET)

$(TARGET): ptracer.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
