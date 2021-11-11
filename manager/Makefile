COMPILER=gcc
CFLAGS   = -Wall -fsanitize=address -g -I./include -D_POSIX_C_SOURCE=200112L
LINKER 	 = clang
LFLAGS 	 = -Wall -fsanitize=address -g -lpthread

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
rm       = rm -rf


all:$(SOURCES)
	$(COMPILER) $(CFLAGS) $(SOURCES)


%.o : %.c
	$(COMPILER) $(CFLAGS) -I./include -c $< -o $@

clean:
	@$(rm) $(OBJECTS)