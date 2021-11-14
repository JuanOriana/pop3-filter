COMPILER=gcc
CFLAGS   = -Wall -fsanitize=address -g -I./include -D_POSIX_C_SOURCE=200112L
LINKER 	 = clang
LFLAGS 	 = -Wall -fsanitize=address -g -lpthread

TARGET := manager_client
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
rm       = rm -rf

all: compile link

compile:$(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES)

link:$(SOURCES)
	$(LINKER) $(LFLAGS) $(OBJECTS) ../args.o ../utils/*.o ./../manager/*.o -o $(TARGET).out


%.o : %.c
	$(CC) $(CFLAGS) -I./include -c $< -o $@

clean:
	@$(rm) $(OBJECTS)
	@$(rm) $(TARGET).out