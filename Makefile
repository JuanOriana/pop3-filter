COMPILER=gcc
CFLAGS = -Wall -fsanitize=address -g -lpthread -pthread

all: clean utils main

utils:
	cd utils; make all

clean:	
	cd utils; make clean
	- rm -f *.o  main report.tasks 

COMMON =  ./utils/buffer.c ./utils/logger.c ./utils/selector.c ./utils/stm.c ./utils/proxypop3nio.c

main:      
	$(COMPILER) $(CFLAGS) -o main main.c args.c $(COMMON)



.PHONY=all clean