COMPILER=gcc
CFLAGS = -Wall -fsanitize=address -g -lpthread -pthread

all: clean utils proxy

utils:
	cd utils; make all

clean:	
	cd utils; make clean
	- rm -f *.o  proxy report.tasks 

COMMON =  ./utils/buffer.c ./utils/logger.c ./utils/selector.c ./utils/stm.c ./utils/proxypop3nio.c

proxy:      
	$(COMPILER) $(CFLAGS) -o proxy proxy.c args.c $(COMMON)



.PHONY=all clean