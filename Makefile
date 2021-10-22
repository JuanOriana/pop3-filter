.PHONY=clean all
COMPILER=gcc
CFLAGS = -Wall -fsanitize=address -g

all:clean proxy
clean:	
	- rm -f *.o  proxy report.tasks 

COMMON =  -I/lib/buffer.c -I/lib/logger.c

proxy:      
	$(COMPILER) $(CFLAGS) -o proxy proxy.c $(COMMON)
