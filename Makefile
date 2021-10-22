.PHONY=clean all
COMPILER=gcc
CFLAGS = -Wall -fsanitize=address -g

all:clean proxy
clean:	
	- rm -f *.o  proxy report.tasks 

COMMON =  -I/utils/buffer.c -I/utils/logger.c -I/utils/selector.c

proxy:      
	$(COMPILER) $(CFLAGS) -o proxy proxy.c $(COMMON)