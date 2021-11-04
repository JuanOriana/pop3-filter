COMPILER=gcc
CFLAGS = -Wall -fsanitize=address -g -lpthread -pthread -D_POSIX_C_SOURCE=200112L
# Ver si corresponde compilar con -o3 para optimizar
all: clean proxy parsers utils main

parsers:
	cd parsers; make all

utils:
	cd utils; make all

utils:
	cd utils; make all


clean:	
	cd utils; make clean
	- rm -f *.o  main report.tasks 

COMMON =  ./utils/buffer.c ./utils/logger.c ./utils/selector.c ./utils/stm.c ./proxy/proxypop3nio.c ./utils/netutils.c ./parsers/hello_parser.c

main:      
	$(COMPILER) $(CFLAGS) -o main main.c args.c $(COMMON)



.PHONY=all clean