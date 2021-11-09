CFLAGS = -Wall -fsanitize=address -g -lpthread -pthread -D_POSIX_C_SOURCE=200112L
# Ver si corresponde compilar con -o3 para optimizar
all: main

parsers:
	cd parsers; make all

utils:
	cd utils; make all

proxy:
	cd proxy; make all


clean:	
	cd utils; make clean
	- rm -f *.o  main report.tasks 

COMMON =  ./utils/buffer.o ./utils/logger.o ./utils/selector.o ./utils/stm.o ./proxy/proxypop3nio.o ./utils/netutils.o ./parsers/hello_parser.o ./parsers/command_parser.o ./parsers/command_response_parser.o

utils/buffer.o:utils/include/buffer.h

main:     $(COMMON) 
	$(CC) $(CFLAGS) -o main main.c args.c $(COMMON)



.PHONY=all clean parsers utils proxy
