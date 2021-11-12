COMPILER=gcc
CFLAGS = -Wall -fsanitize=address -g -lpthread -pthread -D_POSIX_C_SOURCE=200112L
SUBDIRS = utils parsers proxy manager
# Ver si corresponde compilar con -o3 para optimizar

all: subdirs main manager_client

subdirs:
	$(CC) $(CFLAGS) -I./include -c args.c
	@for subdir in $(SUBDIRS); do \
    	echo "Making all in $$subdir"; \
        cd $$subdir && $(MAKE) all && cd ..; \
    done


clean:	
	@for subdir in $(SUBDIRS); do \
		echo "Cleaning all in $$subdir"; \
		cd $$subdir && $(MAKE) clean && cd ..; \
	done
	rm -r -f *.o  main report.tasks

COMMON =  ./utils/buffer.c ./utils/logger.c ./utils/selector.c ./utils/stm.c ./proxy/proxypop3nio.c ./utils/netutils.c ./parsers/hello_parser.c ./parsers/command_parser.c ./parsers/command_response_parser.c ./manager/sap.c ./manager/manager_server.c

main:
	echo "Making main" \
	$(COMPILER) $(CFLAGS) -o main main.c args.c $(COMMON)

manager_client:
	echo "Making client"
	$(COMPILER) $(CFLAGS) -o ./manager_client/client ./manager_client/manager_client.c args.c $(COMMON)

.PHONY=all clean