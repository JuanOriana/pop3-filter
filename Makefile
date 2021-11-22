CFLAGS = -Wall -fsanitize=address -g -lpthread -pthread -D_POSIX_C_SOURCE=200112L
SUBDIRS = utils parsers proxy manager
# Ver si corresponde compilar con -o3 para optimizar
COMMON =  ./utils/buffer.o ./utils/logger.o ./utils/selector.o ./utils/stm.o ./proxy/proxypop3nio.o ./utils/netutils.o ./parsers/hello_parser.o ./parsers/command_parser.o ./parsers/command_response_parser.o ./manager/sap.o ./manager/manager_server.o ./parsers/filter_parser.o

all: subdirs ${COMMON}
	@echo "Making proxy";
	$(CC) $(CFLAGS) -o pop3filter main.c args.c $(COMMON)
	@echo "Making client";
	$(CC) $(CFLAGS) -o ./manager_client/client ./manager_client/manager_client.c args.c $(COMMON)

subdirs: ${COMMON}
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
	rm -r -f *.o  main report.tasks;


.PHONY =all clean subdirs
