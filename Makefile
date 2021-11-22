CFLAGS = -Wall -fsanitize=address -g -pthread -D_POSIX_C_SOURCE=200112L
COMMON =  ./utils/buffer.o ./utils/logger.o ./utils/selector.o ./utils/stm.o ./proxy/proxypop3nio.o ./utils/netutils.o ./parsers/hello_parser.o ./parsers/command_parser.o ./parsers/command_response_parser.o ./manager/sap.o ./manager/manager_server.o ./parsers/filter_parser.o

all: ${COMMON}
	@echo "\n+-+	Making proxy	+-+\n";
	$(CC) $(CFLAGS) -o pop3filter main.c args.c $(COMMON)
	@echo "\n+-+	Making client	+-+\n";
	$(CC) $(CFLAGS) -o ./manager_client/client ./manager_client/manager_client.c args.c $(COMMON)


clean:
	rm -r -f *.o  main report.tasks $(COMMON);


.PHONY =all clean subdirs
