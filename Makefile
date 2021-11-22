CFLAGS = -g --std=c11 -pedantic -fsanitize=address  -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200809L -pthread
OBJECTS =  ./utils/buffer.o ./utils/logger.o ./utils/selector.o ./utils/stm.o ./proxy/proxypop3nio.o ./utils/netutils.o ./parsers/hello_parser.o ./parsers/command_parser.o ./parsers/command_response_parser.o ./manager/sap.o ./manager/manager_server.o ./parsers/filter_parser.o

all: ${OBJECTS}
	@echo "\n+-+	Making proxy	+-+\n";
	$(CC) $(CFLAGS) -o pop3filter main.c args.c $(OBJECTS)
	@echo "\n+-+	Making client	+-+\n";
	$(CC) $(CFLAGS) -o ./manager_client/client ./manager_client/manager_client.c args.c $(OBJECTS)


clean:
	rm -r -f *.o  main report.tasks $(COMMON);


.PHONY =all clean subdirs
