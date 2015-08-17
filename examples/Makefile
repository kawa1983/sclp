CC = @gcc

TARGETS = echo_client echo_server client server

all: $(TARGETS)

.c.o:
	$(CC) -c $<

echo_client: echo_client.o lib.o
	$(CC) -o $@ $^

echo_server: echo_server.o lib.o
	$(CC) -o $@ $^

client: client.o lib.o
	$(CC) -o $@ $^

server: server.o lib.o
	$(CC) -o $@ $^

clean:
	@rm -f $(TARGETS) *.o