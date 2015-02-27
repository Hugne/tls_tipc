CFLAGS= -m64 -std=gnu99 -pedantic -Wshadow -Wpointer-arith -Wcast-qual \
	-Wstrict-prototypes -Wmissing-prototypes
LDFLAGS=-lgnutls
all: tls_server tls_client cert

clean:
	rm -f ./*.o tls_server tls_client cert.pem key.pem

cert:
	certtool --generate-privkey --outfile key.pem
	certtool --generate-self-signed --load-privkey key.pem --template template.txt --outfile cert.pem
tls_server: tls_server.o ${LOBJS}
	gcc $(CFLAGS) $(LDFLAGS) tls_server.c -lm -o tls_server

tls_client: tls_client.o
	gcc $(CFLAGS) $(LDFLAGS) tls_client.c -o tls_client


