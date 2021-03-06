/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <linux/tipc.h>
/* A very basic Datagram TLS client, over TIPC with X.509 authentication. */

#define MAX_BUF 1024
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define MSG "GET / HTTP/1.0\r\n\r\n"


static int rdm_connect(struct sockaddr_tipc *sa)
{
	int err, sd, optval;

	/* connects to server
	*/
	if (sa->family != AF_TIPC) {
		printf("FAIL\n");
		return -1;
	}
	sd = socket(AF_TIPC, SOCK_RDM, 0);
	if (!sd) {
		perror("connect");
		exit(1);
	}

	if(connect(sd, (struct sockaddr *) sa, sizeof(*sa))) {
		perror("connect");
		exit(1);
	}
	printf("TIPC dgram connected: socket %u\n", sd);
	return sd;
}

static int verify_certificate_callback(gnutls_session_t session)
{
	return 0;
}

int main(void)
{
	int ret, sd, ii;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	const char *err;
	gnutls_certificate_credentials_t xcred;

	if (gnutls_check_version("3.1.4") == NULL) {
		fprintf(stderr, "GnuTLS 3.1.4 or later is required for this example\n");
		exit(1);
	}
	/* for backwards compatibility with gnutls < 3.3.0 */
	gnutls_global_init();
	gnutls_global_set_log_level(10);
	/* X509 stuff */
	gnutls_certificate_allocate_credentials(&xcred);
	/* sets the trusted cas file */
	gnutls_certificate_set_x509_trust_file(xcred, CAFILE,
			GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_verify_function(xcred,
			verify_certificate_callback);
	/* Initialize TLS session */
	gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);

	/* Use default priorities */
	ret = gnutls_priority_set_direct(session, 
			"NORMAL", &err);
	if (ret < 0) {
		if (ret == GNUTLS_E_INVALID_REQUEST) {
			fprintf(stderr, "Syntax error at: %s\n", err);
		}
		exit(1);
	}

	/* put the x509 credentials to the current session */
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_server_name_set(session, GNUTLS_NAME_DNS, "my_host_name",
			strlen("my_host_name"));

	/*The handshake will work fine towards a NAME or NAMESEQ address
	 * unless there are any overlapping publications (multiple servers).
	 * In that case, you need to do a subscription to the topology server
	 * fot the name/type/{instance | [lower,upper]} and get the tipc_portid.
	 * Then use that portid in the connect call*/
	struct sockaddr_tipc sa = {
		.family = AF_TIPC,
		.addrtype = TIPC_ADDR_NAME,
		.addr.name.name.type = 7000,
		.addr.name.name.instance = 400
	};
	/* connect to the peer */
	sd = rdm_connect(&sa);

	gnutls_transport_set_int(session, sd);

	/* set the connection MTU */
	gnutls_dtls_set_mtu(session, TIPC_MAX_USER_MSG_SIZE);
	gnutls_handshake_set_timeout(session,
			GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	/* Perform the TLS handshake */
	do {
		ret = gnutls_handshake(session);
	}
	while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
	/* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */
	if (ret < 0) {
		fprintf(stderr, "*** Handshake failed\n");
		gnutls_perror(ret);
		goto end;
	} else {
		char *desc;

		desc = gnutls_session_get_desc(session);
		printf("- Session info: %s\n", desc);
		gnutls_free(desc);
	}

	gnutls_record_send(session, MSG, strlen(MSG));

	ret = gnutls_record_recv(session, buffer, MAX_BUF);
	if (ret == 0) {
		printf("- Peer has closed the TLS connection\n");
		goto end;
	} else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
		fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
	} else if (ret < 0) {
		fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
		goto end;
	}

	if (ret > 0) {
		printf("- Received %d bytes: ", ret);
		for (ii = 0; ii < ret; ii++) {
			fputc(buffer[ii], stdout);
		}
		fputs("\n", stdout);
	}
	/* It is suggested not to use GNUTLS_SHUT_RDWR in DTLS
	 * connections because the peer's closure message might
	 * be lost */
	gnutls_bye(session, GNUTLS_SHUT_WR);
end:
	close(sd);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
	return 0;
}
