/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tipc.h>
#include <sys/select.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE "crl.pem"

/* This is a sample DTLS echo server, using X.509 authentication.
 * Note that error checking is minimal to simplify the example.
 */

#define MAX_BUFFER 1024
#define PORT 5557

typedef struct {
	gnutls_session_t session;
	int fd;
	struct sockaddr *cli_addr;
	socklen_t cli_addr_size;
} priv_data_st;

static int pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms);
static ssize_t push_func(gnutls_transport_ptr_t p, const void *data,
		size_t size);
static ssize_t pull_func(gnutls_transport_ptr_t p, void *data,
		size_t size);
static int wait_for_connection(int fd);
static int generate_dh_params(void);

/* Use global credentials and parameters to simplify
 * the example. */
static gnutls_certificate_credentials_t x509_cred;
static gnutls_priority_t priority_cache;
static gnutls_dh_params_t dh_params;

static void print_sockaddr_tipc(const struct sockaddr_tipc *sa);
static void diep(char *msg)
{
	perror(msg);
	exit(-1);
}

int main(void)
{
	int listen_sd;
	int sock, ret;
	struct sockaddr_tipc sa_serv = {
		.family = AF_TIPC,
		.addrtype = TIPC_ADDR_NAMESEQ,
		.addr.nameseq.type = 7000,
		.addr.nameseq.lower = 0,
		.addr.nameseq.upper = ~0,
		.scope = TIPC_ZONE_SCOPE
	};
	struct sockaddr_tipc cli_addr;
	socklen_t cli_addr_size;
	gnutls_session_t session;
	char buffer[TIPC_MAX_USER_MSG_SIZE];
	priv_data_st priv;
	gnutls_datum_t cookie_key;
	gnutls_dtls_prestate_st prestate;
	unsigned char sequence[8];

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
					       GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,
					     GNUTLS_X509_FMT_PEM);
	if (gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE,
						   GNUTLS_X509_FMT_PEM))
		diep("No certificate or key were found\n");

	generate_dh_params();
	gnutls_certificate_set_dh_params(x509_cred, dh_params);
	gnutls_priority_init(&priority_cache,
			"PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE",
			NULL);
	gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);

	listen_sd = socket(AF_TIPC, SOCK_RDM, 0);
	bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
	printf("TIPC server ready. Listening on {%u, %u, %u}.\n\n",
	       sa_serv.addr.nameseq.type, sa_serv.addr.nameseq.lower,
	       sa_serv.addr.nameseq.upper);

	for (;;) {
		printf("Waiting for connection...\n");
		sock = wait_for_connection(listen_sd);
		if (sock < 0)
			continue;

		cli_addr_size = sizeof(cli_addr);
		ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK,
			       (struct sockaddr *) &cli_addr, &cli_addr_size);
		if (ret > 0) {
			memset(&prestate, 0, sizeof(prestate));
			ret = gnutls_dtls_cookie_verify(&cookie_key,
							&cli_addr,
							sizeof(cli_addr),
							buffer, ret,
							&prestate);
			if (ret < 0) {  /* cookie not valid */
				priv_data_st s;
				memset(&s, 0, sizeof(s));
				s.fd = sock;
				s.cli_addr = (void *) &cli_addr;
				s.cli_addr_size = sizeof(cli_addr);
				printf("Sending hello verify request to: ");
				print_sockaddr_tipc(&cli_addr);
				gnutls_dtls_cookie_send(&cookie_key, &cli_addr,
							sizeof(cli_addr),
							&prestate,
							(gnutls_transport_ptr_t)
							& s, push_func);
				/* discard peeked data */
				recvfrom(sock, buffer, sizeof(buffer), 0,
						(struct sockaddr *) &cli_addr,
						&cli_addr_size);
				usleep(100);
				continue;
			}
			printf("Accepted connection from:");
			print_sockaddr_tipc(&cli_addr);
		} else
			continue;

		gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
		gnutls_priority_set(session, priority_cache);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				x509_cred);

		gnutls_dtls_prestate_set(session, &prestate);
		gnutls_dtls_set_mtu(session, TIPC_MAX_USER_MSG_SIZE);

		priv.session = session;
		priv.fd = sock;
		priv.cli_addr = (struct sockaddr *) &cli_addr;
		priv.cli_addr_size = sizeof(cli_addr);

		gnutls_transport_set_ptr(session, &priv);
		gnutls_transport_set_push_function(session, push_func);
		gnutls_transport_set_pull_function(session, pull_func);
		gnutls_transport_set_pull_timeout_function(session,
				pull_timeout_func);

		do {
			ret = gnutls_handshake(session);
		}
		while ((ret == GNUTLS_E_INTERRUPTED) ||
		       (ret == GNUTLS_E_AGAIN));
		/* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET.
		 * In that case the MTU should be adjusted.
		 */

		if (ret < 0) {
			fprintf(stderr, "Error in handshake(): %s\n",
				gnutls_strerror(ret));
			gnutls_deinit(session);
			continue;
		}

		printf("- Handshake was completed\n");

		for (;;) {
			do {
				ret = gnutls_record_recv_seq(session, buffer,
							     MAX_BUFFER,
							     sequence);
			}
			while (ret == GNUTLS_E_AGAIN
					|| ret == GNUTLS_E_INTERRUPTED);

			if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
				fprintf(stderr, "*** Warning: %s\n",
						gnutls_strerror(ret));
				continue;
			} else if (ret < 0) {
				fprintf(stderr, "Error in recv(): %s\n",
						gnutls_strerror(ret));
				break;
			}

			if (ret == 0) {
				printf("EOF\n\n");
				break;
			}
			buffer[ret] = 0;
			printf("received[%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x]: %s\n",
				 sequence[0], sequence[1], sequence[2],
				 sequence[3], sequence[4], sequence[5],
				 sequence[6], sequence[7], buffer);

			/* reply back */
			ret = gnutls_record_send(session, buffer, ret);
			if (ret < 0) {
				fprintf(stderr, "Error in send(): %s\n",
						gnutls_strerror(ret));
				break;
			}
		}
		gnutls_bye(session, GNUTLS_SHUT_WR);
		gnutls_deinit(session);
	}
	close(listen_sd);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_priority_deinit(priority_cache);
	gnutls_global_deinit();

	return 0;

}

static int wait_for_connection(int fd)
{
	fd_set rd, wr;
	int n;

	FD_ZERO(&rd);
	FD_ZERO(&wr);

	FD_SET(fd, &rd);

	/* waiting part */
	n = select(fd + 1, &rd, &wr, NULL, NULL);
	if (n == -1 && errno == EINTR)
		return -1;
	if (n < 0) {
		perror("select()");
		exit(1);
	}

	return fd;
}

/* Wait for data to be received within a timeout period in milliseconds
*/
static int pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	fd_set rfds;
	struct timeval tv;
	priv_data_st *priv = ptr;
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_size;
	int ret;
	char c;

	FD_ZERO(&rfds);
	FD_SET(priv->fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;

	while (tv.tv_usec >= 1000000) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}

	ret = select(priv->fd + 1, &rfds, NULL, NULL, &tv);

	if (ret <= 0)
		return ret;

	/* only report ok if the next message is from the peer we expect
	 * from 
	 */
	cli_addr_size = sizeof(cli_addr);
	ret = recvfrom(priv->fd, &c, 1, MSG_PEEK, (struct sockaddr *) &cli_addr,
		       &cli_addr_size);
	if (ret > 0) {
		if (cli_addr_size == priv->cli_addr_size &&
		    memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
			return 1;
	}

	return 0;
}

static ssize_t push_func(gnutls_transport_ptr_t p, const void *data, size_t size)
{
	priv_data_st *priv = p;

	return sendto(priv->fd, data, size, 0, priv->cli_addr,
			priv->cli_addr_size);
}

static ssize_t pull_func(gnutls_transport_ptr_t p, void *data, size_t size)
{
	priv_data_st *priv = p;
	struct sockaddr_tipc cli_addr;
	socklen_t cli_addr_size;
	char buffer[64];
	int ret;

	cli_addr_size = sizeof(cli_addr);
	ret = recvfrom(priv->fd, data, size, 0, (struct sockaddr *) &cli_addr,
		       &cli_addr_size);
	if (ret == -1)
		return ret;

	if (cli_addr_size == priv->cli_addr_size &&
	    memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
		return ret;

	printf("Denied connection from: ");
	print_sockaddr_tipc(&cli_addr);
	gnutls_transport_set_errno(priv->session, EAGAIN);
	return -1;
}

static void print_sockaddr_tipc(const struct sockaddr_tipc *sa)
{
	switch (sa->addrtype) {
	case TIPC_ADDR_NAME:
		printf("name: {%u, %u}\n",
		       sa->addr.name.name.type,
		       sa->addr.name.name.instance);
		break;
	case TIPC_ADDR_NAMESEQ: /*TIPC_ADDR_MCAST*/
		printf("nameseq: {%u, %u, %u}\n",
		       sa->addr.nameseq.type,
		       sa->addr.nameseq.lower,
		       sa->addr.nameseq.upper);
		break;
	case TIPC_ADDR_ID:
		printf("portid: <%u.%u.%u:%u>\n",
		       tipc_zone(sa->addr.id.node),
		       tipc_cluster(sa->addr.id.node),
		       tipc_node(sa->addr.id.node),
		       sa->addr.id.ref);
	default:
		printf("Address error\n");
	}

}

static int generate_dh_params(void)
{
	int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
			GNUTLS_SEC_PARAM_LEGACY);

	/* Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters often.
	 */
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params, bits);

	return 0;
}
