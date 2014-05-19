#define _GNU_SOURCE

#include <pico_stack.h>
#include <pico_config.h>
#include <pico_ipv4.h>
#include <pico_socket.h>
#include <pico_icmp4.h>

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <eth/log.h>
#include <eth/pico_dev_netmap.h>
#include <eth/http11.h>

#define BSIZE (1024 * 10)

/* TODO: parse cmd line args */

#define IF_NAME "ens4"
#define IF_ADDR "192.168.12.2"

void
init_pico_device() {
	unsigned char macaddr[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x57};

	struct pico_device *dev = NULL;
	struct pico_ip4 addr, netmask;

	pico_stack_init();

	dev = pico_netmap_create(IF_NAME, "eth_if", macaddr);

	pico_string_to_ipv4(IF_ADDR, &addr.addr);
	pico_string_to_ipv4("255.255.255.0", &netmask.addr);
	pico_ipv4_link_add(dev, addr, netmask);
}

static void
cb_tcp_eth(uint16_t ev, struct pico_socket *s) {
	char request[BSIZE];
	int len = 0;
	int flag = 0;
	char *response;

	if (ev & PICO_SOCK_EV_RD) {
		len = pico_socket_read(s, request, BSIZE);
		if (len > 0) {
			int w, t;
			flag &= ~(PICO_SOCK_EV_RD);
			request[len] = '\x00';
			response = handle_http_request(s, request, len);

			/* XXX:
			 * I dont think this is the right way (calling pico_stack_tick() here)
			 * Maybe it's better to enqueue somewhere data to be written,
			 * (and do a dequeue() and pico_socket_write() at the
			 * beginning of the main cycle)
			 *
			 */

			w = 0;
			t = strlen(response);

			do {
				w += pico_socket_write(s, response + w, t - w);
				pico_stack_tick();
			} while (w < t);

			free(response);
		} else {
			flag |= PICO_SOCK_EV_RD;
		}
	}

	if (ev & PICO_SOCK_EV_CONN) {
		struct pico_socket *sock_a = { 0 };
		struct pico_ip4 orig = { 0 };
		uint16_t port = 0;
		char peer[30] = { 0 };
		int yes = 1;

		sock_a = pico_socket_accept(s, &orig, &port);
		pico_ipv4_to_string(peer, orig.addr);

		log_debug1("Connection established with %s:%d", peer, short_be(port));
		pico_socket_setoption(sock_a, PICO_TCP_NODELAY, &yes);
	}

	if (ev & PICO_SOCK_EV_FIN) {
		log_debug1("Socket closed. Exit normally");
		exit(0);
	}

	if (ev & PICO_SOCK_EV_ERR) {
		log_debug1("Socket error received: %s. Bailing out", strerror(pico_err));
		exit(1);
	}

	if (ev & PICO_SOCK_EV_CLOSE) {
		log_debug1("Socket received close from peer.\n");
		flag |= PICO_SOCK_EV_CLOSE;
		if ((flag & PICO_SOCK_EV_RD) && (flag & PICO_SOCK_EV_CLOSE)) {
			pico_socket_shutdown(s, PICO_SHUT_WR);
			log_debug1("SOCKET> Called shutdown write, ev = %d\n", ev);
		}
	}
}

void
setup_tcp_app() {
	struct pico_socket *listen_socket;
	struct pico_ip4 address;
	uint16_t port;
	int ret, yes;

	listen_socket = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcp_eth);

	if (!listen_socket) {
		fatal_tragedy(1, "cannot open socket: %s", strerror(pico_err));
	}

	yes = 1;
	pico_socket_setoption(listen_socket, PICO_TCP_NODELAY, &yes);

	bzero(&address, sizeof(address));
	port = short_be(8080);
	ret = pico_socket_bind(listen_socket, &address, &port);

	if (ret < 0) {
		fatal_tragedy(1, "cannot bind socket to port %u: %s", short_be(port), strerror(pico_err));
	}

	ret = pico_socket_listen(listen_socket, 40);

	if (ret != 0) {
		fatal_tragedy(1, "cannot listen on port %u", short_be(port));
	}

	log_info("Starting eth web server!");
	return;
}

