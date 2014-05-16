#define NETMAP_WITH_LIBS


#include <stdio.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <net/netmap_user.h>

#include <pico_device.h>
#include <pico_stack.h>

#include <eth/log.h>

struct pico_device_netmap {
	struct pico_device dev;
	struct nm_desc *conn;
};

static int
pico_netmap_send(struct pico_device *dev, void *buf, int len) {
	struct pico_device_netmap *netmap;
	int ret;

	netmap = (struct pico_device_netmap *) dev;
	ret    = nm_inject(netmap->conn, buf, len);

	ioctl(NETMAP_FD(netmap->conn), NIOCTXSYNC);

	return ret;
}

static int
pico_netmap_poll(struct pico_device *dev, int loop_score) {
	struct pico_device_netmap *netmap;
	struct pollfd fds;
	void *buf;
	struct nm_pkthdr hdr;

	netmap     = (struct pico_device_netmap *) dev;
	fds.fd     = NETMAP_FD(netmap->conn);
	fds.events = POLLIN;

	poll(&fds, 1, 0);

	while ((buf = nm_nextpkt(netmap->conn, &hdr))) {
		pico_stack_recv_zerocopy_ext_buffer((struct pico_device *) dev, (uint8_t *) buf, hdr.len);
		loop_score--;
	}

	return loop_score;
}

void
pico_netmap_destroy(struct pico_device *dev) {
	struct pico_device_netmap *netmap = (struct pico_device_netmap *) dev;

	nm_close(netmap->conn);
}

struct pico_device *
pico_netmap_create(char *interface, char *name, uint8_t *mac) {
	struct pico_device_netmap *netmap;
	char   ifname[IFNAMSIZ + 7];

	netmap = PICO_ZALLOC(sizeof(struct pico_device_netmap));
	if (!netmap) {
		return NULL;
	}

	if (pico_device_init((struct pico_device *)netmap, name, mac)) {
		pico_netmap_destroy((struct pico_device *)netmap);
		return NULL;
	}

	sprintf(ifname, "netmap:%s", interface);

	netmap->dev.overhead = 0;
	netmap->conn         = nm_open(ifname, NULL, 0, 0);

	if (! netmap->conn) {
		pico_netmap_destroy((struct pico_device *)netmap);
		return NULL;
	}

	netmap->dev.send    = pico_netmap_send;
	netmap->dev.poll    = pico_netmap_poll;
	netmap->dev.destroy = pico_netmap_destroy;

	return (struct pico_device *)netmap;
}

