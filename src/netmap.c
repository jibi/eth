#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <eth/log.h>
#include <eth/exotcp.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct nm_desc *netmap;

#if 0
struct netmap_if *
open_netmap_if(const char *ifname, int *ret_fd) {
	int fd, ret;
	struct nmreq req;
	void *mem;
	struct netmap_if *nifp;

	fd = open("/dev/netmap", O_RDWR);
	if (fd < 0) {
		return NULL;
	}

	bzero(&req, sizeof(struct nmreq));
	strcpy(req.nr_name, ifname);

	req.nr_version = NETMAP_API;
	req.nr_flags   = NR_REG_ALL_NIC;
	req.nr_ringid  = (NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL) & ~NETMAP_RING_MASK;

	ret = ioctl(fd, NIOCREGIF, &req);
	if (ret < 0) {
		return NULL;
	}

	mem = mmap(NULL, req.nr_memsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (!mem) {
		return NULL;
	}

	nifp = NETMAP_IF(mem, req.nr_offset);
	if (!nifp) {
		return NULL;
	}

	*ret_fd = fd;
	return nifp;
}
#endif

void
init_netmap(char *ifname) {
	char _ifname[IFNAMSIZ + 7];

	sprintf(_ifname, "netmap:%s", ifname);
	netmap = nm_open(_ifname, NULL, 0, 0);

	if (!netmap) {
		fatal_tragedy(1, "Cannot open netmap device");
	}
}

void
netmap_recv_loop(void (*process_packet)(char *)) {
	while (1) {
		struct pollfd fds;
		struct netmap_ring *ring;
		unsigned int i, idx, len;
		char *buf;

		fds.fd     = NETMAP_FD(netmap);
		fds.events = POLLIN;

		poll(&fds, 1, -1);

		ring = NETMAP_RXRING(netmap->nifp, 0);

		if (nm_ring_empty(ring))
			continue;

		i   = ring->cur;
		idx = ring->slot[i].buf_idx;

		buf = NETMAP_BUF(ring, idx);
		len = ring->slot[i].len;

		process_packet(buf);

		ring->head = ring->cur = nm_ring_next(ring, i);
	}
}

void
send_packet(int fd, struct netmap_if *nifp) {
	struct pollfd fds;
	struct netmap_ring *ring;
	int i, idx;
	void *buf;

	fds.fd     = fd;
	fds.events = POLLOUT;

	ring = NETMAP_TXRING(nifp, 0);

	poll(&fds, 1, -1);

	i    = ring->cur;
	idx  = ring->slot[i].buf_idx;

	buf  = NETMAP_BUF(ring, idx);
//	ring->slot[i].len = len;

	ring->head = ring->cur = nm_ring_next(ring, i);
}

