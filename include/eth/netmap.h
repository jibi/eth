/*
 * Copyright (C) 2014 jibi <jibi@paranoici.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _ETH_NETMAP_H
#define _ETH_NETMAP_H

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

typedef struct netmap_tx_ring_desc_s {
	char *buf;
	int  i;
	uint16_t  *len;
} netmap_tx_ring_desc_t;

extern struct nm_desc *netmap;

void init_netmap(char *ifname);
void netmap_recv_loop(void (*process_packet)(char *, size_t len));
netmap_tx_ring_desc_t *netmap_get_tx_ring_buffer();
netmap_tx_ring_desc_t *netmap_get_tx_ring_buffer_no_poll();

#endif

