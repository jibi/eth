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

#ifndef _ETH_HTTP11_H
#define _ETH_HTTP11_H

#include <sys/types.h>

#include <eth.h>
#include <eth/exotcp/tcp.h>

#define BUFFER_LEN 1024

struct eth_parser_s;

typedef void (*element_cb)(struct eth_parser_s *hp, const char *at, size_t length);
typedef void (*field_cb)(struct eth_parser_s *hp, const char *field, size_t flen, const char *value, size_t vlen);

typedef struct eth_parser_s {
	int cs;
	size_t body_start;
	int content_len;
	size_t nread;
	size_t mark;
	size_t field_start;
	size_t field_len;
	size_t query_start;

	field_cb   field_cb;
	element_cb method_cb;
	element_cb uri_cb;
	element_cb fragment_cb;
	element_cb path_cb;
	element_cb query_cb;
	element_cb version_cb;
	element_cb header_done_cb;

	char *method;
	char *uri;
	char *path;
	char *query;
	char *version;

	char buf[BUFFER_LEN];

} eth_parser_t;

typedef struct http_response_s {
	eth_parser_t *parser;

	char   *header_buf;
	size_t header_pos;
	size_t header_len;

	int    file_fd;
	size_t file_len;
	size_t file_pos;

	bool   finished;
} http_response_t;

int eth_parser_init(eth_parser_t *parser);
int eth_parser_finish(eth_parser_t *parser);
size_t eth_parser_execute(eth_parser_t *parser, const char *data, size_t len, size_t off);
int eth_parser_has_error(eth_parser_t *parser);
int eth_parser_is_finished(eth_parser_t *parser);

#define eth_parser_nread(parser) (parser)->nread

eth_parser_t *new_eth_parser();
void delete_eth_parser_t(eth_parser_t *p);
void handle_http_request(tcp_conn_t *conn, char *request, size_t len);

int http_res_has_header_to_send(http_response_t *res);
int http_res_has_file_to_send(http_response_t *res);

#endif

