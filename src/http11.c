/*
 * Copyright (C) 2005 Zed A. Shaw
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <eth.h>
#include <eth/http11.h>
#include <eth/exotcp/tcp.h>

static inline
void
field(eth_parser_t* hp, const char *field, size_t flen, const char *value, size_t vlen)
{
//	printf("field:\n\tname:\t%.*s\n\tvalue:\t%.*s\n",  (int)flen, field,  (int)vlen, value);
}

static inline
void
method(eth_parser_t* hp, const char *at, size_t length)
{
	asprintf(&hp->method, "%.*s", (int) length, at);
}

static inline
void
uri(eth_parser_t* hp, const char *at, size_t length)
{
	asprintf(&hp->uri, "%.*s", (int) length, at);
}

static inline
void
fragment(eth_parser_t* hp, const char *at, size_t length)
{
	//printf("frag:\t\t%.*s\n", (int) length, at);
}

static inline
void
path(eth_parser_t* hp, const char *at, size_t length)
{
	asprintf(&hp->path, "%.*s", (int) length, at);
}

static inline
void
query(eth_parser_t* hp, const char *at, size_t length)
{
	asprintf(&hp->query, "%.*s", (int) length, at);

}

static inline
void
version(eth_parser_t* hp, const char *at, size_t length)
{
	asprintf(&hp->version, "%.*s", (int) length, at);

}

static inline
void
header_done(eth_parser_t* hp, const char *at, size_t length)
{
}

eth_parser_t *
new_eth_parser(void)
{
	eth_parser_t *parser = malloc(sizeof(eth_parser_t));

	parser->field_cb       = field;
	parser->method_cb      = method;
	parser->uri_cb         = uri;
	parser->fragment_cb    = fragment;
	parser->path_cb        = path;
	parser->query_cb       = query;
	parser->version_cb     = version;
	parser->header_done_cb = header_done;

	parser->method         = NULL;
	parser->uri            = NULL;
	parser->path           = NULL;
	parser->query          = NULL;
	parser->version        = NULL;

	parser->parsed         = false;

	eth_parser_init(parser);

	return parser;
}

void
delete_eth_parser(eth_parser_t *p)
{
	if (p->method) {
		free(p->method);
	}

	if (p->uri) {
		free(p->uri);
	}

	if (p->path) {
		free(p->path);
	}

	if (p->query) {
		free(p->query);
	}

	if (p->version) {
		free(p->version);
	}

	free(p);
}

/*
 * TODO: add "Connection: close" if client does not request keep-alive
 */
void
test_response(http_response_t *response)
{
	char *body;

	asprintf(&body,
		"Oh, Hi.\n"
		"I'm an autistic web server.\n\n"
		"method: %s\n"
		"uri:    %s\n"
		"path:   %s\n"
		"query:  %s\n",
		response->parser->method,
		response->parser->uri,
		response->parser->path,
		response->parser->query);


	asprintf(&response->header_buf,
		"HTTP/1.1 200 OK\r\n"
		"Host: sbiriguda\r\n"
		"Content-Length: %d\r\n"
		"\r\n%s", (int) strlen(body), body);

	response->header_len = strlen(response->header_buf);
	response->header_pos = 0;

	response->file_len   = 0;
	response->file_pos   = 0;

	free(body);
}

void
build_404(http_response_t *response)
{
	char *body = "<h1>404 Not Found :(<h1>";

	asprintf(&response->header_buf,
		"HTTP/1.1 404 Not Found\r\n"
		"Host: internet\r\n"
		"Content-Length: %d\r\n"
		"\r\n%s", (int) strlen(body), body);

	response->header_len = strlen(response->header_buf);
	response->header_pos = 0;

	response->file_len   = 0;
	response->file_pos   = 0;
}

void
eth_http_response(http_response_t *response)
{
	char *path;
	char *wd = getcwd(NULL, 0);
	struct stat stat;

	asprintf(&path, "%s/htdocs/%s", wd, response->parser->path);

	response->file_fd = open(path, O_RDONLY);

	if (response->file_fd == -1) {
		build_404(response);
		return;
	}

	fstat(response->file_fd, &stat);

	asprintf(&response->header_buf,
		"HTTP/1.1 200 OK\r\n"
		"Host: internet\r\n"
		"Content-Length: %d\r\n"
		"\r\n", (int) stat.st_size);

	response->header_len = strlen(response->header_buf);
	response->header_pos = 0;

	response->file_len   = stat.st_size;
	response->file_pos   = 0;
}

void
handle_http_request(void)
{
	http_response_t *response;

	if (!cur_conn->http_response) {
		response = malloc(sizeof(http_response_t));

		response->parser = new_eth_parser();

		cur_conn->http_response = response;
	} else {
		response = cur_conn->http_response;
	}

	eth_parser_execute(response->parser, (const char *) cur_conn->data_buffer, cur_conn->data_len + 1, 0);

	if (eth_parser_finish(response->parser) == 1) {
		if (!strcmp(response->parser->path, "/autism")) {
			test_response(response);
		} else {
			eth_http_response(response);
		}

		response->parser->parsed = true;
		response->sent           = false;
	}
}

void
free_http_response(void)
{
	http_response_t *res = cur_conn->http_response;

	delete_eth_parser(res->parser);
	free(res->header_buf);
	close(res->file_fd);
	free(res);

	cur_conn->data_len      = 0;
	cur_conn->http_response = NULL;
}

