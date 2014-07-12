#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <eth/http11.h>

static void
field(eth_parser_t* hp, const char *field, size_t flen, const char *value, size_t vlen) {
//	printf("field:\n\tname:\t%.*s\n\tvalue:\t%.*s\n",  (int)flen, field,  (int)vlen, value);
}

static void
method(eth_parser_t* hp, const char *at, size_t length) {
	asprintf(&hp->method, "%.*s", (int) length, at);

}

static void
uri(eth_parser_t* hp, const char *at, size_t length) {
	asprintf(&hp->uri, "%.*s", (int) length, at);
}

static void
fragment(eth_parser_t* hp, const char *at, size_t length) {
	//printf("frag:\t\t%.*s\n", (int) length, at);
}

static void
path(eth_parser_t* hp, const char *at, size_t length) {
	asprintf(&hp->path, "%.*s", (int) length, at);
}

static void
query(eth_parser_t* hp, const char *at, size_t length) {
	asprintf(&hp->query, "%.*s", (int) length, at);

}

static void
version(eth_parser_t* hp, const char *at, size_t length) {
	asprintf(&hp->version, "%.*s", (int) length, at);

}

static void
header_done(eth_parser_t* hp, const char *at, size_t length) {

}

eth_parser_t *
new_eth_parser() {
	eth_parser_t *parser = malloc(sizeof(eth_parser_t));

	parser->field_cb       = field;
	parser->method_cb      = method;
	parser->uri_cb         = uri;
	parser->fragment_cb    = fragment;
	parser->path_cb        = path;
	parser->query_cb       = query;
	parser->version_cb     = version;
	parser->header_done_cb = header_done;

	parser->method      = NULL;
	parser->uri         = NULL;
	parser->path        = NULL;
	parser->query       = NULL;
	parser->version     = NULL;

	eth_parser_init(parser);

	return parser;
}

void
delete_eth_parser(eth_parser_t *p) {
	if (p->method)
		free(p->method);

	if (p->uri)
		free(p->uri);

	if (p->path)
		free(p->path);

	if (p->query)
		free(p->query);

	if (p->version)
		free(p->version);

	free(p);

}

char *
test_response(eth_parser_t *request) {
	char *body;
	char *response;

	asprintf(&body,
		"Oh, Hi.\n"
		"I'm an autistic web server.\n\n"
		"method: %s\n"
		"uri:    %s\n"
		"path:   %s\n"
		"query:  %s\n", request->method, request->uri, request->path, request->query);


	asprintf(&response,
		"HTTP/1.1 200 OK\r\n"
		"Host: sbiriguda\r\n"
		"Content-Length: %d\r\n"
		"\r\n%s", (int) strlen(body), body);

	free(body);

	return response;
}

char *
build_404(eth_parser_t *request) {
	char *response;
	char *body = "<h1>404 Not Found :(<h1>";

	asprintf(&response,
		"HTTP/1.1 404 Not Found\r\n"
		"Host: internet\r\n"
		"Content-Length: %d\r\n"
		"\r\n%s", (int) strlen(body), body);

	return response;
}

char *
eth_http_response(eth_parser_t *request) {
	char *path;
	char *wd = getcwd(NULL, 0);
	int fd;
	struct stat stat;
	char *buf;
	char *response;

	asprintf(&path, "%s/htdocs/%s", wd, request->path);

	fd = open(path, O_RDONLY);

	if (fd == -1) {
		return build_404(request);
	}

	fstat(fd, &stat);

	buf = malloc(stat.st_size);
	read(fd, buf, stat.st_size);

	asprintf(&response,
		"HTTP/1.1 200 OK\r\n"
		"Host: internet\r\n"
		"Content-Length: %d\r\n"
		"\r\n%s", (int) stat.st_size, buf);

	return response;
}

char *
handle_http_request(char *request, size_t len) {
	char *response;

	eth_parser_t *parsed_req = new_eth_parser();
	eth_parser_execute(parsed_req, request, len + 1, 0);

	if (!strcmp(parsed_req->path, "/autism")) {
		response = test_response(parsed_req);
	} else {
		response = eth_http_response(parsed_req);
	}

	return response;
}

