#include <sys/types.h>

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

int eth_parser_init(eth_parser_t *parser);
int eth_parser_finish(eth_parser_t *parser);
size_t eth_parser_execute(eth_parser_t *parser, const char *data, size_t len, size_t off);
int eth_parser_has_error(eth_parser_t *parser);
int eth_parser_is_finished(eth_parser_t *parser);

#define eth_parser_nread(parser) (parser)->nread

eth_parser_t *new_eth_parser();
void delete_eth_parser_t(eth_parser_t *p);
char *handle_http_request(char *request, size_t len);
