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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <eth/http11.h>

static void
snake_upcase_char(char *c) {
	if (*c >= 'a' && *c <= 'z') {
		*c &= ~0x20;
	} else if (*c == '-') {
		*c = '_';
	}
}

#define LEN(AT, FPC) (FPC - buffer - parser->AT)
#define MARK(M,FPC) (parser->M = (FPC) - buffer)
#define PTR_TO(F) (buffer + parser->F)

%%{
	machine eth_parser;

	action mark {
		MARK(mark, fpc);
	}

	action start_field {
		MARK(field_start, fpc);
	}

	action snake_upcase_field {
		snake_upcase_char((char *)fpc);
	}

	action write_field {
		parser->field_len = LEN(field_start, fpc);
	}

	action start_value {
		MARK(mark, fpc);
	}

	action write_value {
		parser->field_cb(parser, PTR_TO(field_start), parser->field_len, PTR_TO(mark), LEN(mark, fpc));
	}

	action request_method {
		parser->method_cb(parser, PTR_TO(mark), LEN(mark, fpc));
	}

	action request_uri {
		parser->uri_cb(parser, PTR_TO(mark), LEN(mark, fpc));
	}

	action fragment {
		parser->fragment_cb(parser, PTR_TO(mark), LEN(mark, fpc));
	}

	action start_query {
		MARK(query_start, fpc);
	}

	action query {
		parser->query_cb(parser, PTR_TO(query_start), LEN(query_start, fpc));
	}

	action http_version {	
		parser->version_cb(parser, PTR_TO(mark), LEN(mark, fpc));
	}

	action request_path {
		parser->path_cb(parser, PTR_TO(mark), LEN(mark,fpc));
	}

	action done {
		parser->body_start = fpc - buffer + 1;
		parser->header_done_cb(parser, fpc + 1, pe - fpc - 1);
		fbreak;
	}

#### HTTP PROTOCOL GRAMMAR
# line endings
	CRLF = "\r\n";

# character types
	CTL = (cntrl | 127);
	safe = ("$" | "-" | "_" | ".");
	extra = ("!" | "*" | "'" | "(" | ")" | ",");
	reserved = (";" | "/" | "?" | ":" | "@" | "&" | "=" | "+");
	unsafe = (CTL | " " | "\"" | "#" | "%" | "<" | ">");
	national = any -- (alpha | digit | reserved | extra | safe | unsafe);
	unreserved = (alpha | digit | safe | extra | national);
	escape = ("%" xdigit xdigit);
	uchar = (unreserved | escape);
	pchar = (uchar | ":" | "@" | "&" | "=" | "+");
	tspecials = ("(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\\" | "\"" | "/" | "[" | "]" | "?" | "=" | "{" | "}" | " " | "\t");

# elements
	token = (ascii -- (CTL | tspecials));

# URI schemes and absolute paths
	scheme = ( alpha | digit | "+" | "-" | "." )* ;
	absolute_uri = (scheme ":" (uchar | reserved )*);

	path = ( pchar+ ( "/" pchar* )* ) ;
	query = ( uchar | reserved )* %query ;
	param = ( pchar | "/" )* ;
	params = ( param ( ";" param )* ) ;
	rel_path = ( path? %request_path (";" params)? ) ("?" %start_query query)?;
	absolute_path = ( "/"+ rel_path );

	Request_URI = ( "*" | absolute_uri | absolute_path ) >mark %request_uri;
	Fragment = ( uchar | reserved )* >mark %fragment;
	Method = ( upper | digit | safe ){1,20} >mark %request_method;

	http_number = ( digit+ "." digit+ ) ;
	HTTP_Version = ( "HTTP/" http_number ) >mark %http_version ;
	Request_Line = ( Method " " Request_URI ("#" Fragment){0,1} " " HTTP_Version CRLF ) ;

	field_name = ( token -- ":" )+ >start_field $snake_upcase_field %write_field;

	field_value = any* >start_value %write_value;

	message_header = field_name ":" " "* field_value :> CRLF;

	Request = Request_Line ( message_header )* ( CRLF @done );

	main := Request;

}%%

/** Data **/
%% write data;

int
eth_parser_init(eth_parser_t *parser)  {
	int cs = 0;

	%% write init;

	parser->cs          = cs;
	parser->body_start  = 0;
	parser->content_len = 0;
	parser->mark        = 0;
	parser->nread       = 0;
	parser->field_len   = 0;
	parser->field_start = 0;


	return 1;
}

/** exec **/
size_t
eth_parser_execute(eth_parser_t *parser, const char *buffer, size_t len, size_t off)  {
	const char *p, *pe;
	int cs = parser->cs;

	assert(off <= len && "offset past end of buffer");

	p = buffer+off;
	pe = buffer+len;

	/* assert(*pe == '\0' && "pointer does not end on NUL"); */
	assert(pe - p == len - off && "pointers aren't same distance");

	%% write exec;

	if (!eth_parser_has_error(parser))
		parser->cs = cs;
	parser->nread += p - (buffer + off);

	assert(p <= pe && "buffer overflow after parsing execute");
	assert(parser->nread <= len && "nread longer than length");
	assert(parser->body_start <= len && "body starts after buffer end");
	assert(parser->mark < len && "mark is after buffer end");
	assert(parser->field_len <= len && "field has length longer than whole buffer");
	assert(parser->field_start < len && "field starts after buffer end");

	return(parser->nread);
}

int
eth_parser_finish(eth_parser_t *parser) {
	if (eth_parser_has_error(parser)) {
		return -1;
	} else if (eth_parser_is_finished(parser)) {
		return 1;
	} else {
		return 0;
	}
}

int
eth_parser_has_error(eth_parser_t *parser) {
	return parser->cs == eth_parser_error;
}

int
eth_parser_is_finished(eth_parser_t *parser) {
	return parser->cs >= eth_parser_first_final;
}

/* shut clang */
#pragma unused(eth_parser_en_main)
