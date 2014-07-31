#define _BSD_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdint.h>

#define PRINT_BLACK   "\033[22;30m"
#define PRINT_RED     "\033[22;31m"
#define PRINT_GREEN   "\033[22;32m"
#define PRINT_BROWN   "\033[22;33m"
#define PRINT_BLUE    "\033[22;34m"
#define PRINT_MAGENTA "\033[22;35m"
#define PRINT_CYAN    "\033[22;36m"
#define PRINT_GRAY    "\033[22;37m"
#define PRINT_YELLOW  "\033[01;33m"

#define PRINT_RST     "\033[0m"

int debug_level = 4;
void do_log(const char *fmt, va_list args, const char *type);

void
dump(const char *data_buffer, size_t length) {
	uint8_t byte;
	size_t i, j;

	for (i = 0; i < length; i++) {
		byte = data_buffer[i];

		printf("%02x ", (uint8_t) data_buffer[i]);

		if (((i%16) == 15) || (i == length - 1)) {
			for(j = 0; j < 15 - (i % 16); j++) {
				printf("   ");
			}

			printf("| ");

			for(j = (i - (i % 16 )); j <= i; j++) {
				byte = data_buffer[j];
				if ((byte > 31) && (byte < 127)) {
					printf("%c", byte);
				}
				else {
					printf(".");
				}
			}
			printf("\n");
		}
	}
}

void
log_debug1(const char *msg __attribute__((unused)), ...) {
#if DEBUG >= 1
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_BLUE "debug" PRINT_RST);
	va_end(args);
#endif
}

void
log_debug2(const char *msg __attribute__((unused)), ...) {
#if DEBUG >= 2
	va_list args;

	if (debug_level < 2) {
		return;
	}

	va_start(args, msg);
	do_log(msg, args, PRINT_BLUE "debug" PRINT_RST);
	va_end(args);
#endif
}
void
log_info(const char *msg, ...) {
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_GREEN "info " PRINT_RST);
	va_end(args);
}

void
log_error(const char *msg, ...) {
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_RED "error" PRINT_RST);
	va_end(args);
}

void
fatal_tragedy(int code, const char *msg, ...) {
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_RED "fatal" PRINT_RST);
	va_end(args);

	exit(code);
}

void
do_log(const char *fmt, va_list args, const char *type) {
	char msgbuf[1024];
	char fmtbuf[1024];

	snprintf(fmtbuf, sizeof(fmtbuf), "[%s] %s\n", type, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
	fprintf(stdout, "%s", msgbuf);
	fflush(stdout);
}

