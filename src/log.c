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

void do_log(const char *fmt, va_list args, const char *type);

void
log_debug1(const char *msg __attribute__((unused)), ...)
{
#if DEBUG >= 1
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_BLUE "debug" PRINT_RST);
	va_end(args);
#endif
}

void
log_debug2(const char *msg __attribute__((unused)), ...)
{
#if DEBUG >= 2
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_BLUE "debug" PRINT_RST);
	va_end(args);
#endif
}

void
log_info(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_GREEN "info " PRINT_RST);
	va_end(args);
}

void
log_warn(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_YELLOW "warn " PRINT_RST);
	va_end(args);
}


void
log_error(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_RED "error" PRINT_RST);
	va_end(args);
}

void
fatal_tragedy(int code, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	do_log(msg, args, PRINT_RED "fatal" PRINT_RST);
	va_end(args);

	exit(code);
}

void
do_log(const char *fmt, va_list args, const char *type)
{
	char msgbuf[1024];
	char fmtbuf[1024];

	snprintf(fmtbuf, sizeof(fmtbuf), "[%s] %s\n", type, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);
	fprintf(stdout, "%s", msgbuf);
	fflush(stdout);
}

