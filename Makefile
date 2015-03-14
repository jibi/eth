#
# Copyright (C) 2014 jibi <jibi@paranoici.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

CC=gcc
CFLAGS=-Wall -pedantic -Ofast -std=gnu11 -I ./include -isystem ./deps/netmap/sys
LDFLAGS=-lJudy
SOURCES=src/eth.c src/exotcp.c src/http11.c src/log.c src/netmap.c src/parser.c \
src/datastruct/hash.c src/datastruct/list.c \
src/exotcp/arp.c src/exotcp/checksum.c src/exotcp/eth.c src/exotcp/icmp.c src/exotcp/ip.c src/exotcp/tcp.c
PARSER=src/parser.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=eth

$(EXECUTABLE): $(PARSER) $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
.c.o:
	$(CC) -c $(CFLAGS) $< -o $@
$(PARSER):
	ragel src/parser.rl -o $@
all: $(SOURCES) $(EXECUTABLE)
deps: deps/netmap
	cd deps/netmap/LINUX; ./configure --kernel-sources=/usr/src/linux
	cd deps/netmap/LINUX; make
clean:
	@rm $(EXECUTABLE) $(OBJECTS)
depsclean:
	cd deps/netmap/LINUX; make clean
