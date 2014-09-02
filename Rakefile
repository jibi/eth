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

require 'rake'
require 'rake/clean'

NAME    = 'eth'

CC      = ENV['CC'] || 'clang'
CFLAGS  = ENV['CFLAGS'].to_s + " -Wall -pedantic -g -DDEBUG=1 -Wno-c11-extensions -I ./include -I ./deps/netmap/sys `pkg-config --cflags glib-2.0`"
LDFLAGS = ENV['LDFLAGS'].to_s + " `pkg-config --libs glib-2.0`"

PARSER  = FileList['src/*.rl']
SOURCES = FileList['src/*.c'] + FileList['src/**/*c']
OBJECTS = (SOURCES.ext('o') + PARSER.ext('o')).uniq

CLEAN.include(OBJECTS).include(NAME).include(PARSER.ext('c'))

task :default => [PARSER.ext('c'), NAME]
task :deps => [:netmap]

task :netmap do
  sh "cd deps/netmap/LINUX; make clean; make"
end

file NAME => OBJECTS do
	sh "#{CC} #{LDFLAGS} #{OBJECTS} -o #{NAME}"
end

rule '.c' => '.rl' do |file|
	sh "ragel #{file.source}"
end

rule '.o' => '.c' do |file|
	sh "#{CC} #{CFLAGS} -c #{file.source} -o #{file}"
end

