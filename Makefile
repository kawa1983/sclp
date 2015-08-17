# Makefile for sclp kernel module
# 
# Copyright 2014-2015 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

TARGET:= sclp.ko

CFILES = proto.c ipv4.c output.c sock_util.c frag_table.c tunnel.c offload.c

EXTRA_CFLAGS = -I$(src)/compat/include

sclp-objs:= $(CFILES:.c=.o)

all: ${TARGET}

sclp.ko: $(CFILES)
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 modules

modules_install:
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 modules_install

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 clean

obj-m:= sclp.o

proto.c: sclp_impl.h frag_table.h

ipv4.c: sclp_impl.h

output.c: sclp_impl.h

sock_util.c: sclp_impl.h

frag_table.c: frag_table.h

tunnel.c: sclp_impl.h

offload.c: 


clean-files := *.o *.ko *.mod.[co] *~

