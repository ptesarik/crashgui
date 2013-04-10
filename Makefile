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

ifeq ($(shell arch), i686)
  TARGET=X86
  TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64
endif
ifeq ($(shell arch), ppc64)
  TARGET=PPC64
  TARGET_CFLAGS=-m64
endif
ifeq ($(shell arch), ia64)
  TARGET=IA64
  TARGET_CFLAGS=
endif
ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
endif

CFLAGS=-g -Wall

MODULES=guiserver.so
GUISERVER_SRC=guiserver.c getline.c

all: $(MODULES)

clean:
	rm $(MODULES) $(OBJS)

guiserver.so: $(GUISERVER_SRC)
	$(CC) $(CFLAGS) -nostartfiles -shared -rdynamic -o $@ $+ -fPIC -D$(TARGET)
