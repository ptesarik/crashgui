/*
    Non-blocking interface to read arbitrarily long lines
    Copyright (C) 1997-2013 Petr Tesarik <ptesarik@suse.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "getline.h"

#define BUFFER_LOW	1024	/* low watermark */
#define BUFFER_INCR	4096	/* allocation increment */

enum getline_status
cbgetline(struct getline *s, GETLINEFUNC callback, void *cbdata)
{
	ssize_t res;
	char *p;

	if (s->data + s->len < s->end) {
		s->data += s->len;
		if ( (p = memchr(s->data, '\n', s->end - s->data)) ) {
			s->len = p - s->data + 1;
			return memchr(p + 1, '\n', s->end - p - 1)
				? GLS_MORE
				: GLS_ONE;
		}
		memmove(s->buf, s->data, s->end - s->data + 1);
		s->end -= s->data - s->buf;
	} else
		s->end = s->buf;

	s->data = s->buf;
	s->len = 0;

	if (s->buf + s->alloc - s->end < BUFFER_LOW) {
		if ( !(p = realloc(s->buf, s->alloc + BUFFER_INCR)) )
			return GLS_ERROR;
		s->end = p + (s->end - s->buf);
		s->buf = s->data = p;
		s->alloc += BUFFER_INCR;
	}

	res = callback(cbdata, s->end, s->buf + s->alloc - s->end - 1);
	if (res < 0)
		return res;

	s->end += res;
	*s->end = 0;

	if ( (p = memchr(s->data, '\n', s->end - s->data)) ) {
		s->len = p - s->buf + 1;
		return memchr(p + 1, '\n', s->end - p - 1)
			? GLS_MORE
			: GLS_ONE;
	} else if (!res) {
		s->len = s->end - s->data;
		return s->len ? GLS_FINAL : GLS_EOF;
	} else
		return GLS_AGAIN;
}

enum getline_status
cbgetraw(struct getline *s, size_t length,
	 GETLINEFUNC callback, void *cbdata)
{
	ssize_t res;
	char *p;

	if (s->data + s->len < s->end) {
		s->data += s->len;
		if (s->end - s->data >= length) {
			s->len = length;
			return s->data + s->len < s->end
				? GLS_MORE
				: GLS_ONE;
		}
		memmove(s->buf, s->data, s->end - s->data + 1);
		s->end -= s->data - s->buf;
	} else
		s->end = s->buf;

	s->data = s->buf;
	s->len = 0;

	if (s->alloc < length) {
		if ( !(p = realloc(s->buf, length)) )
			return GLS_ERROR;
		s->end = p + (s->end - s->buf);
		s->buf = s->data = p;
		s->alloc = length;
	}

	res = callback(cbdata, s->end, s->buf + s->alloc - s->end - 1);
	if (res < 0)
		return res;

	s->end += res;
	*s->end = 0;

	if (s->end - s->data >= length) {
		s->len = length;
		return s->data + s->len < s->end
			? GLS_MORE
			: GLS_ONE;
	} else if (!res) {
		s->len = s->end - s->buf;
		return s->len ? GLS_FINAL : GLS_EOF;
	} else
		return GLS_AGAIN;
}

static ssize_t
fdlinefunc(void *data, void *buf, size_t buflen)
{
	return read(*(int*)data, buf, buflen);
}

enum getline_status
fdgetline(struct getline *s, int fd)
{
	return cbgetline(s, fdlinefunc, &fd);
}

enum getline_status
fdgetraw(struct getline *s, size_t length, int fd)
{
	return cbgetraw(s, length, fdlinefunc, &fd);
}
