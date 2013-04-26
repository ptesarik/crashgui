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

#ifndef __GETLINE_H
#define __GETLINE_H

enum getline_status {
	GLS_FINAL = 0,		/* unterminated last line of a file */
	GLS_OK,			/* complete line (terminated by a newline) */

	GLS_AGAIN = -1,		/* not a complete line yet (would block) */
	GLS_EOF = -2,		/* end-of-file reached */
	GLS_ERROR = -3,		/* error condition (see errno) */
};

struct getline {
	char *data;		/* data start */
	size_t len;		/* data length */

	char *buf;		/* buffer base address */
	char *end;		/* buffer end */
	size_t alloc;		/* current buffer size */
};

/* fdgetline - a non-blocking interface to read arbitrarily long lines
 *
 * Arguments:
 * s		struct getline
 * fd		file descriptor as returned by open(2), socket(2) or similar
 *
 * Returns:
 * The status, see enum getline_status above.
 *
 * This function never blocks if fd is ready for reading upon calling.
 *
 * Note: If fdgetline() returns GLS_MORE, next call to fdgetline() will
 * never block. If it returns GLS_NONE or GLS_ONE, it may block. If it
 * returns GLS_FINAL, the file descriptor has reached end of file, *pbuf
 * will contain the incomplete last line, or it may be empty.
 *
 * The correct way to use this function:
 *
 * 1. Initialise struct getline to all zero.
 *
 * 2. Call fdgetline(&s, fd)
 *	fdgetline() will allocate a buffer and read the first bit.
 *
 * 3. You may call fdgetline() with the same buf, off, len and alloc
 *	to read as much of the file as you want. Every time you call it
 *	and it returns an integer greater than zero, there will be
 *	a line at (buf), (off) bytes long. The line is terminated by
 *	a new-line character if it is complete, or by NUL ('\0') if
 *	this is an incomplete last line.
 *
 * 3. Finally, call free(buf) because it has been dynamically allocated.
 *
 * cbgetline is a more general interface which uses a callback function
 * for reading and a general data pointer so that it can read from any
 * type of input (e.g. SSL). The callback takes these arguments:
 *
 * data		data pointer passed to cbgetline()
 * buf		pointer to read buffer
 * buflen	number of bytes to read
 *
 * The callback function should return the number of bytes actually read
 * or negative on error. Negative values are returned directly to the caller
 * of cbgetline(). In particular, you should return 0 on EOF, not GLS_EOF,
 * because some data may be already buffered.
 */

typedef ssize_t (*GETLINEFUNC)(void *data, void *buf, size_t buflen);

enum getline_status cbgetline(struct getline *s,
			      GETLINEFUNC callback, void *cbdata);
enum getline_status fdgetline(struct getline *s, int fd);

enum getline_status cbgetraw(struct getline *s, size_t length,
			     GETLINEFUNC callback, void *cbdata);
enum getline_status fdgetraw(struct getline *s, size_t length, int fd);

/* Returns non-zero if more lines are buffered already */
static inline int
getline_hasmore(struct getline *s)
{
	return !!memchr(s->data + s->len, '\n', s->end - (s->data + s->len));
}

/* Get the number of buffered (and not yet read) bytes */
static inline size_t
getline_buffered(struct getline *s)
{
	return s->end - (s->data + s->len);
}

#endif	/* __GETLINE_H */
