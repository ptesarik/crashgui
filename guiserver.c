#include <stdlib.h>
#include <stdarg.h>

#include <string.h>
#include <ctype.h>

#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <crash/defs.h>

void guiserver_init(void);    /* constructor function */
void guiserver_fini(void);    /* destructor function (optional) */

#define MODULE_NAME	"guiserver"
#define PROTOCOL_MAJOR	0
#define PROTOCOL_MINOR	1

/* printf format specifier for the greeting message */
#define GREET_FMT "[PROTOCOL=%d.%d] crashgui server ready.", \
		  PROTOCOL_MAJOR, PROTOCOL_MINOR

#define LISTEN_BACKLOG  1

typedef enum conn_status {
	conn_ok,		/* OK */
	conn_bad,		/* Malformed command */
	conn_no,		/* NO response */
	conn_bye,		/* Connection terminating */
	conn_dump,		/* DUMP response */
	conn_symbol,		/* SYMBOL response */

	conn_eof,		/* End of stream */
	conn_fatal = -1		/* Fatal error */
} CONN_STATUS;

typedef enum session_status {
	session_normal,		/* Normal session end */
	session_terminate,	/* TERMINATE command was used */
	session_error,		/* A (local) error occured */
} SESSION_STATUS;

typedef struct conn {
	/* socket stream */
	FILE *f;

	enum conn_status status;
	const struct proto_command *lastcmd;

	/* current input line */
	char *line;
	size_t linealloc;

	/* current tag */
	char *tag;
	size_t tagalloc;
	size_t taglen;

	/* current command */
	char *cmd, *cmdend;
	size_t cmdalloc;
	char *cmdp;		/* current pointer */

	/* current response */
	char *resp;
	size_t respalloc;
	size_t resplen;

	/* buffer (e.g. for literals) */
	char *buf;
	size_t bufalloc;

	/* terminating */
	int terminate;
} CONN;

struct proto_command {
	size_t len;
	const char *const name;
	CONN_STATUS (*const handler)(CONN *);
};

static CONN_STATUS do_DISCONNECT(CONN *conn);
static CONN_STATUS do_TERMINATE(CONN *conn);
static CONN_STATUS do_READMEM(CONN *conn);
static CONN_STATUS do_ADDRESS(CONN *conn);
static CONN_STATUS do_SYMBOL(CONN *conn);

#define DEFINE_CMD(name)	{ (sizeof(#name) - 1), (#name), (do_ ## name) }

static const struct proto_command cmds[] = {
	DEFINE_CMD(DISCONNECT),
	DEFINE_CMD(TERMINATE),
	DEFINE_CMD(READMEM),
	DEFINE_CMD(ADDRESS),
	DEFINE_CMD(SYMBOL),
	{ 0, NULL }
};

static const char crlf[2] = { '\r', '\n' };

#ifndef offsetof
#  define offsetof(TYPE, MEMBER) ((ulong)&((TYPE *)0)->MEMBER)
#endif

static void
report_error(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "%s: ", MODULE_NAME);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(errno));
}

static char *
copy_string(char **pdst, size_t *pdstalloc,
	    const char *src, size_t srclen)
{
	char *dst = *pdst;
	if (srclen > *pdstalloc) {
		if ( !(dst = realloc(dst, srclen)) )
			return dst;
		*pdst = dst;
		*pdstalloc = srclen;
	}
	memcpy(dst, src, srclen);
	return dst;
}

static void
toupper_string(char *str, size_t len)
{
	while (len--) {
		*str = toupper(*str);
		++str;
	}
}

static CONN *
conn_init(FILE *f)
{
	CONN *ret = calloc(1, sizeof(struct conn));
	if (ret) {
		ret->f = f;

		/* Prepare the greeting message */
		int n;
		ret->status = conn_ok;
		n = snprintf(NULL, 0, GREET_FMT);
		if (n < 0 || !(ret->resp = malloc(n+1))) {
			free(ret);
			return NULL;
		}
		ret->resplen = n;
		ret->respalloc = n + 1;
		snprintf(ret->resp, ret->respalloc, GREET_FMT);
	}
	return ret;
}

static void
conn_done(CONN *conn)
{
	if (conn->f)
		fclose(conn->f);
	if (conn->line)
		free(conn->line);
	if (conn->tag)
		free(conn->tag);
	if (conn->cmd)
		free(conn->cmd);
	if (conn->resp)
		free(conn->resp);
	if (conn->buf)
		free(conn->buf);
	free (conn);
}

static CONN_STATUS
ensure_buffer(CONN *conn, size_t size)
{
	if (size <= conn->bufalloc)
		return conn_ok;

	char *newbuf = realloc(conn->buf, size);
	if (!newbuf)
		return conn_bad;
	conn->buf = newbuf;
	conn->bufalloc = size;
	return conn_ok;
}

static CONN_STATUS
do_getcommand(CONN * conn)
{
	ssize_t length = getline(&conn->line, &conn->linealloc, conn->f);
	if (length <= 0)
		return ferror(conn->f) ? conn_fatal : conn_eof;

	/* Every line must be terminated by a LF. */
	if (conn->line[--length] != '\n')
		return conn_eof;
	/* The protocol requires terminating lines with CRLF,
	 * but we're lenient on what we accept and also allow LF.
	 */
	if (length > 0 && conn->line[length-1] == '\r')
		conn->line[--length] = 0;

	conn->taglen = 0;
	char *p = conn->line, *endp = p + length;
	while (p != endp && *p != ' ')
		++conn->taglen, ++p;
	if (!copy_string(&conn->tag, &conn->tagalloc,
			 conn->line, conn->taglen)) {
		conn->taglen = 0;
		return conn_fatal;
	}
	if (!conn->taglen || p == endp)
		return conn_bad;

	if (p == endp || *p != ' ')
		return conn_bad;
	++p;

	if (!copy_string(&conn->cmd, &conn->cmdalloc, p, endp - p))
		return conn_fatal;
	conn->cmdend = conn->cmd + (endp - p);
	conn->cmdp = conn->cmd;

	return 0;
}

static CONN_STATUS
conn_getcommand(CONN *conn)
{
	return conn->status = do_getcommand(conn);
}

static CONN_STATUS
do_respond(CONN *conn, int tagged)
{
	size_t sz;

	size_t taglen = conn->taglen;
	if (tagged && taglen) {
		conn->taglen = 0;
		sz = fwrite(conn->tag, 1, taglen, conn->f);
		if (sz != taglen)
			return conn_fatal;
	} else if (putc('*', conn->f) < 0)
		return conn_fatal;

	if (putc(' ', conn->f) < 0)
		return conn_fatal;

	const char *cond;
	switch (conn->status) {
	case conn_ok:	cond = "OK";  break;
	case conn_no:	cond = "NO";  break;
	case conn_bye:	cond = "BYE"; break;
	case conn_dump:	cond = "DUMP"; break;
	case conn_symbol: cond = "SYMBOL"; break;
	case conn_bad:
	default:	cond = "BAD"; break;
	}
	sz = fwrite(cond, 1, strlen(cond), conn->f);
	if (sz != strlen(cond))
		return conn_fatal;

	size_t resplen = conn->resplen;
	if (resplen) {
		conn->resplen = 0;
		if (putc(' ', conn->f) < 0)
			return conn_fatal;

		sz = fwrite(conn->resp, 1, resplen, conn->f);
		if (sz != resplen)
			return conn_fatal;
	} else if (conn->status == conn_ok && conn->lastcmd) {
		if (putc(' ', conn->f) < 0)
			return conn_fatal;

		size_t len = strlen(conn->lastcmd->name);
		sz = fwrite(conn->lastcmd->name, 1, len, conn->f);
		if (sz != len)
			return conn_fatal;

		static const char msg[] = " completed";
		sz = fwrite(msg, 1, sizeof(msg) - 1, conn->f);
		if (sz != sizeof(msg) - 1)
			return conn_fatal;
	}

	if (fwrite(crlf, 1, sizeof(crlf), conn->f) != sizeof(crlf))
		return conn_fatal;

	return conn_ok;
}

static CONN_STATUS
conn_respond(CONN *conn, int tagged)
{
	CONN_STATUS ret = do_respond(conn, tagged);
	fflush(conn->f);
	return ret;
}

static CONN_STATUS
set_response(CONN *conn, CONN_STATUS status, const char *msg)
{
	copy_string(&conn->resp, &conn->resplen, msg, strlen(msg));
	return conn->status = status;
}

static CONN_STATUS
read_space(CONN *conn)
{
	if (conn->cmdp == conn->cmdend || *conn->cmdp != ' ')
		return conn_bad;
	++conn->cmdp;
	return conn_ok;
}

static CONN_STATUS
read_number(CONN *conn, char **num, size_t *numlen)
{
	char *p = conn->cmdp;
	while (p != conn->cmdend && isdigit(*p))
		++p;

	*num = conn->cmdp;
	*numlen = p - conn->cmdp;
	conn->cmdp = p;
	return *numlen ? conn_ok : conn_bad;
}

static CONN_STATUS
read_atom(CONN *conn, char **atom, size_t *atomlen)
{
	char *p = conn->cmdp;
	while (p != conn->cmdend && *p != ' ')
		++p;

	*atom = conn->cmdp;
	*atomlen = p - conn->cmdp;
	conn->cmdp = p;
	return *atomlen ? conn_ok : conn_bad;
}

static CONN_STATUS
read_quoted(CONN *conn, char **string, size_t *len)
{
	char *p = conn->cmdp, *q;
	if (p == conn->cmdend || *p != '\"')
		return set_response(conn, conn_bad, "Quoted string expected");

	*string = q = ++p;
	while (p != conn->cmdend && *p != '\"') {
		if (*p == '\\')
			if (++p == conn->cmdend)
				break;
		*q++ = *p++;
	}

	if (p == conn->cmdend || *p != '\"')
		return set_response(conn, conn_bad, "Invalid quoted string");
	conn->cmdp = ++p;

	*len = q - *string;
	return conn_ok;
}

static CONN_STATUS
read_literal(CONN *conn, char **string, size_t *len)
{
	CONN_STATUS status;

	if (conn->cmdp == conn->cmdend || *conn->cmdp != '{')
		return set_response(conn, conn_bad, "Literal expected");
	++conn->cmdp;

	/* Read the number of bytes */
	char *num, *endnum;
	size_t numlen;
	if ((status = read_number(conn, &num, &numlen)) != conn_ok)
		return status;
	unsigned long size = strtoul(num, &endnum, 10);
	if (endnum != conn->cmdp)
		return set_response(conn, conn_bad, "Invalid literal");

	if (conn->cmdp + 1 != conn->cmdend || *conn->cmdp != '}')
		return set_response(conn, conn_bad, "Invalid literal");
	++conn->cmdp;

	/* Check for overflow */
	if (size == (size_t)-1)
		return set_response(conn, conn_bad, "Literal too big");

	if ( (status = ensure_buffer(conn, size + 1)) != conn_ok)
		return set_response(conn, status, strerror(errno));

	fputs("+ Ready for literal data\r\n", conn->f);
	fflush(conn->f);

	if (fread(conn->buf, 1, size, conn->f) != size) {
		const char *msg = ferror(conn->f)
			? strerror(errno)
			: "Unexpected EOF";
		return set_response(conn, conn_fatal, msg);
	}

	*string = conn->buf;
	*len = size;
	return conn_ok;
}

static CONN_STATUS
read_astring(CONN *conn, char **string, size_t *len)
{
	char *p = conn->cmdp;
	if (p == conn->cmdend)
		return conn_bad;
	else if (*p == '\"')
		return read_quoted(conn, string, len);
	else if (*p == '{')
		return read_literal(conn, string, len);
	else
		return read_atom(conn, string, len);
}

static CONN_STATUS
run_command(CONN *conn)
{
	char *cmd;
	size_t len;
	CONN_STATUS status;

	if ( (status = read_atom(conn, &cmd, &len)) != conn_ok)
		return conn->status = status;
	toupper_string(cmd, len);

	conn->lastcmd = NULL;
	const struct proto_command *cp = cmds;
	while (cp->len) {
		if (cp->len == len && !memcmp(cp->name, cmd, len)) {
			conn->lastcmd = cp;
			return conn->status = cp->handler(conn);
		}
		++cp;
	}

	return set_response(conn, conn_bad, "Unknown protocol command.");
}

static CONN_STATUS
send_untagged(CONN *conn, CONN_STATUS status, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(conn->buf, conn->bufalloc, fmt, ap);
	va_end(ap);

	if (n >= conn->bufalloc) {
		if (ensure_buffer(conn, n + 1) != conn_ok)
			return set_response(conn, conn_fatal, strerror(errno));
		va_start(ap, fmt);
		vsnprintf(conn->buf, conn->bufalloc, fmt, ap);
		va_end(ap);
	}

	CONN_STATUS oldstatus = conn->status;
	set_response(conn, status, conn->buf);
	status = conn_respond(conn, 0);
	conn->status = (status == conn_fatal) ? status : oldstatus;
	return status;
}

static CONN_STATUS
send_literal(CONN *conn, CONN_STATUS status, void *buffer, size_t length)
{
	status = send_untagged(conn, status, "{%lu}", (unsigned long) length);
	if (status == conn_ok) {
		size_t sz = fwrite(buffer, 1, length, conn->f);
		if (sz != length)
			status = conn_fatal;
	}
	return status;
}

/* This function returns NULL if sp is invalid */
static const char *
get_syment_module(struct syment *sp)
{
	if (sp >= st->symtable && sp < st->symend)
		return "";

	int i;
	for (i = 0; i < st->mods_installed; i++) {
		struct load_module *lm = &st->load_modules[i];
		if ((sp >= lm->mod_symtable && sp <= lm->mod_symend) ||
		    (sp >= lm->mod_init_symtable && sp <= lm->mod_init_symend))
			return lm->mod_name;
	}
	return NULL;
}

static CONN_STATUS
send_symbol(CONN *conn, struct syment *sp)
{
	unsigned long addr = sp->value;
	const char *modname = get_syment_module(sp);
	CONN_STATUS status;

	do {
		struct syment *nextsp = sp + 1;
		const char *nextmod = get_syment_module(nextsp);
		unsigned long symsize = 0;

		if (nextmod)
			symsize = nextsp->value - sp->value;
		status = send_untagged(conn, conn_symbol,
				       "%lx %lx %c \"%s\" \"%s\"",
				       sp->value, symsize, sp->type,
				       sp->name, modname);
		sp = nextsp;
		modname = nextmod;
	} while (status == conn_ok && modname && sp->value == addr);

	return status;
}

static CONN_STATUS
disconnect(CONN *conn, const char *reason)
{
	if (shutdown(fileno(conn->f), SHUT_RD))
		return set_response(conn, conn_fatal, strerror(errno));

	return send_untagged(conn, conn_bye, "%s", reason);
}

static CONN_STATUS
too_many_args(CONN *conn)
{
	char *p = conn->cmdp;
	while (p != conn->cmdend && *p == ' ')
		++p;
	return set_response(conn, conn_bad, (p != conn->cmdend
					     ? "Too many arguments"
					     : "Trailing space"));
}

static CONN_STATUS
do_DISCONNECT(CONN *conn)
{
	if (conn->cmdp < conn->cmdend)
		return too_many_args(conn);

	return disconnect(conn, "connection closing");
}

static CONN_STATUS
do_TERMINATE(CONN *conn)
{
	if (conn->cmdp < conn->cmdend)
		return too_many_args(conn);

	CONN_STATUS status = disconnect(conn, "terminating crashgui server");
	if (status == conn_ok)
		conn->terminate = 1;
	return status;
}

static CONN_STATUS
do_READMEM(CONN *conn)
{
	char *tok, *endnum;
	size_t len;
	CONN_STATUS status;

	/* Get starting address */
	if ( (status = read_space(conn)) != conn_ok)
		return status;
	if ((status = read_atom(conn, &tok, &len)) != conn_ok)
		return status;
	unsigned long addr = strtoul(tok, &endnum, 16);
	if (endnum != conn->cmdp)
		return set_response(conn, conn_bad, "Invalid start address");

	/* Get byte count */
	if ( (status = read_space(conn)) != conn_ok)
		return status;
	if ((status = read_atom(conn, &tok, &len)) != conn_ok)
		return status;
	unsigned long bytecnt = strtoul(tok, &endnum, 16);
	if (endnum != conn->cmdp)
		return set_response(conn, conn_bad, "Invalid byte count");

	/* Get (optional) memory type */
	int memtype = KVADDR;
	if (conn->cmdp != conn->cmdend) {
		if ((status = read_space(conn)) != conn_ok)
			return status;
		if ((status = read_atom(conn, &tok, &len)) != conn_ok)
			return status;
		toupper_string(tok, len);
		if (len) {
			if (len == 6 && !memcmp(tok, "KVADDR", 6))
				memtype = KVADDR;
			else if (len == 6 && !memcmp(tok, "UVADDR", 6))
				memtype = UVADDR;
			else if (len == 8 && !memcmp(tok, "PHYSADDR", 8))
				memtype = PHYSADDR;
			else if (len == 11 && !memcmp(tok, "XENMACHADDR", 11))
				memtype = XENMACHADDR;
			else if (len == 8 && !memcmp(tok, "FILEADDR", 8))
				memtype = FILEADDR;
			else
				return set_response(conn, conn_bad,
						    "Invalid memory type");
		}

		if (conn->cmdp != conn->cmdend)
			return too_many_args(conn);
	}

	char *buffer = malloc(bytecnt);
	if (!buffer)
		return set_response(conn, conn_bad,
				    "Buffer allocation failure");

	if (!readmem(addr, memtype, buffer, bytecnt,
		     "crashgui", RETURN_ON_ERROR))
		return set_response(conn, conn_no, "Read error");

	status = send_literal(conn, conn_dump, buffer, bytecnt);

	free(buffer);
	return status;
}

static CONN_STATUS
do_ADDRESS(CONN *conn)
{
	CONN_STATUS status;
	char *tok;
	size_t len;

	/* Get the symbol name */
	if ( (status = read_space(conn)) != conn_ok)
		return status;
	if ((status = read_astring(conn, &tok, &len)) != conn_ok)
		return status;
	tok[len] = 0;

	struct syment *sp = symbol_search(tok);
	if (!sp)
		return set_response(conn, conn_no, "Symbol not found");

	return send_symbol(conn, sp);
}

static CONN_STATUS
do_SYMBOL(CONN *conn)
{
	CONN_STATUS status;
	char *tok, *endnum;
	size_t len;

	/* Get the address */
	if ( (status = read_space(conn)) != conn_ok)
		return status;
	if ((status = read_atom(conn, &tok, &len)) != conn_ok)
		return status;
	unsigned long addr = strtoul(tok, &endnum, 16);
	if (endnum != conn->cmdp)
		return set_response(conn, conn_bad, "Invalid address");

	if (conn->cmdp != conn->cmdend)
		return too_many_args(conn);

	ulong offset;
	struct syment *sp = value_search(addr, &offset);
	if (!sp)
		return set_response(conn, conn_no, "Symbol not found");

	return send_symbol(conn, sp);
}

static SESSION_STATUS
run_session(FILE *f)
{
	CONN *conn;
	CONN_STATUS status;
	int terminate = 0;

	if (! (conn = conn_init(f)) )
		return session_error;

	do {
		status = conn_respond(conn, 1);
		if (status == conn_fatal)
			break;

		status = conn_getcommand(conn);
		if (status == conn_ok)
			status = run_command(conn);
	} while (status != conn_fatal && status != conn_eof);

	terminate = conn->terminate;
	conn_done(conn);
	if (status == conn_fatal)
		return session_error;
	else if (terminate)
		return session_terminate;
	else
		return session_normal;
}

static int
run_server(const char *path)
{
	size_t sz = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
	struct sockaddr_un *sun;
	int fd, sessfd;
	int ret = -1;
	int i;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		report_error("Cannot create socket");
		goto err;
	}

	if (! (sun = malloc(sz)) ) {
		report_error("Cannot allocate file name %s", path);
		goto err_close;
	}

	sun->sun_family = AF_UNIX;
	strcpy(sun->sun_path, path);
	for (i = 1; i >= 0; --i) {
		if (!i)
			unlink(path);
		if (!bind(fd, (struct sockaddr *) sun, sz))
			break;
	}
	free(sun);
	if (i < 0) {
		report_error("Cannot bind socket to %s", path);
		goto err_close;
	}

	if (listen(fd, LISTEN_BACKLOG)) {
		report_error("Cannot listen on %s", path);
		goto err_unlink;
	}

	while ( (sessfd = accept(fd, NULL, NULL)) >= 0) {
		FILE *f;

		if (! (f = fdopen(sessfd, "a+")) ) {
			report_error("Cannot create input stream");
			close(sessfd);
			continue;
		}

		SESSION_STATUS status = run_session(f);
		if (status == session_terminate) {
			ret = 0;
			break;
		}
	}

 err_unlink:
	unlink(path);
 err_close:
	close(fd);
 err:
	return ret;
}

static void
cmd_guiserver(void)
{
	if (argcnt > 2) {
		cmd_usage(pc->curcmd, SYNOPSIS);
		return;
	}
	if (argcnt < 2) {
		fprintf(stderr, "Creating a default socket file name not yet implemented.\n");
		return;
	}

	run_server(args[1]);
}

static char *help_guiserver[] = {
        "guiserver",		      /* command name */
        "starts the crashgui server", /* short description */
        "[file]",		      /* argument synopsis, or " " if none */

	"  This command starts the crashgui server. The server listens on",
	"  a UNIX-domain socket for connections from the crashgui client.",
	"  If no file is specified, the command creates a socket in a subdir",
        "  of TMPDIR (if this environment variable is set) or of /tmp.",
        "\nEXAMPLE",
        "  Start the server with socket in /home/joe/crashgui.socket:\n",
        "    crash> guiserver /home/joe/crashgui.socket",
        NULL
};

static struct command_table_entry command_table[] = {
        { "guiserver", cmd_guiserver, help_guiserver, 0},
        { NULL },                                     /* terminated by NULL, */
};

void __attribute__((constructor))
guiserver_init(void)
{
	register_extension(command_table);
}

void __attribute__((destructor))
guiserver_fini(void)
{
}
