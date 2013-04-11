#include <stdlib.h>
#include <stdarg.h>

#include <string.h>
#include <ctype.h>

#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#include <crash/defs.h>

#include "getline.h"

void guiserver_init(void);    /* constructor function */
void guiserver_fini(void);    /* destructor function (optional) */

#define MODULE_NAME	"guiserver"
#define PROTOCOL_MAJOR	0
#define PROTOCOL_MINOR	1

/* printf format specifier for the greeting message */
#define GREET_FMT "[PROTOCOL=%d.%d] crashgui server ready.", \
		  PROTOCOL_MAJOR, PROTOCOL_MINOR

#define LISTEN_BACKLOG  1

typedef struct server {
	struct server *next, **pprev;

	struct pollfd pfd;
	struct sockaddr_un sun;
} SERVER;

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

typedef struct conn CONN;
typedef CONN_STATUS (*conn_handler_t)(CONN *);
typedef CONN_STATUS (*read_handler_t)(CONN *, char *, size_t);

struct conn {
	struct conn *next, **pprev;

	struct pollfd pfd;

	conn_handler_t handler;
	enum conn_status status;
	const struct proto_command *lastcmd;

	/* Server termination */
	enum {
		conn_running,
		conn_bye_pending,
		conn_bye_xmit,
		conn_bye_sent
	} term_state;
	short term_events;

	/* current input line */
	struct getline line;
	enum getline_status gls;

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

	/* I/O progress */
	char *iobuf;
	size_t iotodo;

	union {
		struct {
			read_handler_t handler;
			unsigned long size;
		} read;
		struct {
			struct syment *sp;
			const char *modname;
			int byname;
		} symbol;
	};
};

/* Connection state handlers */
static CONN_STATUS finish_response(CONN *conn);
static CONN_STATUS conn_readcommand(CONN *conn);
static CONN_STATUS conn_getcommand(CONN *conn);
static CONN_STATUS literal_data_raw(CONN *conn);
static CONN_STATUS literal_data_done(CONN *conn);
static CONN_STATUS send_symbol_data(CONN *conn);

struct proto_command {
	size_t len;
	const char *const name;
	CONN_STATUS (*const handler)(CONN *);
};

static CONN_STATUS do_DISCONNECT(CONN *conn);
static CONN_STATUS do_TERMINATE(CONN *conn);
static CONN_STATUS do_READMEM(CONN *conn);
static CONN_STATUS do_SYMBOL(CONN *conn);
static CONN_STATUS do_ADDRESS(CONN *conn);

#define DEFINE_CMD(name)	{ (sizeof(#name) - 1), (#name), (do_ ## name) }

static const struct proto_command cmds[] = {
	DEFINE_CMD(DISCONNECT),
	DEFINE_CMD(TERMINATE),
	DEFINE_CMD(READMEM),
	DEFINE_CMD(SYMBOL),
	DEFINE_CMD(ADDRESS),
	{ 0, NULL }
};

static const char crlf[2] = { '\r', '\n' };

#ifndef offsetof
#  define offsetof(TYPE, MEMBER) ((ulong)&((TYPE *)0)->MEMBER)
#endif

/* Linked list of active servers */
static struct server *servers;
static int nservers;

/* Linked list of open connexions */
static struct conn *connections;
static int nconnections;

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

static void server_done(SERVER *server);

static SERVER *
server_init(const char *path)
{
	size_t sz;
	SERVER *ret;
	int i;

	sz = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
	if (! (ret = malloc(offsetof(struct server, sun) + sz)) ) {
		report_error("Cannot allocate server struct for %s", path);
		return NULL;
	}
	ret->next = servers;
	ret->pprev = &servers;
	if (servers)
		servers->pprev = &ret->next;
	servers = ret;
	++nservers;

	ret->pfd.fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret->pfd.fd < 0) {
		report_error("Cannot create socket");
		goto err;
	}

	ret->sun.sun_family = AF_UNIX;
	strcpy(ret->sun.sun_path, path);
	for (i = 1; i >= 0; --i) {
		if (!i)
			unlink(path);
		if (!bind(ret->pfd.fd, (struct sockaddr *) &ret->sun, sz))
			break;
	}
	if (i < 0) {
		report_error("Cannot bind socket to %s", path);
		goto err;
	}

	if (listen(ret->pfd.fd, LISTEN_BACKLOG)) {
		report_error("Cannot listen on %s", path);
		goto err;
	}
	ret->pfd.events = POLLIN;

	return ret;

 err:
	server_done(ret);
	return NULL;
}

static void
server_done(SERVER *server)
{
	--nservers;
	if (server->next)
		server->next->pprev = server->pprev;
	*server->pprev = server->next;

	if (server->pfd.fd >= 0) {
		close(server->pfd.fd);
		unlink(server->sun.sun_path);
	}
	free(server);
}

static void
server_destroyall(void)
{
	while (servers)
		server_done(servers);
}

static CONN *
conn_init(int fd)
{
	CONN *ret = calloc(1, sizeof(struct conn));
	if (ret) {
		ret->pfd.fd = fd;

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

		if (finish_response(ret) != conn_ok) {
			free(ret);
			return NULL;
		}

		ret->next = connections;
		ret->pprev = &connections;
		if (connections)
			connections->pprev = &ret->next;
		connections = ret;
		++nconnections;
	}
	return ret;
}

static void
conn_done(CONN *conn)
{
	--nconnections;
	if (conn->next)
		conn->next->pprev = conn->pprev;
	*conn->pprev = conn->next;

	if (conn->pfd.fd >= 0)
		close(conn->pfd.fd);
	if (conn->line.buf)
		free(conn->line.buf);
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

static void
conn_destroyall(void)
{
	while (connections)
		conn_done(connections);
}

static void
disconnect(CONN *conn)
{
	if (shutdown(conn->pfd.fd, SHUT_RD)) {
		close(conn->pfd.fd);
		conn->pfd.fd = -1;
	}
}

static int
check_bye(CONN *conn)
{
	static const char msg_bye[] = "* BYE Server terminating\r\n";

	if (conn->iotodo)
		return 0;

	if (conn->term_state == conn_bye_pending) {
		conn->term_events = conn->pfd.events;
		conn->iobuf = (char*)msg_bye;
		conn->iotodo = sizeof msg_bye - 1;
		conn->pfd.events = POLLOUT;
		conn->term_state = conn_bye_xmit;
		return 1;
	} else if (conn->term_state == conn_bye_xmit) {
		disconnect(conn);
		conn->pfd.events = conn->term_events;
		conn->term_state = conn_bye_sent;
	}
	return 0;
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

static CONN_STATUS run_command(CONN *conn);

static CONN_STATUS
do_readcommand(CONN * conn)
{
	conn->gls = fdgetline(&conn->line, conn->pfd.fd);
	if (conn->gls < GLS_ONE) {
		if (conn->gls == GLS_AGAIN)
			return conn_ok;
		if (conn->gls == GLS_EOF || conn->gls == GLS_FINAL)
			return conn_eof;
		return conn_fatal;
	}
	conn->pfd.events = 0;
	conn->handler = finish_response;

	/* The protocol requires terminating lines with CRLF,
	 * but we're lenient on what we accept and also allow LF.
	 */
	size_t length = conn->line.len - 1;
	if (length > 0 && conn->line.data[length-1] == '\r')
		--length;

	conn->taglen = 0;
	char *p = conn->line.data, *endp = p + length;
	while (p != endp && *p != ' ')
		++conn->taglen, ++p;
	if (!copy_string(&conn->tag, &conn->tagalloc,
			 conn->line.data, conn->taglen)) {
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

	return run_command(conn);
}

static CONN_STATUS
conn_readcommand(CONN *conn)
{
	return conn->status = do_readcommand(conn);
}

static CONN_STATUS
conn_getcommand(CONN *conn)
{
	conn->pfd.events = POLLIN;
	conn->handler = conn_readcommand;
	return conn_ok;
}

static CONN_STATUS
conn_respond(CONN *conn, int tagged)
{
	static const char *const msg_cond[] = {
		[conn_ok] =     "OK",
		[conn_no] =     "NO",
		[conn_bad] =    "BAD",
		[conn_bye] =    "BYE",
		[conn_dump] =   "DUMP",
		[conn_symbol] = "SYMBOL",
	};
	static const char msg_completed[] = " completed";
	static const char msg_failed[] = " failed";

	size_t taglen = tagged ? conn->taglen : 0;

	const char *cond =
		(conn->status < sizeof(msg_cond)/sizeof(msg_cond[0]))
		? msg_cond[conn->status]
		: msg_cond[conn_bad];

	size_t sz = (taglen ?: 1)	/* tag or "*" */
		+ 1			/* SP */
		+ strlen(cond)		/* condition code */
		+ 1			/* SP */
		+ (conn->resplen ?:	/* custom response, or */
		   (conn->lastcmd ?
		    strlen(conn->lastcmd->name) /* command name */
		    + 1				/* SP */
		    + sizeof msg_completed - 1	/* " completed" */
		    : 0))		/* or nothing */
		+ 2;			/* CRLF */

	if (ensure_buffer(conn, sz + 1) != conn_ok)
		return conn_fatal;

	char *p = conn->buf;
	if (taglen) {
		memcpy(p, conn->tag, conn->taglen);
		p += conn->taglen;
		conn->taglen = 0;
	} else
		*p++ = '*';

	*p++ = ' ';
	p = stpcpy(p, cond);
	*p++ = ' ';

	if (conn->resplen) {
		memcpy(p, conn->resp, conn->resplen);
		p += conn->resplen;
		conn->resplen = 0;
	} else if (conn->lastcmd) {
		p = stpcpy(p, conn->lastcmd->name);
		p = stpcpy(p, (conn->status == conn_ok
			       ? msg_completed
			       : msg_failed));
	}
	if (tagged)
		conn->lastcmd = NULL;

	memcpy(p, crlf, sizeof crlf);
	p += sizeof crlf;

	conn->iobuf = conn->buf;
	conn->iotodo = p - conn->buf;
	conn->pfd.events = POLLOUT;

	return conn_ok;
}

static CONN_STATUS
set_response(CONN *conn, CONN_STATUS status, const char *msg)
{
	copy_string(&conn->resp, &conn->resplen, msg, strlen(msg));
	return conn->status = status;
}

static CONN_STATUS
finish_response(CONN *conn)
{
	conn->handler = conn_getcommand;
	return conn_respond(conn, 1);
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
read_literal(CONN *conn, read_handler_t handler)
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
	conn->read.size = strtoul(num, &endnum, 10);
	if (endnum != conn->cmdp)
		return set_response(conn, conn_bad, "Invalid literal");

	if (conn->cmdp + 1 != conn->cmdend || *conn->cmdp != '}')
		return set_response(conn, conn_bad, "Invalid literal");
	++conn->cmdp;

	if (ensure_buffer(conn, conn->read.size) != conn_ok)
		return set_response(conn, conn_bad, strerror(errno));

	static char msg[] = "+ Ready for literal data\r\n";
	conn->iobuf = msg;
	conn->iotodo = sizeof msg - 1;
	conn->pfd.events = POLLOUT;

	conn->handler = literal_data_raw;
	conn->read.handler = handler;

	return conn_ok;
}

static CONN_STATUS
literal_data_raw(CONN *conn)
{
	conn->iobuf = conn->buf;
	conn->iotodo = conn->read.size;

	size_t avl = getline_buffered(&conn->line);
	if (avl >= conn->read.size)
		avl = conn->read.size;
	if (avl) {
		conn->gls = fdgetraw(&conn->line, avl, conn->pfd.fd);
		conn->iobuf += conn->line.len;
		conn->iotodo -= conn->line.len;
		if (conn->iotodo)
			memcpy(conn->buf, conn->line.data, conn->line.len);
	}
	if (conn->iotodo)
		conn->pfd.events = POLLIN;

	conn->handler = literal_data_done;
	return conn_ok;
}

static CONN_STATUS
literal_data_done(CONN *conn)
{
	conn->handler = finish_response;
	return conn->read.handler(conn, conn->buf, conn->read.size);
}

static CONN_STATUS
read_astring(CONN *conn, read_handler_t handler)
{
	char *p = conn->cmdp;
	CONN_STATUS status;
	char *string;
	size_t len;

	if (p == conn->cmdend)
		return conn_bad;
	else if (*p == '\"')
		status = read_quoted(conn, &string, &len);
	else if (*p == '{')
		return read_literal(conn, handler);
	else
		status = read_atom(conn, &string, &len);

	if (status != conn_ok)
		return status;
	return handler(conn, string, len);
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

/* If byname is non-zero, multiple symbols will be searched by name rather
 * than by symbol value (address).
 */
static CONN_STATUS
send_symbol(CONN *conn, struct syment *sp, int byname)
{
	conn->symbol.sp = sp;
	conn->symbol.modname = get_syment_module(sp);
	conn->symbol.byname = byname;
	conn->handler = send_symbol_data;
	conn->pfd.events = 0;
	return conn_ok;
}

static CONN_STATUS
send_symbol_data(CONN *conn)
{
	struct syment *sp = conn->symbol.sp;
	struct syment *nextsp = sp + 1;
	const char *nextmod = get_syment_module(nextsp);
	unsigned long addr = sp->value;
	unsigned long symsize = 0;
	CONN_STATUS status;

	if (nextmod)
		symsize = nextsp->value - sp->value;
	status = send_untagged(conn, conn_symbol,
			       "%lx %lx %c \"%s\" \"%s\"",
			       sp->value, symsize, sp->type,
			       sp->name, conn->symbol.modname);

	if (conn->symbol.byname) {
		nextsp = symbol_search_next(sp->name, sp);
		nextmod = nextsp ? get_syment_module(nextsp) : NULL;
	} else if (nextsp->value != addr)
		nextmod = NULL;

	if (status == conn_ok && nextmod) {
		conn->symbol.sp = nextsp;
		conn->symbol.modname = nextmod;
	} else
		conn->handler = finish_response;
	return status;
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

	disconnect(conn);
	return send_untagged(conn, conn_bye, "Closing connection");
}

static CONN_STATUS
do_TERMINATE(CONN *conn)
{
	if (conn->cmdp < conn->cmdend)
		return too_many_args(conn);

	for (conn = connections; conn; conn = conn->next)
		if (conn->term_state == conn_running)
			conn->term_state = conn_bye_pending;
	server_destroyall();

	return conn_ok;
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

	status = send_untagged(conn, conn_dump, "%lx {%lu}",
			       addr, (unsigned long) bytecnt);
	if (status == conn_ok) {
		size_t sz = write(conn->pfd.fd, buffer, bytecnt);
		if (sz != bytecnt)
			status = conn_fatal;
	}

	free(buffer);
	return status;
}

static CONN_STATUS SYMBOL_on_read(CONN *conn, char *tok, size_t len);

static CONN_STATUS
do_SYMBOL(CONN *conn)
{
	CONN_STATUS status;

	/* Get the symbol name */
	if ( (status = read_space(conn)) != conn_ok)
		return status;
	return read_astring(conn, SYMBOL_on_read);
}

static CONN_STATUS
SYMBOL_on_read(CONN *conn, char *tok, size_t len)
{
	CONN_STATUS status;

	if ((status = ensure_buffer(conn, len + 1)) != conn_ok)
		return set_response(conn, status, strerror(errno));
	if (tok != conn->buf) {
		memcpy(conn->buf, tok, len);
		tok = conn->buf;
	}
	tok[len] = 0;

	struct syment *sp = symbol_search(tok);
	if (!sp)
		return set_response(conn, conn_no, "Symbol not found");

	return send_symbol(conn, sp, 1);
}

static CONN_STATUS
do_ADDRESS(CONN *conn)
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

	return send_symbol(conn, sp, 0);
}

static CONN_STATUS
handle_rawio(CONN *conn, struct pollfd *pfd)
{
	ssize_t res;
	if (pfd->revents & POLLIN)
		res = read(pfd->fd, conn->iobuf, conn->iotodo);
	else if (pfd->revents & POLLOUT)
		res = write(pfd->fd, conn->iobuf, conn->iotodo);
	else
		return conn_bad;

	if (res < 0)
		return conn_fatal;
	if (!res)
		return conn_eof;
	conn->iobuf += res;
	conn->iotodo -= res;
	if (!conn->iotodo)
		conn->pfd.events = 0;

	return conn_ok;
}

static CONN_STATUS
handle_conn(CONN *conn, struct pollfd *pfd)
{
	CONN_STATUS status;

	if (pfd->revents & (POLLERR|POLLNVAL))
		status = conn_fatal;
	else if (pfd->revents & POLLHUP)
		status = conn_eof;
	else if (conn->iotodo)
		status = handle_rawio(conn, pfd);
	else
		status = conn->handler(conn);

	while (status == conn_ok && !conn->pfd.events && !check_bye(conn))
		status = conn->handler(conn);

	if (status == conn_fatal || status == conn_eof || conn->pfd.fd < 0)
		conn_done(conn);

	return conn_ok;
}

static int
handle_accept(struct pollfd *pfd)
{
	int sessfd = accept(pfd->fd, NULL, NULL);
	CONN *newconn;

	if (sessfd < 0) {
		report_error("Connection failed");
		return -1;
	}
	if (! (newconn = conn_init(sessfd)) ) {
		report_error("Connection init failed");
		return -1;
	}
	return 0;
}

static int
run_server_loop(struct pollfd **pfds)
{
	SERVER *srv;
	CONN *conn;
	int nfds;

	while ( (nfds = nconnections + nservers) != 0) {
		struct pollfd *fds =
			realloc(*pfds, nfds * sizeof(struct pollfd));
		if (!fds) {
			report_error("Cannot allocate poll FDs");
			return -1;
		}
		*pfds = fds;

		struct pollfd *pfd = *pfds;
		for (conn = connections; conn; conn = conn->next) {
			check_bye(conn);
			*pfd++ = conn->pfd;
		}
		for (srv = servers; srv; srv = srv->next)
			*pfd++ = srv->pfd;

		int todo = poll(*pfds, nfds, -1);
		if (todo < 0) {
			report_error("Poll failed");
			return -1;
		}

		conn = connections;
		for (pfd = *pfds; todo; ++pfd) {
			CONN *nconn = conn ? conn->next : NULL;
			if (pfd->revents) {
				--todo;
				if (conn)
					handle_conn(conn, pfd);
				else
					handle_accept(pfd);
			}
			conn = nconn;
		}
	}

	return 0;
}

static int
run_server(const char *path)
{
	struct pollfd *fds = NULL;

	if (!server_init(path))
		return -1;

	int ret = run_server_loop(&fds);
	if (fds)
		free(fds);

	server_destroyall();
	conn_destroyall();

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
