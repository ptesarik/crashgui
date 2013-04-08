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
	conn_eof,		/* End of stream */

	conn_fatal = -1		/* Fatal error */
} CONN_STATUS;

typedef enum session_status {
	session_normal,		/* Normal session end */
	session_terminate,	/* TERMINATE command was used */
	session_error,		/* A (local) error occured */
} SESSION_STATUS;

typedef struct conn {
	/* input and output streams */
	FILE *fin, *fout;

	enum conn_status status;
	const struct proto_command *lastcmd;

	/* current input line */
	char *line;
	size_t linealloc;
	size_t linelen;

	/* current tag */
	char *tag;
	size_t tagalloc;
	size_t taglen;

	/* current command */
	char *cmd;
	size_t cmdalloc;
	size_t cmdlen;

	/* current response */
	char *resp;
	size_t respalloc;
	size_t resplen;

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

#define DEFINE_CMD(name)	{ (sizeof(#name) - 1), (#name), (do_ ## name) }

static const struct proto_command cmds[] = {
	DEFINE_CMD(DISCONNECT),
	DEFINE_CMD(TERMINATE),
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

static CONN *
conn_init(FILE *fin, FILE *fout)
{
	CONN *ret = calloc(1, sizeof(struct conn));
	if (ret) {
		ret->fin = fin;
		ret->fout = fout;

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
	if (conn->fin)
		fclose(conn->fin);
	if (conn->fout)
		fclose(conn->fout);
	if (conn->line)
		free(conn->line);
	if (conn->tag)
		free(conn->tag);
	if (conn->cmd)
		free(conn->cmd);
	if (conn->resp)
		free(conn->resp);
	free (conn);
}

static CONN_STATUS
do_getcommand(CONN * conn)
{
	if (!conn->fin)
		return conn_eof;

	ssize_t length = getline(&conn->line, &conn->linealloc, conn->fin);
	if (length <= 0)
		return ferror(conn->fin) ? conn_fatal : conn_eof;

	/* Every line must be terminated by a LF. */
	if (conn->line[--length] != '\n')
		return conn_eof;
	/* The protocol requires terminating lines with CRLF,
	 * but we're lenient on what we accept and also allow LF.
	 */
	if (length > 0 && conn->line[length-1] == '\r')
		conn->line[--length] = 0;
	conn->linelen = length;

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

	while (*p == ' ')
		++p;

	if (!copy_string(&conn->cmd, &conn->cmdalloc, p, endp - p))
		return conn_fatal;
	conn->cmdlen = endp - p;

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

	if (!conn->fout)
		return conn_fatal;

	size_t taglen = conn->taglen;
	if (tagged && taglen) {
		conn->taglen = 0;
		sz = fwrite(conn->tag, 1, taglen, conn->fout);
		if (sz != taglen)
			return conn_fatal;
	} else if (putc('*', conn->fout) < 0)
		return conn_fatal;

	if (putc(' ', conn->fout) < 0)
		return conn_fatal;

	const char *cond;
	switch (conn->status) {
	case conn_ok:	cond = "OK";  break;
	case conn_bad:	cond = "BAD"; break;
	case conn_no:	cond = "NO";  break;
	case conn_bye:	cond = "BYE"; break;
	case conn_dump:	cond = "DUMP"; break;
	default:	cond = "ERR"; break;
	}
	sz = fwrite(cond, 1, strlen(cond), conn->fout);
	if (sz != strlen(cond))
		return conn_fatal;

	size_t resplen = conn->resplen;
	if (resplen) {
		conn->resplen = 0;
		if (putc(' ', conn->fout) < 0)
			return conn_fatal;

		sz = fwrite(conn->resp, 1, resplen, conn->fout);
		if (sz != resplen)
			return conn_fatal;
	} else if (conn->status == conn_ok && conn->lastcmd) {
		if (putc(' ', conn->fout) < 0)
			return conn_fatal;

		size_t len = strlen(conn->lastcmd->name);
		sz = fwrite(conn->lastcmd->name, 1, len, conn->fout);
		if (sz != len)
			return conn_fatal;

		static const char msg[] = " completed";
		sz = fwrite(msg, 1, sizeof(msg) - 1, conn->fout);
		if (sz != sizeof(msg) - 1)
			return conn_fatal;
	}

	if (fwrite(crlf, 1, sizeof(crlf), conn->fout) != sizeof(crlf))
		return conn_fatal;

	return conn_ok;
}

static CONN_STATUS
conn_respond(CONN *conn, int tagged)
{
	CONN_STATUS ret = do_respond(conn, tagged);
	fflush(conn->fout);
	return ret;
}

static CONN_STATUS
run_command(CONN *conn)
{
	char *p = conn->cmd, *endp = p + conn->cmdlen;
	size_t len;
	while (p != endp && *p != ' ') {
		*p = toupper(*p);
		++p;
	}
	len = p - conn->cmd;

	conn->lastcmd = NULL;
	const struct proto_command *cp = cmds;
	while (cp->len) {
		if (cp->len == len && !memcmp(cp->name, conn->cmd, len)) {
			conn->lastcmd = cp;
			return conn->status = cp->handler(conn);
		}
		++cp;
	}

	static const char msg[] = "Unknown protocol command.";
	copy_string(&conn->resp, &conn->resplen, msg, sizeof(msg)-1);
	return conn->status = conn_bad;
}

static CONN_STATUS
send_untagged(CONN *conn, CONN_STATUS status, const char *msg)
{
	CONN_STATUS oldstatus = conn->status;
	conn->status = status;
	copy_string(&conn->resp, &conn->resplen, msg, strlen(msg));
	status = conn_respond(conn, 0);
	conn->status = (status == conn_fatal) ? status : oldstatus;
	return status;
}

static CONN_STATUS
disconnect(CONN *conn, const char *reason)
{
	if (fclose(conn->fin)) {
		char *err = strerror(errno);
		copy_string(&conn->resp, &conn->resplen, err, strlen(err));
		return conn_fatal;
	}

	conn->fin = NULL;
	return send_untagged(conn, conn_bye, reason);
}

static CONN_STATUS
do_DISCONNECT(CONN *conn)
{
	return disconnect(conn, "connection closing");
}

static CONN_STATUS
do_TERMINATE(CONN *conn)
{
	CONN_STATUS status = disconnect(conn, "terminating crashgui server");
	if (status == conn_ok)
		conn->terminate = 1;
	return status;
}

static SESSION_STATUS
run_session(FILE *fin, FILE *fout)
{
	CONN *conn;
	CONN_STATUS status;
	int terminate = 0;

	if (! (conn = conn_init(fin, fout)) )
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
	int fd, fdin;
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

	while ( (fdin = accept(fd, NULL, NULL)) >= 0) {
		int fdout;
		FILE *fin, *fout;

		if ( (fdout = dup(fdin)) < 0) {
			report_error("Cannot duplicate FD");
			close(fdin);
			continue;
		}
		if (! (fin = fdopen(fdin, "r")) ) {
			report_error("Cannot create input stream");
			close(fdout);
			close(fdin);
			continue;
		}
		if (! (fout = fdopen(fdout, "w")) ) {
			report_error("Cannot create output stream");
			fclose(fin);
			close(fdout);
			close(fdin);
			continue;
		}

		SESSION_STATUS status = run_session(fin, fout);
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

int main(int argc, char **argv)
{
	return run_server(argv[1]);
}
