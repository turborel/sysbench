/* Copyright (C) 2026 Alex Gaetano Padula <me@alexpadula.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

/*
  A driver for turborel, speaking its native wire protocol (version 1) over
  TCP or a Unix socket, with no client library. Frames are a kind byte, a
  little-endian u32 body length, then the body. protocol/src/lib.rs in the
  turborel tree defines the format.

  turborel has no BEGIN and no autocommit: a transaction starts with its first
  statement, as in SQL-92, and lasts until COMMIT. sysbench expects BEGIN and
  autocommit, so this driver provides them. BEGIN sends SET TRANSACTION with
  the level of --turborel-isolation, so a transaction costs the same round
  trip it costs on other servers. A statement outside BEGIN asks the server
  to end the transaction with it (the request's last byte), so it costs one
  round trip and one reply too.

  TLS and SCRAM are not implemented. Without a password the driver logs in by
  trust, which needs SERVER.TRUST_LOCAL = ON. With one it sends the password
  whole, which the server takes only over a Unix socket.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#endif
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "sb_options.h"
#include "db_driver.h"

#define xfree(ptr) ({ if (ptr) free((void *)ptr); ptr = NULL; })

#define TB_VERSION 1
#define TB_HEADER 5
#define TB_KEY_BYTES 16
/* Replies this size or smaller are read in one call */
#define TB_READ_BYTES 65536
/* The longest text of an exact or approximate value, with its terminator */
#define TB_NUMBER_TEXT 64

/* Request kinds */
#define TB_HELLO 'H'
#define TB_QUERY 'Q'
#define TB_PREPARE 'P'
#define TB_EXECUTE 'E'
#define TB_DEALLOCATE 'D'
#define TB_TERMINATE 'X'

/* Reply kinds */
#define TB_R_CHALLENGE 'C'
#define TB_R_READY 'R'
#define TB_R_PREPARED 'P'
#define TB_R_DESCRIPTION 'D'
#define TB_R_ROWS 'B'
#define TB_R_SUSPENDED 'S'
#define TB_R_COMPLETE 'K'
#define TB_R_ERROR 'E'

/* Value tags */
#define TB_NULL 0
#define TB_CHARACTER 1
#define TB_EXACT 2
#define TB_APPROXIMATE 3

/* SQLCODE of a statement that found no rows */
#define TB_NO_DATA 100

/* The statement numbers this driver keeps for itself */
#define TB_STMT_COMMIT 1
#define TB_STMT_ROLLBACK 2
#define TB_STMT_BEGIN 3
#define TB_STMT_FIRST 4

static sb_arg_t turborel_drv_args[] =
{
  SB_OPT("turborel-host", "turborel server host", "127.0.0.1", STRING),
  SB_OPT("turborel-port", "turborel server port", "7422", INT),
  SB_OPT("turborel-socket", "turborel server Unix socket, used in place of "
         "the host and port if set", "", STRING),
  SB_OPT("turborel-user", "turborel user", "SBTEST", STRING),
  SB_OPT("turborel-password", "turborel password, sent over a Unix socket "
         "only. Without one the server must have SERVER.TRUST_LOCAL = ON", "",
         STRING),
  SB_OPT("turborel-isolation", "isolation level each transaction runs at",
         "READ COMMITTED", STRING),

  SB_OPT_END
};

typedef struct
{
  char *host;
  char *port;
  char *socket;
  char *user;
  char *password;
  char *begin;
} turborel_drv_args_t;

/* What a statement is, which decides what the driver does around it */
typedef enum
{
  TB_KIND_OTHER,
  TB_KIND_QUERY,
  TB_KIND_WRITE,
  TB_KIND_BEGIN,
  TB_KIND_COMMIT,
  TB_KIND_ROLLBACK
} tb_kind_t;

/* A growing byte buffer */
typedef struct
{
  uint8_t *data;
  size_t  len;
  size_t  cap;
} tb_buf_t;

/* A bounded read of a body. ok turns false once it runs past the end */
typedef struct
{
  const uint8_t *p;
  const uint8_t *end;
  int           ok;
} tb_reader_t;

/* The rows of a result, as the server sent them */
typedef struct
{
  tb_buf_t      rows;        /* Bodies of the Rows frames, one after another */
  tb_reader_t   at;          /* Where fetch_row reads next */
  uint32_t      frame_left;  /* Rows left in the frame fetch_row is in */
  char          *text;       /* Text of the numbers of the row fetched */
} tb_result_t;

typedef struct
{
  int           fd;
  uint32_t      next_stmt;
  int           in_tx;      /* Between BEGIN and COMMIT or ROLLBACK */
  tb_buf_t      out;        /* The requests of one write */
  uint8_t       *in;        /* Bytes read and not yet taken */
  size_t        in_at;
  size_t        in_len;
  size_t        in_cap;
  tb_result_t   result;
} tb_conn_t;

typedef struct
{
  uint32_t  id;
  tb_kind_t kind;
} tb_stmt_t;

static turborel_drv_args_t args;
static char use_ps;

static drv_caps_t turborel_drv_caps =
{
  1,    /* multi_rows_insert */
  1,    /* prepared_statements */
  0,    /* auto_increment */
  0,    /* needs_commit */
  0,    /* serial */
  0,    /* unsigned int */
};

static int turborel_drv_init(void);
static int turborel_drv_describe(drv_caps_t *);
static int turborel_drv_connect(db_conn_t *);
static int turborel_drv_disconnect(db_conn_t *);
static int turborel_drv_reconnect(db_conn_t *);
static int turborel_drv_prepare(db_stmt_t *, const char *, size_t);
static int turborel_drv_bind_param(db_stmt_t *, db_bind_t *, size_t);
static int turborel_drv_bind_result(db_stmt_t *, db_bind_t *, size_t);
static db_error_t turborel_drv_execute(db_stmt_t *, db_result_t *);
static int turborel_drv_fetch(db_result_t *);
static int turborel_drv_fetch_row(db_result_t *, db_row_t *);
static db_error_t turborel_drv_query(db_conn_t *, const char *, size_t,
                                     db_result_t *);
static int turborel_drv_free_results(db_result_t *);
static int turborel_drv_close(db_stmt_t *);
static int turborel_drv_done(void);

static db_driver_t turborel_driver =
{
  .sname = "turborel",
  .lname = "turborel driver",
  .args = turborel_drv_args,
  .ops =
  {
    .init = turborel_drv_init,
    .describe = turborel_drv_describe,
    .connect = turborel_drv_connect,
    .disconnect = turborel_drv_disconnect,
    .reconnect = turborel_drv_reconnect,
    .prepare = turborel_drv_prepare,
    .bind_param = turborel_drv_bind_param,
    .bind_result = turborel_drv_bind_result,
    .execute = turborel_drv_execute,
    .fetch = turborel_drv_fetch,
    .fetch_row = turborel_drv_fetch_row,
    .free_results = turborel_drv_free_results,
    .close = turborel_drv_close,
    .query = turborel_drv_query,
    .done = turborel_drv_done
  }
};

int register_driver_turborel(sb_list_t *drivers)
{
  SB_LIST_ADD_TAIL(&turborel_driver.listitem, drivers);

  return 0;
}

/* Encoding */

static int buf_reserve(tb_buf_t *b, size_t more)
{
  size_t  cap;
  uint8_t *data;

  if (b->len + more <= b->cap)
    return 0;

  cap = (b->cap > 0) ? b->cap : 4096;
  while (cap < b->len + more)
    cap *= 2;

  data = realloc(b->data, cap);
  if (data == NULL)
    return 1;

  b->data = data;
  b->cap = cap;

  return 0;
}

static int put_bytes(tb_buf_t *b, const void *data, size_t len)
{
  if (buf_reserve(b, len))
    return 1;

  memcpy(b->data + b->len, data, len);
  b->len += len;

  return 0;
}

static int put_u8(tb_buf_t *b, uint8_t v)
{
  return put_bytes(b, &v, 1);
}

static int put_u32(tb_buf_t *b, uint32_t v)
{
  const uint8_t le[4] = {
    (uint8_t) v, (uint8_t) (v >> 8), (uint8_t) (v >> 16), (uint8_t) (v >> 24)
  };

  return put_bytes(b, le, sizeof(le));
}

static int put_u64(tb_buf_t *b, uint64_t v)
{
  return put_u32(b, (uint32_t) v) || put_u32(b, (uint32_t) (v >> 32));
}

/* Strings and byte strings are their length, then their bytes */
static int put_str(tb_buf_t *b, const char *s, size_t len)
{
  return put_u32(b, (uint32_t) len) || put_bytes(b, s, len);
}

/* An exact value of scale 0: its units, an i128, then the scale */
static int put_exact(tb_buf_t *b, int64_t v)
{
  return put_u8(b, TB_EXACT) || put_u64(b, (uint64_t) v) ||
    put_u64(b, (v < 0) ? UINT64_MAX : 0) || put_u32(b, 0);
}

/* Starts a frame, and returns where its length goes */
static size_t frame_begin(tb_buf_t *b, uint8_t kind)
{
  size_t at;

  put_u8(b, kind);
  at = b->len;
  put_u32(b, 0);

  return at;
}

static void frame_end(tb_buf_t *b, size_t at)
{
  const uint32_t len = (uint32_t) (b->len - at - 4);

  b->data[at] = (uint8_t) len;
  b->data[at + 1] = (uint8_t) (len >> 8);
  b->data[at + 2] = (uint8_t) (len >> 16);
  b->data[at + 3] = (uint8_t) (len >> 24);
}

/* Decoding */

static const uint8_t *take(tb_reader_t *r, size_t len)
{
  const uint8_t *p = r->p;

  if (!r->ok || (size_t) (r->end - r->p) < len)
  {
    r->ok = 0;
    return NULL;
  }
  r->p += len;

  return p;
}

static uint8_t take_u8(tb_reader_t *r)
{
  const uint8_t *p = take(r, 1);

  return (p != NULL) ? p[0] : 0;
}

static uint32_t take_u32(tb_reader_t *r)
{
  const uint8_t *p = take(r, 4);

  if (p == NULL)
    return 0;

  return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
    ((uint32_t) p[3] << 24);
}

static uint64_t take_u64(tb_reader_t *r)
{
  const uint64_t low = take_u32(r);

  return low | ((uint64_t) take_u32(r) << 32);
}

static const char *take_str(tb_reader_t *r, uint32_t *len)
{
  *len = take_u32(r);

  return (const char *) take(r, *len);
}

/* Reading and writing the socket */

static int send_all(tb_conn_t *c)
{
  size_t at = 0;

  while (at < c->out.len)
  {
    const ssize_t n = send(c->fd, c->out.data + at, c->out.len - at,
                           MSG_NOSIGNAL);
    if (n < 0)
    {
      if (errno == EINTR)
        continue;
      log_errno(LOG_FATAL, "send() to the turborel server failed");
      c->out.len = 0;
      return 1;
    }
    at += (size_t) n;
  }
  c->out.len = 0;

  return 0;
}

/* Makes the next want bytes readable at c->in + c->in_at */
static int receive(tb_conn_t *c, size_t want)
{
  if (c->in_cap - c->in_at < want)
  {
    memmove(c->in, c->in + c->in_at, c->in_len);
    c->in_at = 0;
    if (c->in_cap < want)
    {
      uint8_t *in = realloc(c->in, want);

      if (in == NULL)
        return 1;
      c->in = in;
      c->in_cap = want;
    }
  }

  while (c->in_len < want)
  {
    const size_t  end = c->in_at + c->in_len;
    const ssize_t n = recv(c->fd, c->in + end, c->in_cap - end, 0);

    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
    {
      log_text(LOG_FATAL, "the turborel server closed the connection");
      return 1;
    }
    c->in_len += (size_t) n;
  }

  return 0;
}

/* Reads a frame. Its body is good until the next call */
static int read_frame(tb_conn_t *c, uint8_t *kind, tb_reader_t *body)
{
  tb_reader_t header;
  uint32_t    len;

  if (receive(c, TB_HEADER))
    return 1;

  header.p = c->in + c->in_at;
  header.end = header.p + TB_HEADER;
  header.ok = 1;
  *kind = take_u8(&header);
  len = take_u32(&header);

  if (receive(c, TB_HEADER + (size_t) len))
    return 1;

  body->p = c->in + c->in_at + TB_HEADER;
  body->end = body->p + len;
  body->ok = 1;
  c->in_at += TB_HEADER + (size_t) len;
  c->in_len -= TB_HEADER + (size_t) len;

  return 0;
}

/* Failures */

/* Keeps a failure's body on the connection, for sysbench to report */
static void note_failure(db_conn_t *con, tb_reader_t *r)
{
  uint32_t   len;
  const char *s;

  con->sql_errno = (int32_t) take_u32(r);

  xfree(con->sql_state);
  xfree(con->sql_errmsg);

  s = take_str(r, &len);
  con->sql_state = (s != NULL) ? strndup(s, len) : strdup("");
  s = take_str(r, &len);
  con->sql_errmsg = (s != NULL) ? strndup(s, len) : strdup("");
}

/*
  The failures a transaction is run again after. TB911 and 40001 are
  conflicts with another transaction. 23000 is every integrity failure, of
  which sysbench's own statements can break only a unique key, as two threads
  insert one id; the pgsql driver takes unique violations as ignorable too.
*/
static int is_ignorable(const char *state)
{
  return state != NULL && (!strcmp(state, "TB911") ||
                           !strcmp(state, "40001") ||
                           !strcmp(state, "23000"));
}

/* Reading replies */

/* Reads a reply of one frame: the frame of the kind wanted, or an error */
static int read_simple(db_conn_t *con, uint8_t wanted, tb_reader_t *body)
{
  tb_conn_t *c = con->ptr;
  uint8_t   kind;

  if (read_frame(c, &kind, body))
    return 1;

  if (kind == wanted)
    return 0;

  if (kind == TB_R_ERROR)
    note_failure(con, body);
  else
    log_text(LOG_FATAL, "unexpected reply '%c' from the turborel server", kind);

  return 1;
}

/* Reads the reply to a statement that cannot give rows */
static int read_complete(db_conn_t *con)
{
  tb_reader_t body;

  return read_simple(con, TB_R_COMPLETE, &body);
}

/*
  Reads the reply to a statement that may give rows. rows and nfields are its
  results, and sqlcode the SQLCODE of its completion. is_query says on entry
  whether a prepared statement is a query, whose rows come with no
  Description (its columns came with Prepared): their count is then read
  from the first row.
*/
static db_error_t read_reply(db_conn_t *con, int *sqlcode, uint32_t *rows,
                             uint32_t *nfields, int *is_query)
{
  tb_conn_t   *c = con->ptr;
  tb_reader_t body;
  tb_reader_t first;
  uint32_t    in_frame;
  uint8_t     kind;

  *rows = 0;
  *nfields = 0;

  for (;;)
  {
    if (read_frame(c, &kind, &body))
      return DB_ERROR_FATAL;

    switch (kind) {
      case TB_R_DESCRIPTION:
        *nfields = take_u32(&body);
        *is_query = 1;
        break;

      case TB_R_ROWS:
        in_frame = take_u32(&body);
        *rows += in_frame;
        if (*nfields == 0 && in_frame > 0)
        {
          first = body;
          *nfields = take_u32(&first);
        }
        body.p -= 4;
        if (put_bytes(&c->result.rows, body.p, (size_t) (body.end - body.p)))
          return DB_ERROR_FATAL;
        break;

      case TB_R_COMPLETE:
        *sqlcode = (int32_t) take_u32(&body);
        return DB_ERROR_NONE;

      case TB_R_ERROR:
        note_failure(con, &body);
        return DB_ERROR_IGNORABLE;

      case TB_R_SUSPENDED:
      default:
        log_text(LOG_FATAL, "unexpected reply '%c' from the turborel server",
                 kind);
        return DB_ERROR_FATAL;
    }
  }
}

/* Connecting */

static int open_socket(void)
{
  struct addrinfo hints;
  struct addrinfo *found;
  struct addrinfo *a;
  int             fd = -1;
  int             rc;

  if (args.socket[0] != '\0')
  {
    struct sockaddr_un un;

    if (strlen(args.socket) >= sizeof(un.sun_path))
    {
      log_text(LOG_FATAL, "the socket path is too long: %s", args.socket);
      return -1;
    }

    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, args.socket);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
      return -1;

    if (connect(fd, (struct sockaddr *) &un, sizeof(un)))
    {
      log_errno(LOG_FATAL, "cannot connect to %s", args.socket);
      close(fd);
      return -1;
    }

    return fd;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo(args.host, args.port, &hints, &found);
  if (rc != 0)
  {
    log_text(LOG_FATAL, "cannot resolve %s: %s", args.host, gai_strerror(rc));
    return -1;
  }

  for (a = found; a != NULL; a = a->ai_next)
  {
    fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (fd < 0)
      continue;

    if (connect(fd, a->ai_addr, a->ai_addrlen) == 0)
    {
      const int on = 1;

      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(found);

  if (fd < 0)
    log_text(LOG_FATAL, "cannot connect to %s:%s", args.host, args.port);

  return fd;
}

static int login(db_conn_t *con)
{
  tb_conn_t   *c = con->ptr;
  const char  *mechanism = (args.password[0] != '\0') ? "password" : "trust";
  size_t      at;
  tb_reader_t body;
  uint8_t     kind;

  at = frame_begin(&c->out, TB_HELLO);
  put_u32(&c->out, TB_VERSION);
  put_str(&c->out, args.user, strlen(args.user));
  put_str(&c->out, mechanism, strlen(mechanism));
  put_str(&c->out, args.password, strlen(args.password));
  put_u32(&c->out, 0);          /* capabilities */
  frame_end(&c->out, at);

  if (send_all(c) || read_frame(c, &kind, &body))
    return 1;

  if (kind == TB_R_ERROR)
  {
    note_failure(con, &body);
    log_text(LOG_FATAL, "login to turborel failed: %s", con->sql_errmsg);
    return 1;
  }
  if (kind == TB_R_CHALLENGE)
  {
    log_text(LOG_FATAL, "the server asked for a login this driver cannot give");
    return 1;
  }
  if (kind != TB_R_READY)
  {
    log_text(LOG_FATAL, "unexpected reply '%c' to login", kind);
    return 1;
  }

  return 0;
}

static void put_prepare(tb_conn_t *c, uint32_t id, const char *sql, size_t len)
{
  const size_t at = frame_begin(&c->out, TB_PREPARE);

  put_u32(&c->out, id);
  put_str(&c->out, sql, len);
  frame_end(&c->out, at);
}

/* Prepares a statement of the driver's own */
static int prepare_own(db_conn_t *con, uint32_t id, const char *sql)
{
  tb_reader_t body;

  put_prepare(con->ptr, id, sql, strlen(sql));

  if (send_all(con->ptr) || read_simple(con, TB_R_PREPARED, &body))
  {
    log_text(LOG_FATAL, "cannot prepare %s: %s", sql,
             (con->sql_errmsg != NULL) ? con->sql_errmsg : "connection lost");
    return 1;
  }

  return 0;
}

static void conn_free(tb_conn_t *c)
{
  if (c->fd >= 0)
    close(c->fd);
  free(c->out.data);
  free(c->in);
  free(c->result.rows.data);
  free(c->result.text);
  free(c);
}

/* An option's text. Options left empty have none, which is read as "" */
static char *option_text(const char *name)
{
  char *text = sb_get_value_string(name);

  return (text != NULL) ? text : "";
}

int turborel_drv_init(void)
{
  const char *isolation = sb_get_value_string("turborel-isolation");

  args.host = sb_get_value_string("turborel-host");
  args.port = sb_get_value_string("turborel-port");
  args.socket = option_text("turborel-socket");
  args.user = sb_get_value_string("turborel-user");
  args.password = option_text("turborel-password");

  args.begin = malloc(strlen("SET TRANSACTION ISOLATION LEVEL ") +
                      strlen(isolation) + 1);
  if (args.begin == NULL)
    return 1;
  sprintf(args.begin, "SET TRANSACTION ISOLATION LEVEL %s", isolation);

  use_ps = (db_globals.ps_mode != DB_PS_MODE_DISABLE);

  return 0;
}

int turborel_drv_describe(drv_caps_t *caps)
{
  db_conn_t con;

  *caps = turborel_drv_caps;

  memset(&con, 0, sizeof(con));
  if (turborel_drv_connect(&con))
    return 1;

  return turborel_drv_disconnect(&con);
}

int turborel_drv_connect(db_conn_t *sb_conn)
{
  tb_conn_t *c;

  c = calloc(1, sizeof(tb_conn_t));
  if (c == NULL)
    return 1;

  c->next_stmt = TB_STMT_FIRST;
  c->in_cap = TB_READ_BYTES;
  c->in = malloc(c->in_cap);
  c->fd = open_socket();
  sb_conn->ptr = c;

  if (c->in == NULL || c->fd < 0 || login(sb_conn) ||
      prepare_own(sb_conn, TB_STMT_COMMIT, "COMMIT") ||
      prepare_own(sb_conn, TB_STMT_ROLLBACK, "ROLLBACK") ||
      prepare_own(sb_conn, TB_STMT_BEGIN, args.begin))
  {
    conn_free(c);
    sb_conn->ptr = NULL;
    return 1;
  }

  return 0;
}

int turborel_drv_disconnect(db_conn_t *sb_conn)
{
  tb_conn_t *c = sb_conn->ptr;

  xfree(sb_conn->sql_state);
  xfree(sb_conn->sql_errmsg);

  if (c != NULL)
  {
    frame_end(&c->out, frame_begin(&c->out, TB_TERMINATE));
    send_all(c);
    conn_free(c);
    sb_conn->ptr = NULL;
  }

  return 0;
}

int turborel_drv_reconnect(db_conn_t *sb_conn)
{
  if (turborel_drv_disconnect(sb_conn))
    return DB_ERROR_FATAL;

  while (turborel_drv_connect(sb_conn))
  {
    if (sb_globals.error)
      return DB_ERROR_FATAL;
  }

  return DB_ERROR_IGNORABLE;
}

/* Statements */

static int starts_with(const char *sql, const char *word)
{
  const size_t len = strlen(word);

  return !strncasecmp(sql, word, len) &&
    (sql[len] == '\0' || sql[len] == ' ' || sql[len] == '\n' ||
     sql[len] == '\t' || sql[len] == ';');
}

static tb_kind_t kind_of(const char *sql)
{
  while (*sql == ' ' || *sql == '\n' || *sql == '\t')
    sql++;

  if (starts_with(sql, "BEGIN"))
    return TB_KIND_BEGIN;
  if (starts_with(sql, "COMMIT"))
    return TB_KIND_COMMIT;
  if (starts_with(sql, "ROLLBACK"))
    return TB_KIND_ROLLBACK;
  if (starts_with(sql, "INSERT") || starts_with(sql, "UPDATE") ||
      starts_with(sql, "DELETE"))
    return TB_KIND_WRITE;
  if (starts_with(sql, "SELECT"))
    return TB_KIND_QUERY;

  return TB_KIND_OTHER;
}

int turborel_drv_prepare(db_stmt_t *stmt, const char *query, size_t len)
{
  db_conn_t   *con = stmt->connection;
  tb_conn_t   *c = con->ptr;
  tb_stmt_t   *ts;
  tb_reader_t body;

  if (c == NULL)
    return 1;

  if (!use_ps)
  {
    stmt->emulated = 1;
    stmt->query = strdup(query);
    return 0;
  }

  ts = malloc(sizeof(tb_stmt_t));
  if (ts == NULL)
    return 1;

  ts->kind = kind_of(query);

  switch (ts->kind) {
    case TB_KIND_BEGIN:
      ts->id = TB_STMT_BEGIN;
      break;

    case TB_KIND_COMMIT:
      ts->id = TB_STMT_COMMIT;
      break;

    case TB_KIND_ROLLBACK:
      ts->id = TB_STMT_ROLLBACK;
      break;

    case TB_KIND_WRITE:
    case TB_KIND_QUERY:
    case TB_KIND_OTHER:
      ts->id = c->next_stmt++;
      put_prepare(c, ts->id, query, len);

      if (send_all(c) || read_simple(con, TB_R_PREPARED, &body))
      {
        log_text(LOG_FATAL, "cannot prepare %s: %s", query,
                 (con->sql_errmsg != NULL) ? con->sql_errmsg :
                 "connection lost");
        free(ts);
        return 1;
      }
      break;
  }

  stmt->query = strdup(query);
  stmt->ptr = ts;

  return 0;
}

int turborel_drv_bind_param(db_stmt_t *stmt, db_bind_t *params, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
  {
    switch (params[i].type) {
      case DB_TYPE_TINYINT:
      case DB_TYPE_SMALLINT:
      case DB_TYPE_INT:
      case DB_TYPE_BIGINT:
      case DB_TYPE_FLOAT:
      case DB_TYPE_DOUBLE:
      case DB_TYPE_CHAR:
      case DB_TYPE_VARCHAR:
        break;

      case DB_TYPE_NONE:
      case DB_TYPE_DATETIME:
      case DB_TYPE_TIMESTAMP:
      case DB_TYPE_DATE:
      case DB_TYPE_TIME:
      default:
        if (!stmt->emulated)
        {
          log_text(LOG_FATAL, "this parameter's type is not supported");
          return 1;
        }
    }
  }

  if (stmt->bound_param != NULL)
    free(stmt->bound_param);
  stmt->bound_param = malloc(len * sizeof(db_bind_t));
  if (stmt->bound_param == NULL)
    return 1;
  memcpy(stmt->bound_param, params, len * sizeof(db_bind_t));
  stmt->bound_param_len = len;

  return 0;
}

int turborel_drv_bind_result(db_stmt_t *stmt, db_bind_t *params, size_t len)
{
  (void) stmt;
  (void) params;
  (void) len;

  return 0;
}

static int put_value(tb_buf_t *b, const db_bind_t *v)
{
  if (v->is_null != NULL && *v->is_null)
    return put_u8(b, TB_NULL);

  switch (v->type) {
    case DB_TYPE_TINYINT:
      return put_exact(b, *(signed char *) v->buffer);
    case DB_TYPE_SMALLINT:
      return put_exact(b, *(short *) v->buffer);
    case DB_TYPE_INT:
      return put_exact(b, *(int *) v->buffer);
    case DB_TYPE_BIGINT:
      return put_exact(b, *(long long *) v->buffer);
    case DB_TYPE_FLOAT:
    case DB_TYPE_DOUBLE:
    {
      const double d = (v->type == DB_TYPE_FLOAT) ?
        (double) *(float *) v->buffer : *(double *) v->buffer;
      uint64_t bits;

      memcpy(&bits, &d, sizeof(bits));
      return put_u8(b, TB_APPROXIMATE) || put_u64(b, bits);
    }
    case DB_TYPE_CHAR:
    case DB_TYPE_VARCHAR:
      return put_u8(b, TB_CHARACTER) ||
        put_str(b, v->buffer, v->data_len[0]);
    case DB_TYPE_NONE:
    case DB_TYPE_DATETIME:
    case DB_TYPE_TIMESTAMP:
    case DB_TYPE_DATE:
    case DB_TYPE_TIME:
    default:
      return 1;
  }
}

/*
  Requests the execution of a prepared statement, of all its rows; the
  transaction ended with it if ends
*/
static int put_execute(tb_conn_t *c, uint32_t id, const db_bind_t *values,
                       size_t count, int ends)
{
  const size_t at = frame_begin(&c->out, TB_EXECUTE);
  size_t       i;

  put_u32(&c->out, id);
  put_u32(&c->out, (uint32_t) count);
  for (i = 0; i < count; i++)
    if (put_value(&c->out, values + i))
      return 1;
  put_u32(&c->out, 0);
  put_u8(&c->out, (uint8_t) (ends != 0));
  frame_end(&c->out, at);

  return 0;
}

/* Whether a statement of kind outside BEGIN ends its transaction with it */
static int ends_with(const tb_conn_t *c, tb_kind_t kind)
{
  return !c->in_tx && kind != TB_KIND_COMMIT && kind != TB_KIND_ROLLBACK;
}

/* Rolls back after a failure, and ends the transaction it was in */
static int rollback(db_conn_t *con)
{
  tb_conn_t *c = con->ptr;

  c->in_tx = 0;

  return put_execute(c, TB_STMT_ROLLBACK, NULL, 0, 0) || send_all(c) ||
    read_complete(con);
}

/* Sets rs from a statement's outcome, and says what sysbench should do next */
static db_error_t finish(db_conn_t *con, db_result_t *rs, tb_kind_t kind,
                         const char *query, const char *function)
{
  tb_conn_t  *c = con->ptr;
  int        sqlcode = 0;
  int        is_query = (kind == TB_KIND_QUERY);
  uint32_t   rows;
  uint32_t   nfields;
  db_error_t rc;

  rc = read_reply(con, &sqlcode, &rows, &nfields, &is_query);

  if (rc == DB_ERROR_NONE)
  {
    rs->nrows = is_query ? rows : (sqlcode == 0);
    rs->nfields = nfields;

    if (is_query)
    {
      rs->counter = SB_CNT_READ;
      rs->ptr = &c->result;
      c->result.at.p = c->result.rows.data;
      c->result.at.end = c->result.rows.data + c->result.rows.len;
      c->result.at.ok = 1;
      c->result.frame_left = 0;
    }
    else
    {
      rs->counter = (kind == TB_KIND_WRITE && sqlcode != TB_NO_DATA) ?
        SB_CNT_WRITE : SB_CNT_OTHER;
      rs->ptr = NULL;
    }

    return DB_ERROR_NONE;
  }

  rs->nrows = 0;
  rs->counter = SB_CNT_ERROR;
  rs->ptr = NULL;
  c->result.rows.len = 0;

  if (rc == DB_ERROR_FATAL)
    return rc;

  if (is_ignorable(con->sql_state))
    return rollback(con) ? DB_ERROR_FATAL : DB_ERROR_IGNORABLE;

  log_text(LOG_FATAL, "%s() failed: SQLCODE %d (SQLSTATE %s): %s", function,
           con->sql_errno, con->sql_state, con->sql_errmsg);
  if (query != NULL)
    log_text(LOG_FATAL, "failed query was: %s", query);

  return DB_ERROR_FATAL;
}

/* What each kind of statement does to the connection's transaction */
static void note_transaction(tb_conn_t *c, tb_kind_t kind)
{
  if (kind == TB_KIND_BEGIN)
    c->in_tx = 1;
  else if (kind == TB_KIND_COMMIT || kind == TB_KIND_ROLLBACK)
    c->in_tx = 0;
}

static void clear_failure(db_conn_t *con)
{
  con->sql_errno = 0;
  xfree(con->sql_state);
  xfree(con->sql_errmsg);
}

/*
  Executes a statement of the kinds the driver handles by number. A statement
  outside a transaction ends it with the statement, in one request.
*/
static db_error_t execute_numbered(db_stmt_t *stmt, db_result_t *rs)
{
  db_conn_t *con = stmt->connection;
  tb_conn_t *c = con->ptr;
  tb_stmt_t *ts = stmt->ptr;

  if (ts == NULL)
    return DB_ERROR_FATAL;

  note_transaction(c, ts->kind);

  if (put_execute(c, ts->id, stmt->bound_param,
                  (ts->kind == TB_KIND_WRITE || ts->kind == TB_KIND_QUERY ||
                   ts->kind == TB_KIND_OTHER) ? stmt->bound_param_len : 0,
                  ends_with(c, ts->kind)))
  {
    log_text(LOG_FATAL, "cannot encode a parameter");
    c->out.len = 0;
    return DB_ERROR_FATAL;
  }

  if (send_all(c))
    return DB_ERROR_FATAL;

  return finish(con, rs, ts->kind, NULL, "execute");
}

db_error_t turborel_drv_execute(db_stmt_t *stmt, db_result_t *rs)
{
  db_conn_t    *con = stmt->connection;
  char         *buf = NULL;
  unsigned int buflen = 0;
  unsigned int i, j, vcnt;
  char         need_realloc;
  int          n;
  db_error_t   rc;

  clear_failure(con);

  if (!stmt->emulated)
    return execute_numbered(stmt, rs);

  /* Client-side prepared statements: build the text from the parameters */
  need_realloc = 1;
  vcnt = 0;
  for (i = 0, j = 0; stmt->query[i] != '\0'; i++)
  {
  again:
    if (j + 1 >= buflen || need_realloc)
    {
      buflen = (buflen > 0) ? buflen * 2 : 256;
      buf = realloc(buf, buflen);
      if (buf == NULL)
        return DB_ERROR_FATAL;
      need_realloc = 0;
    }

    if (stmt->query[i] != '?')
    {
      buf[j++] = stmt->query[i];
      continue;
    }

    n = db_print_value(stmt->bound_param + vcnt, buf + j, buflen - j);
    if (n < 0)
    {
      need_realloc = 1;
      goto again;
    }
    j += n;
    vcnt++;
  }
  buf[j] = '\0';

  rc = turborel_drv_query(con, buf, j, rs);

  free(buf);

  return rc;
}

db_error_t turborel_drv_query(db_conn_t *sb_conn, const char *query,
                              size_t len, db_result_t *rs)
{
  tb_conn_t       *c = sb_conn->ptr;
  const tb_kind_t kind = kind_of(query);
  size_t          at;

  clear_failure(sb_conn);
  note_transaction(c, kind);

  if (kind == TB_KIND_BEGIN)
  {
    put_execute(c, TB_STMT_BEGIN, NULL, 0, 0);
  }
  else
  {
    at = frame_begin(&c->out, TB_QUERY);
    put_str(&c->out, query, len);
    put_u8(&c->out, (uint8_t) (ends_with(c, kind) != 0));
    frame_end(&c->out, at);
  }

  if (send_all(c))
    return DB_ERROR_FATAL;

  return finish(sb_conn, rs, kind, query, "query");
}

/* Rows */

int turborel_drv_fetch(db_result_t *rs)
{
  (void) rs;

  return 1;
}

/* The text of an exact value: its units, with scale digits after a point */
static uint32_t exact_text(char *out, unsigned __int128 units, int negative,
                           uint32_t scale)
{
  char     digits[TB_NUMBER_TEXT];
  uint32_t count = 0;
  uint32_t len = 0;

  while (units > 0 || count <= scale)
  {
    digits[count++] = (char) ('0' + (int) (units % 10));
    units /= 10;
    if (count == TB_NUMBER_TEXT - 3)
      break;
  }

  if (negative)
    out[len++] = '-';

  while (count > 0)
  {
    if (count == scale)
      out[len++] = '.';
    out[len++] = digits[--count];
  }
  out[len] = '\0';

  return len;
}

/*
  Reads one value. Only the values sysbench's own tables hold are turned into
  text: strings, numbers and nulls.
*/
static int value_text(tb_reader_t *r, db_value_t *v, char *text)
{
  const uint8_t tag = take_u8(r);

  switch (tag) {
    case TB_NULL:
      v->ptr = NULL;
      v->len = 0;
      return 0;

    case TB_CHARACTER:
      v->ptr = take_str(r, &v->len);
      return !r->ok;

    case TB_EXACT:
    {
      const uint64_t    low = take_u64(r);
      const uint64_t    high = take_u64(r);
      const uint32_t    scale = take_u32(r);
      unsigned __int128 units = ((unsigned __int128) high << 64) | low;
      const int         negative = (high >> 63) != 0;

      if (negative)
        units = ~units + 1;
      v->len = exact_text(text, units, negative, scale);
      v->ptr = text;
      return !r->ok;
    }

    case TB_APPROXIMATE:
    {
      const uint64_t bits = take_u64(r);
      double         d;

      memcpy(&d, &bits, sizeof(d));
      v->len = (uint32_t) snprintf(text, TB_NUMBER_TEXT, "%.17g", d);
      v->ptr = text;
      return !r->ok;
    }

    default:
      log_text(LOG_FATAL, "this driver cannot read a value of tag %u", tag);
      return 1;
  }
}

int turborel_drv_fetch_row(db_result_t *rs, db_row_t *row)
{
  tb_result_t *result = rs->ptr;
  uint32_t    count;
  uint32_t    i;

  if (result == NULL)
    return DB_ERROR_IGNORABLE;

  if (result->frame_left == 0)
  {
    if (result->at.p >= result->at.end)
      return DB_ERROR_IGNORABLE;
    result->frame_left = take_u32(&result->at);
    if (result->frame_left == 0)
      return turborel_drv_fetch_row(rs, row);
  }

  if (result->text == NULL)
  {
    result->text = malloc((size_t) rs->nfields * TB_NUMBER_TEXT);
    if (result->text == NULL)
      return DB_ERROR_FATAL;
  }

  count = take_u32(&result->at);
  for (i = 0; i < rs->nfields && i < count; i++)
    if (value_text(&result->at, &row->values[i],
                   result->text + (size_t) i * TB_NUMBER_TEXT))
      return DB_ERROR_FATAL;

  result->frame_left--;

  return result->at.ok ? DB_ERROR_NONE : DB_ERROR_FATAL;
}

int turborel_drv_free_results(db_result_t *rs)
{
  tb_result_t *result = rs->ptr;

  if (result == NULL)
    return 1;

  result->rows.len = 0;
  xfree(result->text);
  rs->ptr = NULL;
  rs->row.ptr = NULL;

  return 0;
}

int turborel_drv_close(db_stmt_t *stmt)
{
  db_conn_t *con = stmt->connection;
  tb_conn_t *c = con->ptr;
  tb_stmt_t *ts = stmt->ptr;
  size_t    at;
  int       rc = 0;

  if (ts == NULL)
    return stmt->emulated ? 0 : 1;

  /* The driver's own statements outlive those sysbench closes */
  if (c != NULL && ts->id >= TB_STMT_FIRST)
  {
    at = frame_begin(&c->out, TB_DEALLOCATE);
    put_u32(&c->out, ts->id);
    frame_end(&c->out, at);
    rc = send_all(c) || read_complete(con);
  }

  xfree(stmt->ptr);

  return rc;
}

int turborel_drv_done(void)
{
  free(args.begin);
  args.begin = NULL;

  return 0;
}
