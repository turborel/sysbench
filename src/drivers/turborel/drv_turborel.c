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
  little-endian u32 body length, then the body. doc/client/05-protocol.md
  in the turborel tree describes the protocol, and protocol/src defines it.

  The protocol grows by capabilities a client asks for in Hello. This driver
  asks for none, so every message it reads is in the protocol's first form,
  with an empty tail. None of them saves a round trip in sysbench's pattern
  of one statement at a time, and each adds bytes to the replies. Compressed
  frames would cost both sides more time than a benchmark's network saves.

  turborel has no BEGIN and no autocommit: a transaction starts with its first
  statement, as in SQL-92, and lasts until COMMIT. sysbench expects BEGIN and
  autocommit, so this driver provides them. BEGIN sends SET TRANSACTION with
  the level of --turborel-isolation, so a transaction costs the same round
  trip it costs on other servers. A statement outside BEGIN asks the server
  to end the transaction with it (the request's ends flag), so it costs one
  round trip and one reply too. A failure says whether the transaction is
  still active, and the driver rolls back only one that is.

  Without a password the driver logs in by trust, which needs
  SERVER.TRUST_LOCAL = ON. With one it uses SCRAM-SHA-256 (RFC 5802, RFC
  7677), which the server takes over a Unix socket, or over TCP where
  SERVER.SCRAM_WITHOUT_TLS = ON. Its keys are derived once and kept for the
  connections after, since each reconnect would otherwise run the whole
  PBKDF2 again. --turborel-mechanism=password sends the password whole
  instead, over a Unix socket only. TLS is not implemented.
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
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
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
/* Replies this size or smaller are read in one call */
#define TB_READ_BYTES 65536
/* The longest text of an exact or approximate value, with its terminator */
#define TB_NUMBER_TEXT 64
/* The deepest a constructed value is shown */
#define TB_DEPTH 32

/* Request kinds */
#define TB_HELLO 'H'
#define TB_ANSWER 'A'
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
#define TB_EXTENSION 4
#define TB_BINARY 6
#define TB_DATE 8
#define TB_TIME 9
#define TB_TIMESTAMP 11
#define TB_INTERVAL 13
#define TB_BOOLEAN 14
#define TB_DECFLOAT 15
#define TB_ARRAY 16
#define TB_ROW 17
#define TB_LOB_WHOLE 20
#define TB_LOB_LOCATOR 21
#define TB_MULTISET 22
#define TB_STRUCTURED 23
#define TB_REFERENCE 24
#define TB_JSON 25
#define TB_XML 26
#define TB_UUID 27

/* SQLCODE of a statement that found no rows */
#define TB_NO_DATA 100

/* The statement numbers this driver keeps for itself */
#define TB_STMT_COMMIT 1
#define TB_STMT_ROLLBACK 2
#define TB_STMT_BEGIN 3
#define TB_STMT_FIRST 4

/* SCRAM-SHA-256 */
#define TB_SCRAM "scram-sha-256"
#define TB_KEY 32
#define TB_NONCE_BYTES 18

static sb_arg_t turborel_drv_args[] =
{
  SB_OPT("turborel-host", "turborel server host", "127.0.0.1", STRING),
  SB_OPT("turborel-port", "turborel server port", "7422", INT),
  SB_OPT("turborel-socket", "turborel server Unix socket, used in place of "
         "the host and port if set", "", STRING),
  SB_OPT("turborel-user", "turborel user", "SBTEST", STRING),
  SB_OPT("turborel-password", "turborel password. Without one the server "
         "must have SERVER.TRUST_LOCAL = ON", "", STRING),
  SB_OPT("turborel-mechanism", "how to log in: trust, scram-sha-256 or "
         "password. By default trust without a password and scram-sha-256 "
         "with one", "", STRING),
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
  char *mechanism;
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
  tb_buf_t      text;        /* Text of the values of the row fetched */
  size_t        *text_at;    /* Where each field's text starts, or SIZE_MAX */
  uint32_t      text_fields; /* The fields text_at has room for */
} tb_result_t;

typedef struct
{
  int           fd;
  uint32_t      next_stmt;
  int           in_tx;      /* Between BEGIN and COMMIT or ROLLBACK */
  int           active;     /* The last failure left a transaction active */
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

  if (len > 0)
    memcpy(b->data + b->len, data, len);
  b->len += len;

  return 0;
}

static int put_text(tb_buf_t *b, const char *s)
{
  return put_bytes(b, s, strlen(s));
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
static int put_str(tb_buf_t *b, const void *s, size_t len)
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

/* SHA-256 (FIPS 180-4), HMAC (RFC 2104) and PBKDF2 (RFC 8018), for SCRAM */

typedef struct
{
  uint32_t h[8];
  uint8_t  block[64];
  size_t   fill;
  uint64_t total;
} tb_sha_t;

static const uint32_t sha_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_compress(tb_sha_t *s, const uint8_t *p)
{
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h;
  int      i;

  for (i = 0; i < 16; i++)
    w[i] = ((uint32_t) p[4 * i] << 24) | ((uint32_t) p[4 * i + 1] << 16) |
      ((uint32_t) p[4 * i + 2] << 8) | (uint32_t) p[4 * i + 3];
  for (i = 16; i < 64; i++)
  {
    const uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^
      (w[i - 15] >> 3);
    const uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^
      (w[i - 2] >> 10);

    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
  e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];

  for (i = 0; i < 64; i++)
  {
    const uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) +
      ((e & f) ^ (~e & g)) + sha_k[i] + w[i];
    const uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) +
      ((a & b) ^ (a & c) ^ (b & c));

    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
  s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(tb_sha_t *s)
{
  static const uint32_t start[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  memcpy(s->h, start, sizeof(start));
  s->fill = 0;
  s->total = 0;
}

static void sha_update(tb_sha_t *s, const void *data, size_t len)
{
  const uint8_t *p = data;

  s->total += len;
  while (len > 0)
  {
    size_t n = 64 - s->fill;

    if (n > len)
      n = len;
    memcpy(s->block + s->fill, p, n);
    s->fill += n;
    p += n;
    len -= n;
    if (s->fill == 64)
    {
      sha_compress(s, s->block);
      s->fill = 0;
    }
  }
}

static void sha_final(tb_sha_t *s, uint8_t out[TB_KEY])
{
  const uint64_t bits = s->total * 8;
  uint8_t        pad[72];
  const size_t   n = (s->fill < 56) ? 56 - s->fill : 120 - s->fill;
  int            i;

  memset(pad, 0, sizeof(pad));
  pad[0] = 0x80;
  for (i = 0; i < 8; i++)
    pad[n + i] = (uint8_t) (bits >> (56 - 8 * i));
  sha_update(s, pad, n + 8);

  for (i = 0; i < 8; i++)
  {
    out[4 * i] = (uint8_t) (s->h[i] >> 24);
    out[4 * i + 1] = (uint8_t) (s->h[i] >> 16);
    out[4 * i + 2] = (uint8_t) (s->h[i] >> 8);
    out[4 * i + 3] = (uint8_t) s->h[i];
  }
}

static void sha256(const void *data, size_t len, uint8_t out[TB_KEY])
{
  tb_sha_t s;

  sha_init(&s);
  sha_update(&s, data, len);
  sha_final(&s, out);
}

/* An HMAC key, as the states after its inner and outer pads */
typedef struct
{
  tb_sha_t inner;
  tb_sha_t outer;
} tb_hmac_t;

static void hmac_init(tb_hmac_t *m, const void *key, size_t len)
{
  uint8_t k[64];
  uint8_t pad[64];
  int     i;

  memset(k, 0, sizeof(k));
  if (len > 64)
    sha256(key, len, k);
  else if (len > 0)
    memcpy(k, key, len);

  for (i = 0; i < 64; i++)
    pad[i] = k[i] ^ 0x36;
  sha_init(&m->inner);
  sha_update(&m->inner, pad, 64);

  for (i = 0; i < 64; i++)
    pad[i] = k[i] ^ 0x5c;
  sha_init(&m->outer);
  sha_update(&m->outer, pad, 64);
}

static void hmac_with(const tb_hmac_t *m, const void *data, size_t len,
                      uint8_t out[TB_KEY])
{
  tb_sha_t s = m->inner;
  uint8_t  inner[TB_KEY];

  sha_update(&s, data, len);
  sha_final(&s, inner);

  s = m->outer;
  sha_update(&s, inner, TB_KEY);
  sha_final(&s, out);
}

static void hmac(const void *key, size_t key_len, const void *data,
                 size_t len, uint8_t out[TB_KEY])
{
  tb_hmac_t m;

  hmac_init(&m, key, key_len);
  hmac_with(&m, data, len, out);
}

/* PBKDF2-HMAC-SHA-256 of one block, as long as SHA-256's output */
static void pbkdf2(const char *password, const uint8_t *salt, size_t salt_len,
                   uint32_t iterations, uint8_t out[TB_KEY])
{
  static const uint8_t first_block[4] = {0, 0, 0, 1};
  tb_hmac_t            m;
  tb_sha_t             s;
  uint8_t              u[TB_KEY];
  uint8_t              inner[TB_KEY];
  uint32_t             i;
  int                  j;

  hmac_init(&m, password, strlen(password));

  s = m.inner;
  sha_update(&s, salt, salt_len);
  sha_update(&s, first_block, sizeof(first_block));
  sha_final(&s, inner);
  s = m.outer;
  sha_update(&s, inner, TB_KEY);
  sha_final(&s, u);
  memcpy(out, u, TB_KEY);

  for (i = 1; i < iterations; i++)
  {
    hmac_with(&m, u, TB_KEY, u);
    for (j = 0; j < TB_KEY; j++)
      out[j] ^= u[j];
  }
}

static const char b64_digits[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(tb_buf_t *b, const uint8_t *p, size_t len)
{
  size_t i;

  for (i = 0; i < len; i += 3)
  {
    const uint32_t v = ((uint32_t) p[i] << 16) |
      ((i + 1 < len) ? (uint32_t) p[i + 1] << 8 : 0) |
      ((i + 2 < len) ? (uint32_t) p[i + 2] : 0);
    char           out[4];

    out[0] = b64_digits[(v >> 18) & 63];
    out[1] = b64_digits[(v >> 12) & 63];
    out[2] = (i + 1 < len) ? b64_digits[(v >> 6) & 63] : '=';
    out[3] = (i + 2 < len) ? b64_digits[v & 63] : '=';
    if (put_bytes(b, out, 4))
      return 1;
  }

  return 0;
}

/* Decodes len characters of base 64 into out, of room for cap bytes */
static int b64_decode(const char *s, size_t len, uint8_t *out, size_t cap,
                      size_t *out_len)
{
  uint32_t v = 0;
  int      bits = 0;
  size_t   n = 0;
  size_t   i;

  for (i = 0; i < len && s[i] != '='; i++)
  {
    const char *d = memchr(b64_digits, s[i], 64);

    if (d == NULL)
      return 1;
    v = (v << 6) | (uint32_t) (d - b64_digits);
    bits += 6;
    if (bits >= 8)
    {
      bits -= 8;
      if (n == cap)
        return 1;
      out[n++] = (uint8_t) (v >> bits);
    }
  }
  *out_len = n;

  return 0;
}

/*
  The keys of the password, kept for each later connection that gets the
  same salt and iterations, so that only the first one runs PBKDF2
*/
static struct
{
  pthread_mutex_t lock;
  int             known;
  uint8_t         salt[256];
  size_t          salt_len;
  uint32_t        iterations;
  uint8_t         client[TB_KEY];
  uint8_t         server[TB_KEY];
} scram_keys = { PTHREAD_MUTEX_INITIALIZER, 0, {0}, 0, 0, {0}, {0} };

static void scram_derive(const uint8_t *salt, size_t salt_len,
                         uint32_t iterations, uint8_t client[TB_KEY],
                         uint8_t server[TB_KEY])
{
  uint8_t salted[TB_KEY];

  pthread_mutex_lock(&scram_keys.lock);
  if (!scram_keys.known || scram_keys.iterations != iterations ||
      scram_keys.salt_len != salt_len ||
      memcmp(scram_keys.salt, salt, salt_len) != 0)
  {
    pbkdf2(args.password, salt, salt_len, iterations, salted);
    hmac(salted, TB_KEY, "Client Key", 10, scram_keys.client);
    hmac(salted, TB_KEY, "Server Key", 10, scram_keys.server);
    memcpy(scram_keys.salt, salt, salt_len);
    scram_keys.salt_len = salt_len;
    scram_keys.iterations = iterations;
    scram_keys.known = 1;
  }
  memcpy(client, scram_keys.client, TB_KEY);
  memcpy(server, scram_keys.server, TB_KEY);
  pthread_mutex_unlock(&scram_keys.lock);
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

/*
  Keeps a failure's body on the connection, for sysbench to report: its
  SQLCODE, SQLSTATE and message, the rule it cites and where in the
  statement, then whether a transaction is still active after it. Its tail
  is empty, since the driver asks for no diagnostics.
*/
static void note_failure(db_conn_t *con, tb_reader_t *r)
{
  tb_conn_t  *c = con->ptr;
  uint32_t   len;
  const char *s;

  con->sql_errno = (int32_t) take_u32(r);

  xfree(con->sql_state);
  xfree(con->sql_errmsg);

  s = take_str(r, &len);
  con->sql_state = (s != NULL) ? strndup(s, len) : strdup("");
  s = take_str(r, &len);
  con->sql_errmsg = (s != NULL) ? strndup(s, len) : strdup("");

  if (take_u8(r))
    take_str(r, &len);
  if (take_u8(r))
    take_u64(r);
  /* A failure cut short is taken to leave its transaction active */
  if (c != NULL)
  {
    const int active = take_u8(r);

    c->active = r->ok ? active != 0 : 1;
  }
}

/*
  The failures a transaction is run again after. TB911 and 40001 are
  conflicts with another transaction. 23000 is every integrity failure, of
  which sysbench's own statements can break only a unique key, as two threads
  insert one id; other sysbench drivers take unique violations as ignorable
  too.
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

/*
  Sends Hello: the version, the user, the mechanism and its first bytes,
  then the capabilities asked for, none, and no attributes in its tail
*/
static int send_hello(tb_conn_t *c, const char *mechanism,
                      const void *initial, size_t len)
{
  const size_t at = frame_begin(&c->out, TB_HELLO);

  put_u32(&c->out, TB_VERSION);
  put_str(&c->out, args.user, strlen(args.user));
  put_str(&c->out, mechanism, strlen(mechanism));
  put_str(&c->out, initial, len);
  put_u32(&c->out, 0);
  frame_end(&c->out, at);

  return send_all(c);
}

static int send_answer(tb_conn_t *c, const void *answer, size_t len)
{
  const size_t at = frame_begin(&c->out, TB_ANSWER);

  put_str(&c->out, answer, len);
  frame_end(&c->out, at);

  return send_all(c);
}

/*
  Reads a step of the login: a Challenge, whose bytes come back, or the
  Ready that ends it. Says which, or -1 on a failure
*/
static int read_login(db_conn_t *con, const char **challenge, uint32_t *len)
{
  tb_reader_t body;
  uint8_t     kind;

  if (read_frame(con->ptr, &kind, &body))
    return -1;

  switch (kind) {
    case TB_R_READY:
      return TB_R_READY;

    case TB_R_CHALLENGE:
      *challenge = take_str(&body, len);
      return (*challenge != NULL) ? TB_R_CHALLENGE : -1;

    case TB_R_ERROR:
      note_failure(con, &body);
      log_text(LOG_FATAL, "login to turborel failed: %s", con->sql_errmsg);
      return -1;

    default:
      log_text(LOG_FATAL, "unexpected reply '%c' to login", kind);
      return -1;
  }
}

/* The value of the attribute name= of a SCRAM message, and its length */
static const char *scram_attribute(const char *msg, size_t msg_len, char name,
                                   size_t *len)
{
  const char *p = msg;
  const char *end = msg + msg_len;

  while (p < end)
  {
    const char *comma = memchr(p, ',', (size_t) (end - p));
    const char *stop = (comma != NULL) ? comma : end;

    if (stop - p >= 2 && p[0] == name && p[1] == '=')
    {
      *len = (size_t) (stop - p - 2);
      return p + 2;
    }
    p = stop + 1;
  }

  return NULL;
}

static int random_bytes(uint8_t *out, size_t len)
{
  const int fd = open("/dev/urandom", O_RDONLY);
  size_t    got = 0;

  if (fd < 0)
    return 1;
  while (got < len)
  {
    const ssize_t n = read(fd, out + got, len - got);

    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    got += (size_t) n;
  }
  close(fd);

  return got != len;
}

/*
  Logs in by SCRAM-SHA-256 with no channel binding: client-first in Hello,
  the server's first message in a Challenge, the proof in an Answer, the
  server's signature checked, then an empty Answer for Ready
*/
static int login_scram(db_conn_t *con)
{
  tb_conn_t     *c = con->ptr;
  tb_buf_t      msg = {NULL, 0, 0};
  tb_buf_t      auth = {NULL, 0, 0};
  uint8_t       nonce[TB_NONCE_BYTES];
  uint8_t       salt[256];
  uint8_t       client[TB_KEY];
  uint8_t       server[TB_KEY];
  uint8_t       stored[TB_KEY];
  uint8_t       sig[TB_KEY];
  uint8_t       got[TB_KEY];
  char          iterations_text[16];
  const char    *reply;
  const char    *both;
  const char    *s;
  const char    *v;
  size_t        nonce_len;
  size_t        both_len = 0;
  size_t        s_len = 0;
  size_t        i_len = 0;
  size_t        v_len = 0;
  size_t        salt_len;
  size_t        got_len;
  uint32_t      reply_len;
  unsigned long iterations;
  int           rc = 1;
  int           i;

  if (random_bytes(nonce, sizeof(nonce)))
  {
    log_text(LOG_FATAL, "cannot read /dev/urandom for a SCRAM nonce");
    return 1;
  }

  /* client-first: the GS2 header "n,," then n=<user>,r=<nonce> */
  put_text(&msg, "n,,n=");
  for (s = args.user; *s != '\0'; s++)
  {
    if (*s == '=')
      put_text(&msg, "=3D");
    else if (*s == ',')
      put_text(&msg, "=2C");
    else
      put_u8(&msg, (uint8_t) *s);
  }
  put_text(&msg, ",r=");
  nonce_len = msg.len;
  b64_encode(&msg, nonce, sizeof(nonce));
  nonce_len = msg.len - nonce_len;

  /* AuthMessage starts with client-first, its GS2 header left out */
  put_bytes(&auth, msg.data + 3, msg.len - 3);
  if (send_hello(c, TB_SCRAM, msg.data, msg.len))
    goto end;

  if (read_login(con, &reply, &reply_len) != TB_R_CHALLENGE)
    goto end;

  both = scram_attribute(reply, reply_len, 'r', &both_len);
  s = scram_attribute(reply, reply_len, 's', &s_len);
  v = scram_attribute(reply, reply_len, 'i', &i_len);
  if (both == NULL || s == NULL || v == NULL || i_len == 0 ||
      i_len >= sizeof(iterations_text) || both_len <= nonce_len ||
      memcmp(both, msg.data + msg.len - nonce_len, nonce_len) != 0 ||
      b64_decode(s, s_len, salt, sizeof(salt), &salt_len))
  {
    log_text(LOG_FATAL, "the server's first SCRAM message is malformed");
    goto end;
  }
  memcpy(iterations_text, v, i_len);
  iterations_text[i_len] = '\0';
  iterations = strtoul(iterations_text, NULL, 10);
  if (iterations == 0 || iterations > UINT32_MAX)
  {
    log_text(LOG_FATAL, "the server's SCRAM iterations are no number");
    goto end;
  }

  scram_derive(salt, salt_len, (uint32_t) iterations, client, server);

  /* Then server-first, then client-final without its proof */
  put_u8(&auth, ',');
  put_bytes(&auth, reply, reply_len);
  msg.len = 0;
  put_text(&msg, "c=biws,r=");      /* "biws" is "n,," in base 64 */
  put_bytes(&msg, both, both_len);
  put_u8(&auth, ',');
  put_bytes(&auth, msg.data, msg.len);

  /* ClientProof = ClientKey XOR HMAC(SHA-256(ClientKey), AuthMessage) */
  sha256(client, TB_KEY, stored);
  hmac(stored, TB_KEY, auth.data, auth.len, sig);
  for (i = 0; i < TB_KEY; i++)
    sig[i] ^= client[i];
  put_text(&msg, ",p=");
  b64_encode(&msg, sig, TB_KEY);

  if (send_answer(c, msg.data, msg.len))
    goto end;

  if (read_login(con, &reply, &reply_len) != TB_R_CHALLENGE)
    goto end;

  /* ServerSignature = HMAC(ServerKey, AuthMessage) */
  hmac(server, TB_KEY, auth.data, auth.len, sig);
  v = scram_attribute(reply, reply_len, 'v', &v_len);
  if (v == NULL || b64_decode(v, v_len, got, sizeof(got), &got_len) ||
      got_len != TB_KEY || memcmp(got, sig, TB_KEY) != 0)
  {
    log_text(LOG_FATAL, "the server did not prove it knows the user");
    goto end;
  }

  if (send_answer(c, NULL, 0) ||
      read_login(con, &reply, &reply_len) != TB_R_READY)
    goto end;

  rc = 0;

end:
  free(msg.data);
  free(auth.data);

  return rc;
}

static int login(db_conn_t *con)
{
  tb_conn_t  *c = con->ptr;
  const char *challenge;
  uint32_t   len;
  int        step;

  if (!strcmp(args.mechanism, TB_SCRAM))
    return login_scram(con);

  if (send_hello(c, args.mechanism, args.password, strlen(args.password)))
    return 1;

  step = read_login(con, &challenge, &len);
  if (step == TB_R_CHALLENGE)
    log_text(LOG_FATAL, "the server asked for a login this driver cannot give");

  return step != TB_R_READY;
}

static void put_prepare(tb_conn_t *c, uint32_t id, const char *sql, size_t len)
{
  const size_t at = frame_begin(&c->out, TB_PREPARE);

  put_u32(&c->out, id);
  put_str(&c->out, sql, len);
  frame_end(&c->out, at);
}

/*
  Prepares the driver's own statements in one write. The server answers
  requests in turn, so the three cost one round trip together
*/
static int prepare_own(db_conn_t *con)
{
  const char  *sql[3] = { "COMMIT", "ROLLBACK", args.begin };
  tb_reader_t body;
  int         i;

  for (i = 0; i < 3; i++)
    put_prepare(con->ptr, TB_STMT_COMMIT + (uint32_t) i, sql[i],
                strlen(sql[i]));

  if (send_all(con->ptr))
    return 1;

  for (i = 0; i < 3; i++)
  {
    if (read_simple(con, TB_R_PREPARED, &body))
    {
      log_text(LOG_FATAL, "cannot prepare %s: %s", sql[i],
               (con->sql_errmsg != NULL) ? con->sql_errmsg :
               "connection lost");
      return 1;
    }
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
  free(c->result.text.data);
  free(c->result.text_at);
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
  args.mechanism = option_text("turborel-mechanism");

  if (args.mechanism[0] == '\0')
    args.mechanism = (args.password[0] != '\0') ? TB_SCRAM : "trust";

  if (strcmp(args.mechanism, "trust") && strcmp(args.mechanism, TB_SCRAM) &&
      strcmp(args.mechanism, "password"))
  {
    log_text(LOG_FATAL, "--turborel-mechanism takes trust, scram-sha-256 or "
             "password, not %s", args.mechanism);
    return 1;
  }

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

  if (c->in == NULL || c->fd < 0 || login(sb_conn) || prepare_own(sb_conn))
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
  if (starts_with(sql, "SELECT") || starts_with(sql, "VALUES"))
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
  transaction ended with it if ends. Its tail is empty
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

/*
  Ends the transaction after a failure. The failure said whether one is
  still active: a statement that was to end its transaction, or a failure
  that rolled it back, leaves none, and costs no ROLLBACK
*/
static int rollback(db_conn_t *con)
{
  tb_conn_t *c = con->ptr;

  c->in_tx = 0;
  if (!c->active)
    return 0;

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
    /* Query: the SQL, then ends, with an empty tail */
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

/* Reads an i128 as its magnitude and its sign */
static unsigned __int128 take_i128(tb_reader_t *r, int *negative)
{
  const uint64_t    low = take_u64(r);
  const uint64_t    high = take_u64(r);
  unsigned __int128 units = ((unsigned __int128) high << 64) | low;

  *negative = (high >> 63) != 0;
  if (*negative)
    units = ~units + 1;

  return units;
}

static int put_exact_text(tb_buf_t *b, unsigned __int128 units, int negative,
                          uint32_t scale)
{
  char text[TB_NUMBER_TEXT];

  if (scale > TB_NUMBER_TEXT - 8)
    scale = TB_NUMBER_TEXT - 8;

  return put_bytes(b, text, exact_text(text, units, negative, scale));
}

static int put_printf(tb_buf_t *b, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

static int put_printf(tb_buf_t *b, const char *format, ...)
{
  char    text[TB_NUMBER_TEXT];
  va_list ap;
  int     n;

  va_start(ap, format);
  n = vsnprintf(text, sizeof(text), format, ap);
  va_end(ap);

  if (n < 0)
    return 1;
  if ((size_t) n >= sizeof(text))
    n = sizeof(text) - 1;

  return put_bytes(b, text, (size_t) n);
}

static int put_hex(tb_buf_t *b, const uint8_t *p, size_t len)
{
  static const char digits[] = "0123456789ABCDEF";
  size_t            i;

  for (i = 0; i < len; i++)
  {
    const char pair[2] = { digits[p[i] >> 4], digits[p[i] & 15] };

    if (put_bytes(b, pair, 2))
      return 1;
  }

  return 0;
}

/* The year, month and day of a count of days since 1970-01-01 */
static void civil(int64_t days, int64_t *y, unsigned *m, unsigned *d)
{
  const int64_t  z = days + 719468;
  const int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = (unsigned) (z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;

  *d = doy - (153 * mp + 2) / 5 + 1;
  *m = (mp < 10) ? mp + 3 : mp - 9;
  *y = (int64_t) yoe + era * 400 + (*m <= 2);
}

/*
  A date, a time or a timestamp: zoned, its precision, the zone's
  displacement in minutes, then the instant in microseconds in UTC, from
  0001-01-01 00:00:00, or from midnight of a time
*/
static int put_datetime(tb_buf_t *b, tb_reader_t *r, uint8_t tag)
{
  const int      zoned = take_u8(r);
  const unsigned precision = take_u8(r);
  const int16_t  zone = (int16_t) (uint16_t) take_u32(r);
  const int64_t  instant = (int64_t) take_u64(r);
  const int64_t  day = INT64_C(86400000000);
  const int64_t  local = instant + (int64_t) zone * 60000000;
  int64_t        days = local / day;
  int64_t        micros = local % day;
  int64_t        y;
  unsigned       m, d;
  int            rc = 0;

  if (micros < 0)
  {
    micros += day;
    days--;
  }
  /* From 0001-01-01 to 1970-01-01, which civil counts from */
  days -= 719162;

  if (tag != TB_TIME)
  {
    civil(days, &y, &m, &d);
    rc |= put_printf(b, "%04" PRId64 "-%02u-%02u", y, m, d);
    if (tag == TB_TIMESTAMP)
      rc |= put_u8(b, ' ');
  }

  if (tag != TB_DATE)
  {
    rc |= put_printf(b, "%02u:%02u:%02u", (unsigned) (micros / 3600000000),
                     (unsigned) (micros / 60000000 % 60),
                     (unsigned) (micros / 1000000 % 60));
    if (precision > 0)
    {
      char frac[8];

      snprintf(frac, sizeof(frac), "%06u", (unsigned) (micros % 1000000));
      rc |= put_u8(b, '.') ||
        put_bytes(b, frac, (precision < 6) ? precision : 6);
    }
    if (zoned)
      rc |= put_printf(b, "%c%02d:%02d", (zone < 0) ? '-' : '+',
                       abs(zone) / 60, abs(zone) % 60);
  }

  return rc || !r->ok;
}

/*
  An interval: its qualifier's start and end fields and precisions, then
  its units, months of a year-month interval and microseconds of a
  day-time one
*/
static int put_interval(tb_buf_t *b, tb_reader_t *r)
{
  const uint32_t    start = take_u32(r);
  int               negative;
  unsigned __int128 units;
  uint64_t          n;

  take_u32(r);
  take_u32(r);
  take_u32(r);
  units = take_i128(r, &negative);
  n = (uint64_t) units;

  if (negative && put_u8(b, '-'))
    return 1;
  if (start <= 1)
    return put_printf(b, "%" PRIu64 "-%" PRIu64, n / 12, n % 12) || !r->ok;

  return put_printf(b, "%" PRIu64 " %02" PRIu64 ":%02" PRIu64 ":%02" PRIu64
                    ".%06" PRIu64, n / UINT64_C(86400000000),
                    n / UINT64_C(3600000000) % 24, n / 60000000 % 60,
                    n / 1000000 % 60, n % 1000000) || !r->ok;
}

/* A decimal floating point number: its coefficient, then its exponent */
static int put_decfloat(tb_buf_t *b, tb_reader_t *r)
{
  int               negative;
  unsigned __int128 units = take_i128(r, &negative);
  const int32_t     exponent = (int32_t) take_u32(r);

  if (exponent <= 0 && exponent > -(TB_NUMBER_TEXT - 8))
    return put_exact_text(b, units, negative, (uint32_t) -exponent) || !r->ok;

  return put_exact_text(b, units, negative, 0) ||
    put_printf(b, "E%+d", exponent) || !r->ok;
}

static int put_value_text(tb_buf_t *b, tb_reader_t *r, int depth);

/* The values of a list, between open and close */
static int put_list_text(tb_buf_t *b, tb_reader_t *r, const char *open,
                         const char *close, int depth)
{
  const uint32_t count = take_u32(r);
  uint32_t       i;

  if (put_text(b, open))
    return 1;
  for (i = 0; i < count && r->ok; i++)
    if ((i > 0 && put_text(b, ", ")) || put_value_text(b, r, depth + 1))
      return 1;

  return put_text(b, close) || !r->ok;
}

/* A string, quoted as a literal is, its quotes doubled */
static int put_quoted(tb_buf_t *b, const char *s, uint32_t len)
{
  uint32_t i;

  if (put_u8(b, '\''))
    return 1;
  for (i = 0; i < len; i++)
    if ((s[i] == '\'' && put_u8(b, '\'')) || put_u8(b, (uint8_t) s[i]))
      return 1;

  return put_u8(b, '\'');
}

/*
  Appends the text of a value. A string within it is quoted, and a binary
  one written as X'..', as literals are
*/
static int put_value_text(tb_buf_t *b, tb_reader_t *r, int depth)
{
  const uint8_t tag = take_u8(r);
  const char    *s;
  uint32_t      len;
  int           negative;

  if (depth > TB_DEPTH)
  {
    log_text(LOG_FATAL, "a value is nested too deep to show");
    return 1;
  }

  switch (tag) {
    case TB_NULL:
      return put_text(b, "NULL") || !r->ok;

    case TB_CHARACTER:
    case TB_XML:
      s = take_str(r, &len);
      return !r->ok || put_quoted(b, s, len);

    case TB_EXACT:
    {
      const unsigned __int128 units = take_i128(r, &negative);

      return put_exact_text(b, units, negative, take_u32(r)) || !r->ok;
    }

    case TB_APPROXIMATE:
    {
      const uint64_t bits = take_u64(r);
      double         d;

      memcpy(&d, &bits, sizeof(d));
      return put_printf(b, "%.17g", d) || !r->ok;
    }

    case TB_EXTENSION:
      take_str(r, &len);
      s = take_str(r, &len);
      if (!r->ok || put_bytes(b, s, len))
        return 1;
      take_str(r, &len);
      return !r->ok;

    case TB_BINARY:
    case TB_REFERENCE:
    case TB_JSON:
      s = take_str(r, &len);
      return !r->ok || put_text(b, "X'") ||
        put_hex(b, (const uint8_t *) s, len) || put_u8(b, '\'');

    case TB_DATE:
    case TB_TIME:
    case TB_TIMESTAMP:
      return put_datetime(b, r, tag);

    case TB_INTERVAL:
      return put_interval(b, r);

    case TB_BOOLEAN:
      return put_text(b, take_u8(r) ? "TRUE" : "FALSE") || !r->ok;

    case TB_DECFLOAT:
      return put_decfloat(b, r);

    case TB_ARRAY:
      return put_list_text(b, r, "ARRAY[", "]", depth);

    case TB_MULTISET:
      return put_list_text(b, r, "MULTISET[", "]", depth);

    case TB_ROW:
      return put_list_text(b, r, "ROW(", ")", depth);

    case TB_STRUCTURED:
      s = take_str(r, &len);
      if (!r->ok || put_bytes(b, s, len) || put_u8(b, '.'))
        return 1;
      s = take_str(r, &len);
      return !r->ok || put_bytes(b, s, len) ||
        put_list_text(b, r, "(", ")", depth);

    case TB_LOB_WHOLE:
    {
      const uint8_t kind = take_u8(r);

      s = take_str(r, &len);
      if (!r->ok)
        return 1;
      if (kind == 0)
        return put_quoted(b, s, len);
      return put_text(b, "X'") || put_hex(b, (const uint8_t *) s, len) ||
        put_u8(b, '\'');
    }

    case TB_UUID:
    {
      const uint8_t *p;

      s = take_str(r, &len);
      if (!r->ok || len != 16)
        return 1;
      p = (const uint8_t *) s;
      return put_hex(b, p, 4) || put_u8(b, '-') || put_hex(b, p + 4, 2) ||
        put_u8(b, '-') || put_hex(b, p + 6, 2) || put_u8(b, '-') ||
        put_hex(b, p + 8, 2) || put_u8(b, '-') || put_hex(b, p + 10, 6);
    }

    case TB_LOB_LOCATOR:
      log_text(LOG_FATAL, "a large object came by its locator, which this "
               "driver does not read");
      return 1;

    default:
      log_text(LOG_FATAL, "this driver cannot read a value of tag %u", tag);
      return 1;
  }
}

/*
  Reads one value of a row. A string or a binary string, and the bytes of
  a whole large object, of JSON or of XML, are handed over as they came.
  Every other value is turned into text, placed once the whole row is
  read, since the text buffer may move as it grows.
*/
static int field_value(tb_result_t *result, db_value_t *v, size_t *text_at)
{
  tb_reader_t   *r = &result->at;
  const uint8_t tag = (r->p < r->end) ? *r->p : TB_NULL;
  size_t        at;

  *text_at = SIZE_MAX;

  switch (tag) {
    case TB_NULL:
      take_u8(r);
      v->ptr = NULL;
      v->len = 0;
      return !r->ok;

    case TB_CHARACTER:
    case TB_BINARY:
    case TB_JSON:
    case TB_XML:
      take_u8(r);
      v->ptr = take_str(r, &v->len);
      return !r->ok;

    case TB_LOB_WHOLE:
      take_u8(r);
      take_u8(r);
      v->ptr = take_str(r, &v->len);
      return !r->ok;

    default:
      at = result->text.len;
      if (put_value_text(&result->text, r, 0))
        return 1;
      *text_at = at;
      v->len = (uint32_t) (result->text.len - at);
      return 0;
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

  if (result->text_fields < rs->nfields)
  {
    size_t *text_at = realloc(result->text_at,
                              (size_t) rs->nfields * sizeof(size_t));

    if (text_at == NULL)
      return DB_ERROR_FATAL;
    result->text_at = text_at;
    result->text_fields = rs->nfields;
  }
  result->text.len = 0;

  count = take_u32(&result->at);
  for (i = 0; i < rs->nfields && i < count; i++)
    if (field_value(result, &row->values[i], &result->text_at[i]))
      return DB_ERROR_FATAL;

  for (i = 0; i < rs->nfields && i < count; i++)
    if (result->text_at[i] != SIZE_MAX)
      row->values[i].ptr = (const char *) result->text.data +
        result->text_at[i];

  result->frame_left--;

  return result->at.ok ? DB_ERROR_NONE : DB_ERROR_FATAL;
}

int turborel_drv_free_results(db_result_t *rs)
{
  tb_result_t *result = rs->ptr;

  if (result == NULL)
    return 1;

  result->rows.len = 0;
  result->text.len = 0;
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
