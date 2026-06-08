/*
 * amissl.c — AmiSSL compatibility shim for AmiSSL-Tunnel
 *
 * amissl.library exports the OpenSSL/AmiSSL ABI but offloads TLS to a daemon on
 * the LAN (tls_proxy.py), reached over the resident Roadshow/AmiTCP/Miami
 * bsdsocket.library.  At SSL_connect the shim opens a socket to the daemon, sends
 * "CONNECT <host> <port>", and once the daemon has completed the verified TLS
 * handshake to the real server it Dup2Socket()s that socket onto the app's own fd
 * and relays plaintext.  So SSL_read/SSL_write become plain bsd recv/send, and the
 * app's fd/WaitSelect contract is preserved.  See the project README.
 *
 *   App SSL_read/SSL_write  →  amissl.library  →  bsd recv/send on the daemon
 *                                                  socket Dup2Socket'd onto the fd
 *   tls_proxy.py (LAN)      →  Python ssl crypto, system CA bundle
 *
 * Opaque handles (must look like real pointers — AWeb range-checks them):
 *   SSL_CTX* = 0x4000 sentinel.  SSL* = 0x5000 + 1-based g_sess[] index.
 *   Apps treat them as opaque and never dereference.
 *
 * *** ABI NOTE *** The LVO table in amissl_start.S (asset #1) is reused UNCHANGED
 * from the proven a314bsd/a314SSLlib build; only the SSL I/O function bodies below
 * change for Model B.  Functions that call bsd_* are already Wrap*-trampolined in
 * amissl_start.S (a6 save/restore), so no table change is needed.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <proto/exec.h>

/* Model B uses the resident bsdsocket directly; no ssl_lvo.h / BSDSSL_LVO_* needed. */

/* ---- AmiSSL library base ------------------------------------------------- */

struct AmiSSLBase {
    struct Library   lib;        /* standard 34-byte library node */
    struct ExecBase *SysBase;    /* stored in Init from a6 */
    APTR             SegList;
    APTR             BsdBase;    /* bsdsocket.library base; set on first Open */
};

/* Opaque handle types: ULONG IDs cast to pointer size.
 * ID 0 = invalid.  Apps treat these as opaque; we never dereference them. */
typedef APTR SSL_CTX;
typedef APTR SSL;
typedef APTR SSL_METHOD;

/* ---- File-scope globals needed by multiple function groups ---------------- */

/* g_last_ctx_id: most recently created SSL_CTX id (from any SSL_CTX_new variant).
 * Fallback for BIO_do_connect when g_bio_ctx_id is 0.  Happens when iBrowse uses
 * BIO_new_ssl(ctx)+BIO_new_connect("host:port")+BIO_push instead of
 * the combined BIO_new_ssl_connect(ctx). */
static ULONG g_last_ctx_id = 0;

/* SSL_CTX_SENTINEL: the fake non-NULL token returned by every SSL_CTX_new
 * variant.  Must land in [0x1000,0xFFFFFFF0): AWeb 3.6b8 range-checks the
 * SSL_CTX pointer right after SSL_CTX_new and frees+rejects anything < 0x1000
 * as "invalid pointer" (amissl.c GetSharedSSLCTX).  The old value of 1 passed
 * iBrowse (no range check) but made AWeb abort the secure connection before it
 * ever called SSL_new.  The token is opaque — callers only test it non-NULL. */
#define SSL_CTX_SENTINEL 0x4000UL

/* ---- Verify callback / mode storage (forward declarations) ----------------
 * Defined in full later; declared here so ami_ssl_open can initialise them. */

/* dummy_verify_cb: safe no-op OpenSSL verify callback (standard C calling conv).
 * Used as default g_verify_callback so any JSR through it is harmless. */
static LONG dummy_verify_cb(LONG preverify_ok, APTR x509_ctx);

/* Globals initialised by ami_ssl_open on first Open. */
static APTR g_verify_callback;   /* = dummy_verify_cb after first Open */
static LONG g_verify_mode;       /* = 0 */
static APTR g_verify_store;      /* = (APTR)1UL after first Open */

/* Build 38: last SNI hostname set via SSL_set_tlsext_host_name (SSL_ctrl cmd 55).
 * AWeb verifies the cert CN against the hostname locally; we feed this back as the
 * CN (via ASN1_STRING_data/length) so the match succeeds — the Pi already did the
 * real hostname-checked verification. */
static char g_last_sni[256];

/* ---- LVO call helpers (inline so compiler manages a6 correctly) ---------- */
/*
 * Each helper sets a6 = BsdBase, then JSRs to the bsdsocket LVO.
 * "register ... __asm("a6")" forces GCC to put the value in a6 specifically.
 * With -fomit-frame-pointer (set in Makefile) a6 is a free general register.
 *
 * Clobber list covers what bsdsocket library functions may trash:
 * d0 (return value), d1, a0, a1 per Amiga library convention.
 *
 * IMPORTANT — register aliasing fix (Build 14):
 * Earlier code had two separate 'register ... __asm("d0")' variables for the
 * d0 input and d0 output.  With -O2, GCC treats the "=d" output as the sole
 * live use of d0 and optimises away the input initialisation, leaving d0=0
 * when the JSR fires.  The fix is to use a SINGLE register variable with the
 * "+d" (read-write) constraint — GCC is then forced to load the value before
 * the instruction and to read the result afterwards.
 */

/* No d0 input — output only.  No aliasing risk. */
static inline ULONG
_bsd_call0(APTR bbase, WORD lvo)
{
    register ULONG res  __asm("d0");
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c1(%%a6)"
        : "=d"(res)
        : "i"(lvo), "a"(base)
        : "d1", "a0", "a1", "cc", "memory");
    return res;
}

/* d0 in/out, no other d-register inputs. */
static inline ULONG
_bsd_call1d(APTR bbase, WORD lvo, ULONG d0v)
{
    register ULONG d0   __asm("d0") = d0v;   /* single var — no aliasing */
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c2(%%a6)"
        : "+d"(d0)                             /* read-write: load before, result after */
        : "a"(base), "i"(lvo)
        : "d1", "a0", "a1", "cc", "memory");
    return d0;
}

/* d0 and d1 inputs, d0 output. */
static inline ULONG
_bsd_call2d(APTR bbase, WORD lvo, ULONG d0v, ULONG d1v)
{
    register ULONG d0   __asm("d0") = d0v;
    register ULONG d1   __asm("d1") = d1v;
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c3(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1), "i"(lvo)
        : "a0", "a1", "cc", "memory");
    return d0;
}

/* d0 = ssl_id, a0 = ptr arg, d1 = length/max */
static inline ULONG
_bsd_call_dab(APTR bbase, WORD lvo, ULONG d0v, APTR ptr, ULONG d1v)
{
    register ULONG d0   __asm("d0") = d0v;
    register ULONG d1   __asm("d1") = d1v;
    register APTR  xa0  __asm("a0") = ptr;
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c4(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1), "a"(xa0), "i"(lvo)
        : "a1", "cc", "memory");
    return d0;
}

/* d0 = ssl_id, a0 = string ptr */
static inline ULONG
_bsd_call_da(APTR bbase, WORD lvo, ULONG d0v, APTR ptr)
{
    register ULONG d0   __asm("d0") = d0v;
    register APTR  xa0  __asm("a0") = ptr;
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c3(%%a6)"
        : "+d"(d0)
        : "a"(base), "a"(xa0), "i"(lvo)
        : "d1", "a1", "cc", "memory");
    return d0;
}

/* ---- Amiga hostent and sockaddr_in for BIO connect path ------------------ */
/*
 * Standard POSIX structures needed to call bsdsocket.library's socket(),
 * connect(), and gethostbyname() from ami_BIO_ctrl(cmd=10 / BIO_do_connect).
 * No bsdsocket.h is included to avoid namespace conflicts with amissl types.
 */
struct ami_hostent {
    STRPTR   h_name;       /* +0: canonical hostname */
    STRPTR  *h_aliases;    /* +4: alias list (NULL-terminated) */
    LONG     h_addrtype;   /* +8: address family (AF_INET=2) */
    LONG     h_length;     /* +12: address length (4 for IPv4) */
    STRPTR  *h_addr_list;  /* +16: list of addresses (NULL-terminated) */
    /* h_addr_list[0] points to 4 bytes of IPv4 in network byte order */
};

struct ami_sockaddr_in {
    WORD  sin_family;   /* +0: AF_INET = 2 */
    UWORD sin_port;     /* +2: port in network byte order */
    ULONG sin_addr;     /* +4: IPv4 address in network byte order */
    UBYTE sin_zero[8];  /* +8: padding to 16 bytes total */
};

/* ---- BIO path bsdsocket inline helpers ----------------------------------- */
/*
 * Direct LVO calls for TCP socket operations needed by BIO_do_connect.
 * Same pattern as _bsd_call* above: a6 = BsdBase set in each helper.
 *
 * Amiga bsdsocket calling conventions (AmiTCP/Roadshow):
 *   gethostbyname(name)(a0)                 → d0 = struct hostent *
 *   socket(domain,type,proto)(d0,d1,d2)     → d0 = fd or -1
 *   connect(s,name,namelen)(d0,a0,d1)       → d0 = 0 or -1
 *
 * LVOs verified from a314bsd/amiga/lib_start.S:
 *   socket:         LVO -30
 *   connect:        LVO -54
 *   gethostbyname:  LVO -210
 */

static inline struct ami_hostent *
_bsd_gethostbyname(APTR bbase, STRPTR name)
{
    register struct ami_hostent *res __asm("d0");
    register STRPTR xname __asm("a0") = name;
    register APTR   base  __asm("a6") = bbase;
    __asm volatile ("jsr -210(%%a6)"
        : "=d"(res)
        : "a"(base), "a"(xname)
        : "d1", "a1", "cc", "memory");
    return res;
}

static inline LONG
_bsd_socket(APTR bbase, LONG domain, LONG type, LONG proto)
{
    register LONG d0   __asm("d0") = domain;  /* single var — no aliasing */
    register LONG d1   __asm("d1") = type;
    register LONG d2   __asm("d2") = proto;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -30(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1), "d"(d2)
        : "a0", "a1", "cc", "memory");
    return d0;
}

static inline LONG
_bsd_connect(APTR bbase, LONG fd, APTR sa, LONG salen)
{
    register LONG d0   __asm("d0") = fd;      /* single var — no aliasing */
    register APTR a0   __asm("a0") = sa;
    register LONG d1   __asm("d1") = salen;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -54(%%a6)"
        : "+d"(d0)
        : "a"(base), "a"(a0), "d"(d1)
        : "a1", "cc", "memory");
    return d0;
}
/* getpeername(s d0, name a0, namelen a1) — LVO -108. Fills `name` with the peer
 * address of a connected socket; returns 0 on success. Used to learn the real
 * target port the app connected its fd to, so the tunnel CONNECT line is not
 * limited to 443 (works for mail/IRC/FTPS, not just HTTPS). */
static inline LONG
_bsd_getpeername(APTR bbase, LONG s, APTR name, APTR namelen)
{
    register LONG d0   __asm("d0") = s;
    register APTR a0   __asm("a0") = name;
    register APTR a1   __asm("a1") = namelen;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -108(%%a6)"
        : "+d"(d0)
        : "a"(base), "a"(a0), "a"(a1)
        : "d1", "cc", "memory");
    return d0;
}
/* Dup2Socket(old d0, new d1) — LVO -264.  Makes fd `new` refer to fd `old`'s socket
 * (like dup2).  We use it to swap iBrowse's fd onto our daemon connection; because it
 * remaps the fd NUMBER in the socket table, iBrowse's CACHED recv/WaitSelect on that
 * fd then operate on the daemon stream (SetFunction patches don't reach cached calls). */
static inline LONG
_bsd_dup2socket(APTR bbase, LONG oldfd, LONG newfd)
{
    register LONG d0   __asm("d0") = oldfd;
    register LONG d1   __asm("d1") = newfd;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -264(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1)
        : "a0", "a1", "cc", "memory");
    return d0;
}

/* ===========================================================================
 * Legacy crypto-oracle opcodes (UNUSED)
 *
 * An earlier design kept the app's own socket to server:443 and ran the crypto on
 * a LAN daemon over a shared control socket. These OOP_* opcodes were defined for
 * that path but are NOT used — the shipping shim uses the CONNECT+Dup2Socket relay
 * described at the top of this file. Kept only so the definitions don't churn.
 *   request : op(1) ssl_id(4) aux(4) inlen(4) in[inlen]
 *   response: status(1) pending(4) outlen(4) out[outlen]
 * =========================================================================== */

/* Daemon address.  The compiled-in values below are only the FALLBACK; the real
 * address is read once at runtime from ENV:AMISSLPROXY ("host:port") — see
 * resolve_daemon() / daemon_ip() / daemon_port() below.  The Installer writes
 * ENV:/ENVARC:AMISSLPROXY so end users point the shim at their LAN daemon without
 * recompiling.  (Default is the WSL/loopback daemon used for VM testing.) */
#define ORACLE_HOST_DEFAULT "127.0.0.1"
#define ORACLE_PORT_DEFAULT 8443

/* Resolved daemon address from ENV:AMISSLPROXY (0 = unresolved -> use defaults). */
static ULONG g_daemon_ip   = 0;   /* network-order IPv4 */
static UWORD g_daemon_port = 0;
static UBYTE g_cfg_done     = 0;  /* ENV parsed once */
#define ORACLE_MAX_SESS     16
#define ORACLE_SCRATCH      3584        /* per-session ciphertext staging */
#define ORACLE_WRITE_CHUNK  2048        /* plaintext bytes per WRITE op (<= scratch) */

#define OOP_NEW 1
#define OOP_HANDSHAKE 2
#define OOP_WRITE 3
#define OOP_READ 4
#define OOP_SHUTDOWN 5
#define OOP_FREE 6
#define OOP_PROBE 7        /* DIAGNOSTIC: daemon logs aux as a marker */
#define AMISSL_PROBE 0     /* set 0 to strip probes from a release build */
#define OST_OK 0
#define OST_WANT_READ 1
#define OST_EOF 2
#define OST_ERROR 3

struct SslSess {
    UBYTE used;
    LONG  fd;          /* app's server socket; -1 = unset */
    LONG  cfd;         /* per-session control socket to the daemon; -1 = unset */
    APTR  exdata;      /* app data set via SSL_set_ex_data (YAM stores its conn
                        * pointer here and checks the call's return value). */
    APTR  bbase;       /* THIS session's task SocketBase, captured at SSL_new.
                        * A bsdsocket SocketBase is per-task; the shared
                        * base->BsdBase field gets clobbered when AWeb runs
                        * parallel image-fetch tasks (each InitAmiSSLA overwrites
                        * it), so a task could otherwise do socket I/O on another
                        * task's base -> concurrent "0 bytes read" failures. */
    ULONG oracle_id;   /* daemon-side SSLObject id; 0 = not created */
    ULONG pending;     /* cached plaintext-pending still buffered on the daemon */
    UBYTE want_read;   /* last SSL_read hit EWOULDBLOCK -> SSL_get_error=WANT_READ */
    ULONG plain_off;   /* prefetch: read cursor into the local plaintext buffer */
    ULONG plain_len;   /* prefetch: valid plaintext bytes in the local buffer */
    char  sni[256];
    UBYTE scratch[ORACLE_SCRATCH];  /* per-session ciphertext buffer (NOT shared:
                                     * iBrowse runs parallel image fetches in
                                     * separate tasks — a shared buffer races). */
};

/* Backing store as a byte array with a power-of-two stride, so session indexing
 * compiles to shifts only — no __mulsi3/__divsi3 (we link -nostdlib, no libgcc). */
#define SESS_STRIDE 4096                /* power of two, >= sizeof(struct SslSess) */
static UBYTE g_sess_mem[ORACLE_MAX_SESS * SESS_STRIDE];
static struct ExecBase *g_SysBase = 0;  /* for Forbid/Permit around sess_alloc */

/* Per-task SocketBase map.  A bsdsocket SocketBase is per-task, but the shim has
 * only one (shared) AmiSSLBase, so base->BsdBase can't hold more than one task's
 * base at a time.  AWeb fetches inline images in several parallel tasks, each
 * calling InitAmiSSLA with its OWN SocketBase; without this map the last init
 * wins and the other tasks' SSL_connect runs socket I/O on the wrong base ->
 * the daemon sees a connect with no CONNECT line ("0 bytes read") and the image
 * fails.  InitAmiSSLA records (task -> SocketBase) here; SSL_new copies the
 * caller task's base into the session so all of that session's socket I/O uses
 * the right one regardless of what other tasks do to base->BsdBase. */
#define MAX_TASK_BASES 16
static struct { APTR task; APTR bb; } g_task_bb[MAX_TASK_BASES];

static void task_bb_set(APTR task, APTR bb)
{
    struct ExecBase *SysBase = g_SysBase;
    UWORD i, free = 0xFFFF;
    if (!task || !bb) return;
    if (SysBase) Forbid();
    for (i = 0; i < MAX_TASK_BASES; i++) {
        if (g_task_bb[i].task == task) { g_task_bb[i].bb = bb; if (SysBase) Permit(); return; }
        if (!g_task_bb[i].task && free == 0xFFFF) free = i;
    }
    if (free != 0xFFFF) { g_task_bb[free].task = task; g_task_bb[free].bb = bb; }
    if (SysBase) Permit();
}
static APTR task_bb_get(APTR task)
{
    struct ExecBase *SysBase = g_SysBase;
    APTR r = (APTR)0;
    UWORD i;
    if (SysBase) Forbid();
    for (i = 0; i < MAX_TASK_BASES; i++)
        if (g_task_bb[i].task == task) { r = g_task_bb[i].bb; break; }
    if (SysBase) Permit();
    return r;
}
static void task_bb_clear(APTR task)
{
    struct ExecBase *SysBase = g_SysBase;
    UWORD i;
    if (SysBase) Forbid();
    for (i = 0; i < MAX_TASK_BASES; i++)
        if (g_task_bb[i].task == task) { g_task_bb[i].task = (APTR)0; g_task_bb[i].bb = (APTR)0; break; }
    if (SysBase) Permit();
}

/* bsd_* helpers for send/recv/close (recv/send: d0=s,a0=buf,d1=len,d2=flags). */
static inline LONG
_bsd_send(APTR bbase, LONG s, CONST_APTR buf, LONG len, LONG flags)
{
    register LONG      d0   __asm("d0") = s;
    register CONST_APTR a0  __asm("a0") = buf;
    register LONG      d1   __asm("d1") = len;
    register LONG      d2   __asm("d2") = flags;
    register APTR      base __asm("a6") = bbase;
    __asm volatile ("jsr -66(%%a6)"
        : "+d"(d0) : "a"(base), "a"(a0), "d"(d1), "d"(d2)
        : "a1", "cc", "memory");
    return d0;
}
static inline LONG
_bsd_recv(APTR bbase, LONG s, APTR buf, LONG len, LONG flags)
{
    register LONG d0   __asm("d0") = s;
    register APTR a0   __asm("a0") = buf;
    register LONG d1   __asm("d1") = len;
    register LONG d2   __asm("d2") = flags;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -78(%%a6)"
        : "+d"(d0) : "a"(base), "a"(a0), "d"(d1), "d"(d2)
        : "a1", "cc", "memory");
    return d0;
}
static inline LONG
_bsd_closesocket(APTR bbase, LONG s)
{
    register LONG d0   __asm("d0") = s;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -120(%%a6)"
        : "+d"(d0) : "a"(base) : "d1", "a0", "a1", "cc", "memory");
    return d0;
}
/* Errno() — LVO -162.  Read the per-task socket errno after a failed call. */
static inline LONG _bsd_errno(APTR bbase)
{
    register LONG d0   __asm("d0");
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -162(%%a6)"
        : "=d"(d0) : "a"(base) : "d1", "a0", "a1", "cc", "memory");
    return d0;
}
#define EWOULDBLOCK_AMI 35   /* AmiTCP/Roadshow EWOULDBLOCK */

/* Block until fd is readable (or `secs` timeout), for a non-blocking socket.
 * WaitSelect(nfds,readfds,0,0,&tv,0): d0,a0,a1,a2,a3,d1. */
static void wait_readable(APTR bbase, LONG fd, LONG secs)
{
    ULONG rset[8], tv[2];
    UWORD i;
    register LONG  d0 __asm("d0") = fd + 1;
    register APTR  a0 __asm("a0");
    register APTR  a1 __asm("a1") = (APTR)0;
    register APTR  a2 __asm("a2") = (APTR)0;
    register APTR  a3 __asm("a3");
    register ULONG d1 __asm("d1") = 0;
    register APTR  a6 __asm("a6") = bbase;
    if (fd < 0 || fd > 255) return;
    for (i = 0; i < 8; i++) rset[i] = 0;
    rset[fd >> 5] = (1UL << (fd & 31));
    tv[0] = (ULONG)secs; tv[1] = 0;
    a0 = (APTR)rset; a3 = (APTR)tv;
    __asm volatile ("jsr -126(%%a6)"
        : "+d"(d0) : "a"(a0), "a"(a1), "a"(a2), "a"(a3), "d"(d1), "a"(a6)
        : "cc", "memory");
}

/* WaitSelect for the fd becoming WRITABLE (write set in a1), bounded by secs. */
static void wait_writable(APTR bbase, LONG fd, LONG secs)
{
    ULONG wset[8], tv[2];
    UWORD i;
    register LONG  d0 __asm("d0") = fd + 1;
    register APTR  a0 __asm("a0") = (APTR)0;
    register APTR  a1 __asm("a1");
    register APTR  a2 __asm("a2") = (APTR)0;
    register APTR  a3 __asm("a3");
    register ULONG d1 __asm("d1") = 0;
    register APTR  a6 __asm("a6") = bbase;
    if (fd < 0 || fd > 255) return;
    for (i = 0; i < 8; i++) wset[i] = 0;
    wset[fd >> 5] = (1UL << (fd & 31));
    tv[0] = (ULONG)secs; tv[1] = 0;
    a1 = (APTR)wset; a3 = (APTR)tv;
    __asm volatile ("jsr -126(%%a6)"
        : "+d"(d0) : "a"(a0), "a"(a1), "a"(a2), "a"(a3), "d"(d1), "a"(a6)
        : "cc", "memory");
}

/* SSL* handle <-> session (1-based, so 0 = NULL).  Stride is a power of two, so
 * all index math below is shifts (<<9 / >>9), never a libgcc mul/div helper.
 *
 * The handle is offset by SSL_HANDLE_BASE so it lands in [0x1000,0xFFFFFFF0):
 * AWeb 3.6b8 range-checks every SSL/SSL_CTX pointer it gets from AmiSSL against
 * that window (amissl.c Assl_openssl/Assl_connect) and rejects anything below
 * 0x1000 as "corrupted".  A bare 1-based index (1..MAX) fails that check, so the
 * whole handle space is lifted above 0x1000.  iBrowse never range-checks, so it
 * was happy with the small values; AWeb is not.  The handle is opaque to every
 * caller except sess_from_ssl, which strips the base back off. */
#define SSL_HANDLE_BASE 0x5000UL
static struct SslSess *sess_at(UWORD i)
{ return (struct SslSess *)(g_sess_mem + ((ULONG)i << 12)); }   /* i * 4096 */
static SSL *sess_handle(struct SslSess *s)
{
    ULONG off = (ULONG)((UBYTE *)s - g_sess_mem);
    return (SSL *)(SSL_HANDLE_BASE + (off >> 12) + 1);
}
static struct SslSess *sess_from_ssl(SSL *ssl)
{
    ULONG i = (ULONG)ssl;
    struct SslSess *s;
    if (i <= SSL_HANDLE_BASE || i > SSL_HANDLE_BASE + ORACLE_MAX_SESS)
        return (struct SslSess *)0;
    i -= SSL_HANDLE_BASE;                /* back to 1-based session index (1..MAX) */
    s = sess_at((UWORD)(i - 1));
    return s->used ? s : (struct SslSess *)0;
}
static void diag_reset(void);   /* defined with the poll-diagnostics globals below */
static struct SslSess *sess_alloc(void)
{
    struct ExecBase *SysBase = g_SysBase;   /* for Forbid/Permit (proto/exec) */
    struct SslSess *ret = (struct SslSess *)0;
    UWORD i;
    if (SysBase) Forbid();                  /* parallel image tasks race here */
    for (i = 0; i < ORACLE_MAX_SESS; i++) {
        struct SslSess *s = sess_at(i);
        if (!s->used) {
            s->used = 1; s->fd = -1; s->cfd = -1;
            s->oracle_id = 0; s->pending = 0; s->want_read = 0;
            s->plain_off = 0; s->plain_len = 0; s->sni[0] = 0;
            s->bbase = (APTR)0;   /* SSL_new pins it to the caller task's base */
            s->exdata = (APTR)0;
            diag_reset();   /* fresh poll-diagnostics window for this connection */
            ret = s;
            break;
        }
    }
    if (SysBase) Permit();
    return ret;
}

/* dotted-decimal IPv4 -> network-order ULONG (68k is big-endian). */
static ULONG parse_ipv4(const char *s)
{
    ULONG v = 0, oct = 0;
    while (*s) {
        if (*s >= '0' && *s <= '9') oct = oct * 10 + (ULONG)(*s - '0');
        else if (*s == '.')       { v = (v << 8) | (oct & 0xff); oct = 0; }
        s++;
    }
    return (v << 8) | (oct & 0xff);
}

/* GetVar(name a0, buffer a1, size d0, flags d1) — dos.library LVO -906.
 * Returns the variable's length, or -1 if it does not exist. */
static LONG _dos_getvar(APTR dosbase, STRPTR name, STRPTR buf, LONG size)
{
    register LONG   d0   __asm("d0") = size;
    register LONG   d1   __asm("d1") = 0;     /* flags 0: local then global ENV: */
    register STRPTR a0   __asm("a0") = name;
    register STRPTR a1   __asm("a1") = buf;
    register APTR   base __asm("a6") = dosbase;
    __asm volatile ("jsr -906(%%a6)"
        : "+d"(d0)
        : "a"(base), "a"(a0), "a"(a1), "d"(d1)
        : "cc", "memory");
    return d0;
}

/* Read ENV:AMISSLPROXY ("host:port") ONCE into g_daemon_ip / g_daemon_port so the
 * shim can be pointed at any LAN daemon without recompiling (the Installer writes
 * this var).  host may be a dotted-quad IP or a hostname; port is decimal.  On any
 * failure the compiled-in defaults stand (g_daemon_ip stays 0). */
static void resolve_daemon(APTR bbase)
{
    struct ExecBase *SysBase = g_SysBase;
    struct Library  *DOSBase;
    UBYTE buf[80];
    LONG  n;
    UWORD i, colon, port, isip;

    if (g_cfg_done) return;
    g_cfg_done = 1;
    if (!SysBase) return;

    DOSBase = OpenLibrary((CONST_STRPTR)"dos.library", 36);
    if (!DOSBase) return;
    n = _dos_getvar((APTR)DOSBase, (STRPTR)"AMISSLPROXY", (STRPTR)buf, (LONG)sizeof(buf) - 1);
    CloseLibrary(DOSBase);
    if (n <= 0) return;
    buf[n] = 0;
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' ||
                     buf[n-1] == ' '  || buf[n-1] == '\t'))
        buf[--n] = 0;

    colon = 0xFFFF;
    for (i = 0; buf[i]; i++) if (buf[i] == ':') colon = i;   /* last ':' splits host:port */
    if (colon == 0xFFFF || buf[colon + 1] == 0) return;

    port = 0;
    for (i = (UWORD)(colon + 1); buf[i]; i++) {
        if (buf[i] < '0' || buf[i] > '9') { port = 0; break; }
        port = (UWORD)(port * 10 + (buf[i] - '0'));
    }
    if (port == 0) return;
    buf[colon] = 0;   /* terminate host */

    isip = 1;
    for (i = 0; buf[i]; i++)
        if ((buf[i] < '0' || buf[i] > '9') && buf[i] != '.') { isip = 0; break; }

    if (isip) {
        g_daemon_ip = parse_ipv4((const char *)buf);
    } else if (bbase) {
        struct ami_hostent *he = _bsd_gethostbyname(bbase, (STRPTR)buf);
        if (he && he->h_addr_list && he->h_addr_list[0]) {
            UBYTE *p = (UBYTE *)he->h_addr_list[0];   /* 4 bytes, network order */
            g_daemon_ip = ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) |
                          ((ULONG)p[2] << 8)  |  (ULONG)p[3];
        }
    }
    if (g_daemon_ip) g_daemon_port = port;   /* set both, or neither (full fallback) */
}

static ULONG daemon_ip(APTR bbase)
{
    resolve_daemon(bbase);
    return g_daemon_ip ? g_daemon_ip : parse_ipv4(ORACLE_HOST_DEFAULT);
}
static UWORD daemon_port(APTR bbase)
{
    resolve_daemon(bbase);
    return g_daemon_port ? g_daemon_port : (UWORD)ORACLE_PORT_DEFAULT;
}

static LONG ctrl_send_all(APTR bbase, LONG cfd, const UBYTE *p, LONG n)
{
    LONG off = 0, r;
    while (off < n) {
        r = _bsd_send(bbase, cfd, (CONST_APTR)(p + off), n - off, 0);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}
static LONG ctrl_recv_all(APTR bbase, LONG cfd, UBYTE *p, LONG n)
{
    LONG off = 0, r;
    while (off < n) {
        r = _bsd_recv(bbase, cfd, (APTR)(p + off), n - off, 0);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

/* Open a FRESH control socket to the daemon for this session.  Per-session (not
 * shared/persistent): the previous design's single socket got torn down when
 * iBrowse closed its first connection, so the next SSL_connect failed. */
static LONG sess_ctrl_open(APTR bbase, struct SslSess *s)
{
    struct ami_sockaddr_in sa;
    LONG fd; UWORD i;
    if (s->cfd >= 0) return 0;
    fd = _bsd_socket(bbase, 2, 1, 0);
    if (fd < 0) return -1;
    sa.sin_family = 2;
    sa.sin_port   = daemon_port(bbase);             /* ENV:AMISSLPROXY or default */
    sa.sin_addr   = daemon_ip(bbase);
    for (i = 0; i < 8; i++) sa.sin_zero[i] = 0;
    if (_bsd_connect(bbase, fd, (APTR)&sa, 16) != 0) {
        _bsd_closesocket(bbase, fd);
        return -1;
    }
    s->cfd = fd;
    return 0;
}

/* One oracle RPC over the session's control socket `cfd`.  `out` (if any) is read
 * into outbuf (<= outmax).  `in` and `outbuf` may alias.  Returns status or -1. */
static LONG oracle_rpc(APTR bbase, LONG cfd, UBYTE op, ULONG ssl_id, ULONG aux,
                       const UBYTE *in, LONG inlen,
                       UBYTE *outbuf, LONG outmax,
                       ULONG *ppending, LONG *poutlen)
{
    UBYTE hdr[13], rhdr[9];
    ULONG outlen;
    if (cfd < 0) return -1;
    hdr[0]  = op;
    hdr[1]  = (UBYTE)(ssl_id >> 24); hdr[2]  = (UBYTE)(ssl_id >> 16);
    hdr[3]  = (UBYTE)(ssl_id >> 8);  hdr[4]  = (UBYTE)ssl_id;
    hdr[5]  = (UBYTE)(aux >> 24);    hdr[6]  = (UBYTE)(aux >> 16);
    hdr[7]  = (UBYTE)(aux >> 8);     hdr[8]  = (UBYTE)aux;
    hdr[9]  = (UBYTE)(((ULONG)inlen) >> 24); hdr[10] = (UBYTE)(((ULONG)inlen) >> 16);
    hdr[11] = (UBYTE)(((ULONG)inlen) >> 8);  hdr[12] = (UBYTE)inlen;
    if (ctrl_send_all(bbase, cfd, hdr, 13) != 0) return -1;
    if (inlen > 0 && ctrl_send_all(bbase, cfd, in, inlen) != 0) return -1;
    if (ctrl_recv_all(bbase, cfd, rhdr, 9) != 0) return -1;
    if (ppending)
        *ppending = ((ULONG)rhdr[1] << 24) | ((ULONG)rhdr[2] << 16) |
                    ((ULONG)rhdr[3] << 8) | rhdr[4];
    outlen = ((ULONG)rhdr[5] << 24) | ((ULONG)rhdr[6] << 16) |
             ((ULONG)rhdr[7] << 8) | rhdr[8];
    if (outlen > 0) {
        if ((LONG)outlen > outmax) return -1;
        if (ctrl_recv_all(bbase, cfd, outbuf, (LONG)outlen) != 0) return -1;
    }
    if (poutlen) *poutlen = (LONG)outlen;
    return (LONG)rhdr[0];
}

/* DIAGNOSTIC: report a progress marker to the daemon over the control socket.
 * Uses a tiny local buffer (NOT s->scratch) so it never disturbs handshake data.
 * Routed to dbg_probe under AMISSL_PROBE so the per-SSL-function call sites trace
 * the app's exact call sequence (used to debug AWeb's HTTPS path). */
static void dbg_probe(APTR bbase, ULONG marker);   /* fwd decl (defined below) */
static void probe_marker(APTR bbase, ULONG m)
{
#if AMISSL_PROBE
    dbg_probe(bbase, m);
#else
    (void)bbase; (void)m;
#endif
}

/* PROXY model via Dup2Socket.  iBrowse caches its bsdsocket vectors, so we can't
 * intercept its connect()/recv()/WaitSelect() with SetFunction.  Instead, at
 * SSL_connect (which iBrowse DOES route through us), we open OUR OWN socket to the
 * LAN daemon (tls_proxy.py), send "CONNECT <host> <port>\n", get "OK\n" (the daemon
 * has now done the verified TLS to the real server), and then Dup2Socket() our socket
 * onto iBrowse's fd.  That remaps iBrowse's fd-number to the daemon connection, so its
 * cached recv/WaitSelect now operate on the plaintext stream — the a314 model (the
 * bytes really are on the socket, readable on any task).  SSL_read/write become plain
 * recv/send.  Returns 1 on success, -1 on failure. */
/* UWORD -> decimal ASCII (no libgcc div; we link -nostdlib).  Writes digits to
 * `out`, returns the count.  Used to put the real target port in the CONNECT line. */
static UWORD u16_to_dec(UWORD v, UBYTE *out)
{
    UWORD pw[5], i, n = 0, started = 0;
    pw[0] = 10000; pw[1] = 1000; pw[2] = 100; pw[3] = 10; pw[4] = 1;
    for (i = 0; i < 5; i++) {
        UBYTE d = 0;
        while (v >= pw[i]) { v = (UWORD)(v - pw[i]); d++; }
        if (d || started || i == 4) { out[n++] = (UBYTE)('0' + d); started = 1; }
    }
    return n;
}
static LONG sess_connect(APTR bbase, struct SslSess *s)
{
    struct ami_sockaddr_in sa;
    UBYTE line[300];
    LONG  sfd, ll = 0, off, r, n;
    UWORD i, port = 443;   /* default; learned from the app's own fd below */
    const char *cmd = "CONNECT ";

    /* Use the session's own task SocketBase (captured at SSL_new), not the shared
     * base->BsdBase a sibling task may have overwritten. */
    if (s->bbase) bbase = s->bbase;

    /* TRACE: did SSL_connect reach the tunnel, and is the app fd set? (0x5C | fd;
     * fd==0xFFFF means s->fd < 0 -> app never did SSL_set_fd, e.g. AWeb's BIO path). */
    probe_marker(bbase, 0x5C000000UL | ((ULONG)s->fd & 0xFFFF));
    if (s->fd < 0) return -1;

    /* Learn the real target port from the app's own (already-connected) fd, so the
     * tunnel isn't limited to HTTPS:443.  The app connected s->fd to host:port
     * before SSL_connect; getpeername reports that port.  Falls back to 443.
     * (The daemon's CONNECT handshake already accepts an explicit port.) */
    {
        struct ami_sockaddr_in pn;
        LONG pnlen = (LONG)sizeof(pn);
        for (i = 0; i < 8; i++) pn.sin_zero[i] = 0;
        pn.sin_port = 0;
        if (_bsd_getpeername(bbase, s->fd, (APTR)&pn, (APTR)&pnlen) == 0 && pn.sin_port)
            port = pn.sin_port;   /* network order == host order on big-endian 68k */
    }

    /* 1. our own (blocking) socket to the LAN daemon */
    sfd = _bsd_socket(bbase, 2, 1, 0);
    if (sfd < 0) return -1;
    sa.sin_family = 2;
    sa.sin_port   = daemon_port(bbase);                  /* ENV:AMISSLPROXY or default */
    sa.sin_addr   = daemon_ip(bbase);
    for (i = 0; i < 8; i++) sa.sin_zero[i] = 0;
    if (_bsd_connect(bbase, sfd, (APTR)&sa, 16) != 0) { _bsd_closesocket(bbase, sfd); return -1; }

    /* 2. send "CONNECT <sni> <port>\n" (port learned from the app fd above) */
    for (i = 0; cmd[i]; i++) line[ll++] = (UBYTE)cmd[i];
    for (i = 0; s->sni[i] && ll < 280; i++) line[ll++] = (UBYTE)s->sni[i];
    line[ll++] = ' ';
    ll += (LONG)u16_to_dec(port, &line[ll]);
    line[ll++] = '\n';
    for (off = 0; off < ll; off += r) {
        r = _bsd_send(bbase, sfd, (CONST_APTR)(line + off), ll - off, 0);
        if (r <= 0) { _bsd_closesocket(bbase, sfd); return -1; }
    }

    /* 3. read the daemon's status line; "OK\n" = TLS up, "ERR ...\n" = failed */
    {
        UBYTE c, ok = 0, first = 1; LONG got = 0;
        for (;;) {
            n = _bsd_recv(bbase, sfd, (APTR)&c, 1, 0);
            if (n != 1) { _bsd_closesocket(bbase, sfd); return -1; }
            if (first) { ok = (c == 'O'); first = 0; }
            if (c == '\n') break;
            if (++got > 80) break;
        }
        if (!ok) { _bsd_closesocket(bbase, sfd); return -1; }
    }

    /* 4. swap iBrowse's fd onto the daemon connection, then drop our extra ref */
    if (_bsd_dup2socket(bbase, sfd, s->fd) < 0) { _bsd_closesocket(bbase, sfd); return -1; }
    _bsd_closesocket(bbase, sfd);
    s->oracle_id = 1;   /* relay established (reused field = "connected" flag) */
    return 1;
}

/* PROXY WRITE: plaintext straight onto the socket (daemon encrypts).  Returns
 * bytes written (>0), 0, or -1 (with want_read set on EWOULDBLOCK = WANT_WRITE). */
static LONG sess_write(APTR bbase, struct SslSess *s, const UBYTE *buf, LONG num)
{
    LONG done = 0, r;
    if (s->bbase) bbase = s->bbase;     /* this session's task SocketBase */
    while (done < num) {
        r = _bsd_send(bbase, s->fd, (CONST_APTR)(buf + done), num - done, 0);
        if (r > 0) { done += r; continue; }
        if (r < 0 && _bsd_errno(bbase) == EWOULDBLOCK_AMI) {
            if (done > 0) return done;          /* partial; app retries the rest */
            s->want_read = 1; return -1;        /* WANT_WRITE */
        }
        return (done > 0) ? done : -1;
    }
    s->want_read = 0;
    return num;
}

/* PROXY READ: the socket carries the daemon's decrypted plaintext, so this is just
 * a passthrough recv on iBrowse's own fd.  iBrowse reads the full stream at its own
 * pace exactly as it would a plain-HTTP socket — readability is real on any task.
 * Returns bytes (>0), 0 on EOF (daemon/server closed), -1 on WANT_READ/error. */
static LONG sess_read(APTR bbase, struct SslSess *s, UBYTE *buf, LONG num)
{
    LONG n;
    if (s->bbase) bbase = s->bbase;     /* this session's task SocketBase */
    n = _bsd_recv(bbase, s->fd, (APTR)buf, num, 0);
    if (n > 0)  { s->want_read = 0; return n; }
    if (n == 0) { s->want_read = 0; return 0; }   /* clean EOF */
    if (_bsd_errno(bbase) == EWOULDBLOCK_AMI) { s->want_read = 1; return -1; }  /* WANT_READ */
    s->want_read = 0; return -1;
}

/* ===========================================================================
 * TLS-aware socket patch — SetFunction WaitSelect/IoctlSocket on the resident
 * bsdsocket.library.  iBrowse drives its read loop off WaitSelect/FIONREAD on
 * the raw socket; decrypted-but-unread plaintext lives on the LAN daemon, so a
 * raw poll says "nothing there" and iBrowse truncates large responses.  We make
 * those two calls report an SSL fd readable / FIONREAD>0 when the daemon holds
 * pending plaintext (s->pending).  amissl.library never expunges, so the patch
 * stays valid for the life of the system — no restore needed.
 * =========================================================================== */

extern void WrapWaitSelect(void);    /* a6-safe trampolines in amissl_start.S */
extern void WrapIoctlSocket(void);
extern void WrapConnect(void);

static APTR  g_old_waitselect  = (APTR)0;
static APTR  g_old_ioctlsocket = (APTR)0;
static APTR  g_old_connect     = (APTR)0;

/* iBrowse calls InitAmiSSL per-task, each with its OWN SocketBase; patch each
 * distinct base (dedup) so every connection task's WaitSelect/FIONREAD is hooked. */
#define MAX_PATCHED_BASES 12
static APTR  g_patched_bases[MAX_PATCHED_BASES];
static UWORD g_npatched = 0;

/* --- live poll diagnostics, reset each sess_alloc (one connection) ---------
 * The truncated connection never reaches SSL_shutdown/FREE (iBrowse drops it),
 * so we must emit during the read window.  Capped emissions avoid flooding. */
static UWORD g_diag_ws_emit  = 0;   /* WaitSelect-while-pending probes emitted */
static UWORD g_diag_io_emit  = 0;   /* FIONREAD-on-SSL-fd probes emitted */
static UWORD g_diag_seq      = 0;   /* WaitSelect-while-pending call sequence */
static UWORD g_diag_ssl_emit = 0;   /* SSL_read / SSL_get_error probes emitted */
#define DIAG_EMIT_CAP 8
#define DIAG_SSL_CAP 16
static void diag_reset(void)
{ g_diag_ws_emit = 0; g_diag_io_emit = 0; g_diag_seq = 0; g_diag_ssl_emit = 0; }

static void dbg_probe(APTR bbase, ULONG marker);   /* fwd decl (defined below) */

#define FIONREAD 0x4004667FUL

/* Call a saved original bsdsocket vector with the proper register convention. */
static LONG call_old_ws(APTR fn, LONG nfds, APTR rf, APTR wf, APTR ef, APTR tv,
                        ULONG sm, APTR sb)
{
    register LONG  d0  __asm("d0") = nfds;
    register APTR  a0  __asm("a0") = rf;
    register APTR  a1  __asm("a1") = wf;
    register APTR  a2  __asm("a2") = ef;
    register APTR  a3  __asm("a3") = tv;
    register ULONG d1  __asm("d1") = sm;
    register APTR  a6  __asm("a6") = sb;
    register APTR  fnr __asm("a5") = fn;
    __asm volatile ("jsr (%%a5)"
        : "+d"(d0)
        : "a"(a0), "a"(a1), "a"(a2), "a"(a3), "d"(d1), "a"(a6), "a"(fnr)
        : "cc", "memory");
    return d0;
}
static LONG call_old_ioctl(APTR fn, LONG fd, ULONG req, APTR argp, APTR sb)
{
    register LONG  d0  __asm("d0") = fd;
    register ULONG d1  __asm("d1") = req;
    register APTR  a0  __asm("a0") = argp;
    register APTR  a6  __asm("a6") = sb;
    register APTR  fnr __asm("a5") = fn;
    __asm volatile ("jsr (%%a5)"
        : "+d"(d0)
        : "d"(d1), "a"(a0), "a"(a6), "a"(fnr)
        : "a1", "cc", "memory");
    return d0;
}
/* connect(fd, name, namelen)(d0,a0,d1) -> LONG; a6 = SocketBase. */
static LONG call_old_connect(APTR fn, LONG fd, APTR name, LONG namelen, APTR sb)
{
    register LONG  d0  __asm("d0") = fd;
    register APTR  a0  __asm("a0") = name;
    register LONG  d1  __asm("d1") = namelen;
    register APTR  a6  __asm("a6") = sb;
    register APTR  fnr __asm("a5") = fn;
    __asm volatile ("jsr (%%a5)"
        : "+d"(d0)
        : "a"(a0), "d"(d1), "a"(a6), "a"(fnr)
        : "a1", "cc", "memory");
    return d0;
}
/* AmiTCP fd_set: long-array bitmask, bit fd in word fd/32. */
static int  fd_isset(APTR set, LONG fd)
{ return set && (((ULONG *)set)[fd >> 5] & (1UL << (fd & 31))) != 0; }
static void fd_set_bit(APTR set, LONG fd)
{ if (set) ((ULONG *)set)[fd >> 5] |= (1UL << (fd & 31)); }

/* Patched WaitSelect — force our SSL fds readable when the daemon holds plaintext. */
LONG ami_new_waitselect(LONG nfds __asm("d0"), APTR rfds __asm("a0"),
                         APTR wfds __asm("a1"), APTR efds __asm("a2"),
                         APTR tv __asm("a3"), ULONG smask __asm("d1"),
                         APTR sb __asm("a6"))
{
    LONG  ready[ORACLE_MAX_SESS];
    UWORD nready = 0, i;
    LONG  r;
    ULONG ztv[2];                       /* struct timeval {sec,usec} = {0,0} */
    APTR  use_tv = tv;
    LONG  diag_fd = -1;
    ULONG diag_pend = 0;
    UBYTE diag_any = 0, diag_inset = 0;

    ztv[0] = 0; ztv[1] = 0;

    /* TRACE (AWeb connect debug): first few WaitSelect calls of each attempt.
     * 0x77 | (nfds<<4) | rfds-present(1) | wfds-present(2).  wfds set = connect-wait. */
    if (g_diag_ws_emit < DIAG_EMIT_CAP) {
        g_diag_ws_emit++;
        dbg_probe(sb, 0x77000000UL | (((ULONG)nfds & 0xFFFFUL) << 4)
                       | (rfds ? 1UL : 0UL) | (wfds ? 2UL : 0UL));
    }

    /* Survey every session: is plaintext buffered, and is its fd in the read set
     * iBrowse is polling?  Build the force-readable list at the same time. */
    for (i = 0; i < ORACLE_MAX_SESS; i++) {
        struct SslSess *s = sess_at(i);
        if (s->used && s->pending > 0) {
            UBYTE inset = (rfds && s->fd >= 0 && fd_isset(rfds, s->fd)) ? 1 : 0;
            if (!diag_any) { diag_any = 1; diag_fd = s->fd;
                             diag_pend = s->pending; diag_inset = inset; }
            if (inset && s->fd < nfds) ready[nready++] = s->fd;
        }
    }

    /* LIVE diagnostics: emit on every WaitSelect call made while we hold pending
     * plaintext (capped).  0x58 once = nfds + the SSL fd; 0x57 per call = seq,
     * fd-in-set, rfds-non-null, pending.  This is the ground truth on whether
     * iBrowse re-polls this socket to resume reading the rest of the response. */
    if (diag_any && g_diag_ws_emit < DIAG_EMIT_CAP) {
        g_diag_ws_emit++;
        if (g_diag_seq == 0)
            dbg_probe(sb, 0x58000000UL | (((ULONG)nfds & 0xFFF) << 12)
                           | ((ULONG)diag_fd & 0xFFF));
        g_diag_seq++;
        dbg_probe(sb, 0x57000000UL | (((ULONG)g_diag_seq & 0xF) << 20)
                       | ((ULONG)diag_inset << 19) | ((rfds ? 1UL : 0UL) << 18)
                       | (diag_pend & 0x3FFFFUL));
    }

    if (nready) use_tv = (APTR)ztv;     /* buffered data -> don't block */

    r = call_old_ws(g_old_waitselect, nfds, rfds, wfds, efds, use_tv, smask, sb);

    if (nready) {
        if (r < 0) r = 0;               /* override timeout/err: we have data */
        for (i = 0; i < nready; i++)
            if (!fd_isset(rfds, ready[i])) { fd_set_bit(rfds, ready[i]); r++; }
    }
    return r;
}

/* Patched IoctlSocket — FIONREAD reports our pending plaintext for SSL fds. */
LONG ami_new_ioctlsocket(LONG fd __asm("d0"), ULONG req __asm("d1"),
                          APTR argp __asm("a0"), APTR sb __asm("a6"))
{
    if (req == 0x8004667EUL) {   /* FIONBIO: confirm (non-)blocking mode iBrowse sets */
        dbg_probe(sb, 0x4E420000UL | ((argp && *(ULONG *)argp) ? 1UL : 0UL));
    } else if (req != FIONREAD && g_diag_io_emit < DIAG_EMIT_CAP) {
        /* DIAG: surface any OTHER ioctl (e.g. FIOASYNC 0x8004667D) iBrowse uses to
         * arm async-readable notification — reveals its wait mechanism. */
        g_diag_io_emit++;
        dbg_probe(sb, 0x49000000UL | (req & 0x00FFFFFFUL));
    }
    if (req == FIONREAD && argp) {
        UWORD i;
        for (i = 0; i < ORACLE_MAX_SESS; i++) {
            struct SslSess *s = sess_at(i);
            if (s->used && s->fd == fd) {
                if (g_diag_io_emit < DIAG_EMIT_CAP) {   /* FIONREAD on an SSL fd */
                    g_diag_io_emit++;
                    dbg_probe(sb, 0x53000000UL | (s->pending & 0x00FFFFFFUL)); }
                if (s->pending > 0) { *(LONG *)argp = (LONG)s->pending; return 0; }
                break;
            }
        }
    }
    return call_old_ioctl(g_old_ioctlsocket, fd, req, argp, sb);
}

static void dbg_probe(APTR bbase, ULONG marker);   /* fwd decl */

/* Patched connect() — PROXY model.  When iBrowse connects to a server on :443,
 * redirect the socket to the LAN daemon instead.  The shim's SSL_connect then sends
 * the daemon a CONNECT request naming the real host (from SNI), the daemon does the
 * TLS, and the socket carries plaintext.  Non-443 connects pass through untouched. */
LONG ami_new_connect(LONG fd __asm("d0"), APTR name __asm("a0"),
                     LONG namelen __asm("d1"), APTR sb __asm("a6"))
{
    struct ami_sockaddr_in *sa = (struct ami_sockaddr_in *)name;
    if (sa && namelen >= 8 && sa->sin_family == 2 && sa->sin_port == 443) {
        struct ami_sockaddr_in d;
        UWORD i;
        d.sin_family = 2;
        d.sin_port   = daemon_port(sb);                  /* ENV:AMISSLPROXY or default */
        d.sin_addr   = daemon_ip(sb);                    /* the LAN daemon */
        for (i = 0; i < 8; i++) d.sin_zero[i] = 0;
        (void)sb;
        return call_old_connect(g_old_connect, fd, (APTR)&d, 16, sb);
    }
    return call_old_connect(g_old_connect, fd, name, namelen, sb);
}

/* DIAGNOSTIC: fire-and-forget one marker to the daemon (own short-lived socket). */
static void dbg_probe(APTR bbase, ULONG marker)
{
#if AMISSL_PROBE
    struct ami_sockaddr_in sa;
    UBYTE hdr[13];
    LONG  fd;
    UWORD i;
    if (!bbase) return;
    fd = _bsd_socket(bbase, 2, 1, 0);
    if (fd < 0) return;
    sa.sin_family = 2; sa.sin_port = daemon_port(bbase);
    sa.sin_addr = daemon_ip(bbase);
    for (i = 0; i < 8; i++) sa.sin_zero[i] = 0;
    if (_bsd_connect(bbase, fd, (APTR)&sa, 16) == 0) {
        for (i = 0; i < 13; i++) hdr[i] = 0;
        hdr[0] = OOP_PROBE;
        hdr[5] = (UBYTE)(marker >> 24); hdr[6] = (UBYTE)(marker >> 16);
        hdr[7] = (UBYTE)(marker >> 8);  hdr[8] = (UBYTE)marker;
        (void)_bsd_send(bbase, fd, (CONST_APTR)hdr, 13, 0);
    }
    _bsd_closesocket(bbase, fd);
#else
    (void)bbase; (void)marker;
#endif
}

/* Patch WaitSelect/IoctlSocket on this app SocketBase (idempotent per base). */
static void install_sockpatch(struct AmiSSLBase *base)
{
    struct ExecBase *SysBase = base->SysBase;
    APTR  bb = base->BsdBase, oldws, oldio;
    UWORD i;
    if (!bb || !SysBase) return;
    for (i = 0; i < g_npatched; i++)
        if (g_patched_bases[i] == bb) return;       /* already patched this base */
    Forbid();
    oldws  = SetFunction((struct Library *)bb, -126, (APTR)WrapWaitSelect);
    oldio  = SetFunction((struct Library *)bb, -114, (APTR)WrapIoctlSocket);
    Permit();
    /* Save the REAL originals once (same Roadshow code for every base).
     * NOTE: we no longer patch connect(-54) — iBrowse caches that vector so the
     * patch never fired; the proxy swaps the fd via Dup2Socket at SSL_connect. */
    if (!g_old_waitselect)  g_old_waitselect  = oldws;
    if (!g_old_ioctlsocket) g_old_ioctlsocket = oldio;
    if (g_npatched < MAX_PATCHED_BASES) g_patched_bases[g_npatched++] = bb;
    dbg_probe(bb, 0x5E1F0000UL | ((ULONG)oldws & 0xFFFF));
}

/* ---- Open / Close -------------------------------------------------------- */

struct AmiSSLBase *ami_ssl_open(struct AmiSSLBase *base)
{
    struct ExecBase *SysBase = base->SysBase;

    /* Initialise verify callback to the real callable dummy on first-ever open.
     * We can't use a static initializer because casting a function pointer to
     * APTR (void*) is not a constant expression in strict C99.
     * Also initialise g_verify_store to 1UL (non-NULL sentinel) so that
     * SSL_CTX_ctrl(cmd=124) always writes a valid pointer to *parg even if
     * SET_VERIFY_CERT_STORE was never called. */
    if (!g_verify_callback)
        g_verify_callback = (APTR)dummy_verify_cb;
    if (!g_verify_store)
        g_verify_store = (APTR)1UL;  /* non-NULL X509_STORE* sentinel */

    /* Open the resident bsdsocket.library (Roadshow / AmiTCP / Miami).  Model B
     * uses only standard socket calls (socket/connect/send/recv/close), so ANY
     * stack works — there is NO SSL-LVO / NegSize check (that guard was specific
     * to a314bsd's custom SSL-extended bsdsocket and would reject Roadshow). */
    /* Do NOT open our own bsdsocket.library.  Real AmiSSL uses the app's
     * SocketBase (captured from the AmiSSL_SocketBase tag in InitAmiSSLA); a
     * second per-task bsdsocket open corrupts the app's socket context on
     * Roadshow.  BsdBase is therefore filled in by InitAmiSSLA, not here. */
    g_SysBase = SysBase;   /* used by sess_alloc's Forbid/Permit (parallel tasks) */
    base->lib.lib_OpenCnt++;
    return base;
}

void ami_ssl_close(struct AmiSSLBase *base)
{
    struct ExecBase *SysBase = base->SysBase;
    base->lib.lib_OpenCnt--;
    /* BsdBase is the app's borrowed SocketBase — never CloseLibrary it; just
     * forget it on the final close so the next InitAmiSSL re-captures one. */
    (void)SysBase;
    if (base->lib.lib_OpenCnt == 0) base->BsdBase = (APTR)0;
}

/* ---- AmiSSL tag constants (from amissl/tags.h) --------------------------- */
/*
 * Used by InitAmiSSLA to locate the AmiSSL_GetAmiSSLBase tag, which is how
 * the calling app gets the amissl library base pointer in the AmiSSL 4/5 API.
 *
 * When amisslmaster's OpenAmiSSLTagList() calls InitAmiSSLA(tagList), the
 * tagList contains {AmiSSL_GetAmiSSLBase, (ULONG)&app_AmiSSLBase}.
 * We write our library base into that pointer so the app can use it.
 */
#define AMISSL_TAG_BASE         0x80000000UL   /* TAG_USER */
#define AmiSSL_SocketBase       (AMISSL_TAG_BASE + 0x01)
#define AmiSSL_GetAmiSSLBase    (AMISSL_TAG_BASE + 0x0d)
#define AmiSSL_GetAmiSSLExtBase (AMISSL_TAG_BASE + 0x0e)
#define TAG_DONE                0UL

/* Proper tag-list scan: honours TAG_IGNORE(1)/TAG_MORE(2)/TAG_SKIP(3) chaining.
 * The old `tag += 2` walk could not follow TAG_MORE — which is exactly how iBrowse
 * chains in the list that carries AmiSSL_SocketBase, so we never found it. */
static ULONG find_tag(ULONG *tl, ULONG id, ULONG def)
{
    UWORD guard = 0;
    if (!tl) return def;
    while (guard++ < 64) {
        ULONG t = tl[0];
        if (t == 0)       return def;                /* TAG_END   */
        else if (t == 1)  tl += 2;                   /* TAG_IGNORE */
        else if (t == 2)  { tl = (ULONG *)tl[1]; if (!tl) return def; }  /* TAG_MORE */
        else if (t == 3)  tl += 2 + 2 * tl[1];       /* TAG_SKIP  */
        else if (t == id) return tl[1];
        else tl += 2;
    }
    return def;
}

/* ---- InitAmiSSLA / CleanupAmiSSLA --------------------------------------- */
/*
 * InitAmiSSLA(tagList)(a0)  — LVO -36
 * CleanupAmiSSLA(tagList)(a0) — LVO -42
 *
 * Two different calling conventions exist depending on AmiSSL version:
 *
 *   AmiSSL 2/3 (direct OpenLibrary path):
 *     Returns TRUE (non-zero) = success.  Apps check: if (!InitAmiSSLA(tags))
 *
 *   AmiSSL 4/5 (via amisslmaster OpenAmiSSLTagList):
 *     Returns 0 = success (error-code style).  amisslmaster checks: == 0
 *     Also MUST process AmiSSL_GetAmiSSLBase tag so the app's AmiSSLBase
 *     global gets set to our library base pointer.
 *
 * We implement the AmiSSL 4/5 convention (return 0 = success) and process
 * AmiSSL_GetAmiSSLBase, since iBrowse 3.0 uses amisslmaster + OpenAmiSSLTagList.
 *
 * The tagList may also contain AmiSSL_SocketBase, AmiSSL_ErrNoPtr, etc. —
 * we ignore these because we open our own bsdsocket.library and the Pi
 * handles the actual TLS; the Amiga side doesn't do OpenSSL socket I/O.
 */

LONG ami_InitAmiSSLA(APTR tagList_a0 __asm("a0"),
                     struct AmiSSLBase *base __asm("a6"))
{
    ULONG *tl = (ULONG *)tagList_a0;
    ULONG sb, p;

    /* Capture the app's SocketBase and USE it for all our socket I/O — this is
     * exactly what real AmiSSL does (src/amissl_library.c:
     * GetTagData(AmiSSL_SocketBase)); it never opens its own bsdsocket.  Opening
     * a 2nd per-task base on Roadshow corrupted iBrowse's socket context. */
    sb = find_tag(tl, AmiSSL_SocketBase, 0);
    if (sb) {
        struct ExecBase *SysBase = base->SysBase;
        base->BsdBase = (APTR)sb;
        /* Record THIS task's SocketBase so its own SSL sessions keep using it
         * even after a sibling image-fetch task overwrites base->BsdBase. */
        if (SysBase) task_bb_set((APTR)FindTask((STRPTR)0), (APTR)sb);
    }

    /* Write our library base where the app asked. */
    p = find_tag(tl, AmiSSL_GetAmiSSLBase, 0);
    if (p) *(ULONG *)p = (ULONG)base;
    p = find_tag(tl, AmiSSL_GetAmiSSLExtBase, 0);
    if (p) *(ULONG *)p = (ULONG)base;

    /* Install the TLS-aware WaitSelect/FIONREAD patch on the app's bsdsocket so
     * its socket-poll read loop can see plaintext buffered on the LAN daemon. */
    if (base->BsdBase)
        install_sockpatch(base);
    return 0;   /* 0 = success (AmiSSL 4/5 convention) */
}

void ami_CleanupAmiSSLA(APTR tags __asm("a0"),
                         struct AmiSSLBase *base __asm("a6"))
{
    struct ExecBase *SysBase = base->SysBase;
    (void)tags;
    if (SysBase) task_bb_clear((APTR)FindTask((STRPTR)0));
}

/* ---- OPENSSL_init_ssl (LVO -26568, slot 4428) --------------------------------
 * Initialises the SSL library.  Returns 1 on success, 0 on failure.
 * iBrowse 3.0 (AmiSSL 5+) calls this during startup and may abort if it
 * returns 0.  Our shim has nothing to initialise (Pi handles everything),
 * so we always return 1 = success.
 *
 * opts(d0) = OPENSSL_INIT_* flags, settings(a0) = OPENSSL_INIT_SETTINGS* or NULL
 */
LONG ami_OPENSSL_init_ssl(ULONG opts __asm("d0"), APTR settings __asm("a0"),
                           struct AmiSSLBase *base __asm("a6"))
{
    (void)opts; (void)settings;
    return 1;
}

/* ---- SSL_CTX_new_ex (LVO -32370, slot 5395) ---------------------------------
 * OpenSSL 3.x / AmiSSL 5+ version of SSL_CTX_new that takes an explicit
 * library context and property query string.  In AmiSSL 5 SDK headers,
 * SSL_CTX_new(meth) is typically compiled as SSL_CTX_new_ex(NULL,NULL,meth).
 *
 * libctx(a0) = OSSL_LIB_CTX* (NULL = global context; we ignore it)
 * propq(a1)  = const char* property query (always NULL from iBrowse; ignored)
 * meth(a2)   = const SSL_METHOD* (ignored; Pi always uses TLS_CLIENT)
 */
SSL_CTX *ami_SSL_CTX_new_ex(APTR libctx __asm("a0"), STRPTR propq __asm("a1"),
                              SSL_METHOD *meth __asm("a2"),
                              struct AmiSSLBase *base __asm("a6"))
{
    (void)libctx; (void)propq; (void)meth;
    probe_marker(base->BsdBase, 0xA0);
    g_last_ctx_id = SSL_CTX_SENTINEL;  /* sentinel; Model B has no daemon-side ctx */
    return (SSL_CTX *)SSL_CTX_SENTINEL;
}

/* ---- OpenSSL_version (LVO -24960, slot 4160) --------------------------------
 * Returns a human-readable version string selected by the type argument.
 * iBrowse calls this to display "Secured by OpenSSL x.x.x" in connection info.
 * Returning NULL here would cause iBrowse to crash when displaying it.
 *
 * type values (OPENSSL_VERSION=0, OPENSSL_CFLAGS=1, OPENSSL_BUILT_ON=2,
 *              OPENSSL_PLATFORM=3, OPENSSL_DIR=4)
 */
STRPTR ami_OpenSSL_version(LONG type __asm("d0"),
                             struct AmiSSLBase *base __asm("a6"))
{
    static const char v0[] = "OpenSSL 3.6.2 (a314ssl shim)";
    static const char v1[] = "a314ssl";
    static const char v2[] = "built today";
    static const char v3[] = "Amiga";
    static const char v4[] = "/LIBS:";
    (void)base;
    switch (type) {
        case 0:  return (STRPTR)v0;   /* OPENSSL_VERSION */
        case 1:  return (STRPTR)v1;   /* OPENSSL_CFLAGS */
        case 2:  return (STRPTR)v2;   /* OPENSSL_BUILT_ON */
        case 3:  return (STRPTR)v3;   /* OPENSSL_PLATFORM */
        case 4:  return (STRPTR)v4;   /* OPENSSL_DIR */
        default: return (STRPTR)v0;
    }
}

/* ---- OpenSSL_version_num (LVO -24966) ------------------------------------ */
/*
 * Returns the OpenSSL version number encoded as 0xMNN00PP0 (OpenSSL 3.x scheme):
 *   (major << 28) | (minor << 20) | (patch << 4)
 *
 * We report OpenSSL 3.6.2:
 *   (3 << 28) | (6 << 20) | (2 << 4) = 0x30600020
 *
 * iBrowse 3.0 calls this after OpenAmiSSLTagList and requires the result to be
 * >= 0x30100040 (= OpenSSL 3.1.4 minimum).
 */
ULONG ami_OpenSSL_version_num(struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    return 0x30600020UL;   /* OpenSSL 3.6.2 */
}

/* ---- Method constructors ------------------------------------------------- */
/*
 * Return a dummy non-NULL token.  The Pi ignores the method value and always
 * creates ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) with the system CA bundle.
 * We return (SSL_METHOD*)1 so app NULL-checks pass.
 *
 * Note: SSLv23_client_method / SSLv23_method are #define aliases in the
 * AmiSSL headers (not separate LVO entries), so we only need TLS_* here.
 */

SSL_METHOD *ami_TLS_client_method(struct AmiSSLBase *base __asm("a6"))
{ probe_marker(base->BsdBase, 0xA5); return (SSL_METHOD *)1UL; }

SSL_METHOD *ami_TLS_method(struct AmiSSLBase *base __asm("a6"))
{ probe_marker(base->BsdBase, 0xA6); return (SSL_METHOD *)1UL; }

/* ---- SSL_CTX functions --------------------------------------------------- */

/* SSL_CTX_get_cert_store (LVO -8232, slot 1372) ----------------------------
 * iBrowse calls this after SSL_CTX_new to add CA certificates to the context.
 * The real function returns the internal X509_STORE* of the SSL_CTX.
 * Our Pi-side implementation handles all cert verification; there is no real
 * X509_STORE on the Amiga side.
 *
 * We return a non-NULL fake token (ctx itself cast to APTR) so that:
 *   1. iBrowse's "if (!store)" NULL guard passes
 *   2. iBrowse can pass the token back to X509_STORE_* stubs (which return 0
 *      harmlessly without dereferencing it)
 */
APTR ami_SSL_CTX_get_cert_store(SSL_CTX *ctx __asm("a0"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xC4);   /* get_cert_store */
    return ctx ? (APTR)ctx : (APTR)1UL;
}

SSL_CTX *ami_SSL_CTX_new(SSL_METHOD *meth __asm("a0"),
                          struct AmiSSLBase *base __asm("a6"))
{
    (void)meth;
    diag_reset();                      /* fresh socket-probe window per https attempt */
    probe_marker(base->BsdBase, 0xA1);
    g_last_ctx_id = SSL_CTX_SENTINEL;  /* sentinel; Model B has no daemon-side ctx */
    return (SSL_CTX *)SSL_CTX_SENTINEL;
}

void ami_SSL_CTX_free(SSL_CTX *ctx __asm("a0"),
                       struct AmiSSLBase *base __asm("a6"))
{
    (void)base; (void)ctx;   /* sentinel ctx; nothing to free on the daemon */
}

/* ---- Verify callback / mode storage --------------------------------------- */
/*
 * iBrowse calls SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, my_callback) and
 * then later calls SSL_CTX_get_verify_callback() / SSL_CTX_get_verify_mode()
 * / X509_STORE_get_verify_cb() to retrieve what was stored.
 *
 * CRITICAL: returning NULL causes iBrowse to call through NULL → JSR 0 →
 * crash.  Returning 1UL (non-NULL sentinel) passes iBrowse's NULL check, but
 * then iBrowse tries to CALL the returned pointer → JSR 1 → #80000004 crash.
 *
 * Fix: initialize g_verify_callback to a real callable 68K function
 * (dummy_verify_cb below) that accepts and ignores any arguments and returns
 * 1 (= certificate accepted).  The Pi performs actual TLS cert verification;
 * the dummy callback is only ever invoked if iBrowse exercises its verify
 * path on the Amiga side.
 *
 * Also: ami_SSL_CTX_ctrl cmd=123/124 (SET/GET_VERIFY_CERT_STORE) are handled
 * here.  g_verify_store stores the X509_STORE* set by cmd=123; cmd=124 writes
 * it back to *parg so iBrowse's local variable is properly initialised.
 */

/* dummy_verify_cb: no-op verify callback — definition (declared above).
 * OpenSSL verify callbacks use standard C calling convention (args on stack):
 *   int callback(int preverify_ok, X509_STORE_CTX *ctx)
 * On m68k Amiga with gcc, functions without __asm() annotations are called
 * with args pushed on the stack — matching OpenSSL's standard C convention.
 * Returning 1 = accept the certificate (Pi already verified it). */
static LONG dummy_verify_cb(LONG preverify_ok, APTR x509_ctx)
{
    (void)preverify_ok; (void)x509_ctx;
    return 1;   /* accept all certs — Pi's ssl module has already verified them */
}

/* Default return value for every UNIMPLEMENTED LVO.  StubRetZero (in
 * amissl_start.S) routes all unimplemented slots here via the WrapStubProbe
 * a6-preserving trampoline.  We return a real callable no-op (dummy_verify_cb)
 * instead of 0 so that if an app treats the result as a function pointer and
 * JSRs through it, it lands on a safe routine rather than address 0 (#80000004).
 * Args are unused (retaddr was only needed by the removed LVO-logging probe). */
APTR ami_stub_probe(ULONG retaddr __asm("d0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)retaddr; (void)base;
    return (APTR)dummy_verify_cb;   /* non-NULL, callable, JSR-safe */
}

/* g_verify_store: X509_STORE* set via SSL_CTX_ctrl(cmd=123 SET_VERIFY_CERT_STORE).
 * Returned by cmd=124 (GET_VERIFY_CERT_STORE) so iBrowse's local store variable
 * is always initialised to a non-NULL value.
 * (g_verify_callback, g_verify_mode, g_verify_store all forward-declared above.) */

/* (g_last_ctx_id declared near the top of the file) */

/* Cert verify: stores callback/mode so get_verify_* can return them later. */
void ami_SSL_CTX_set_verify(SSL_CTX *ctx __asm("a0"),
                             LONG mode __asm("d0"), APTR cb __asm("a1"),
                             struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xC3);   /* set_verify */
    g_verify_mode     = mode;
    /* Store cb directly: if cb=NULL, keep the dummy (never store NULL itself —
     * the dummy_verify_cb is a safe callable fallback; real certs are verified
     * on the Pi).  If cb is a real iBrowse function, store it so we can return
     * it correctly from get_verify_callback and X509_STORE_get_verify_cb. */
    if (cb) g_verify_callback = cb;
    /* else: keep existing g_verify_callback (dummy_verify_cb or a real cb) */
    (void)ctx;
}

/* SSL_CTX_get_verify_mode (slot 1447, LVO -8682) */
LONG ami_SSL_CTX_get_verify_mode(SSL_CTX *ctx __asm("a0"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    return g_verify_mode;
}

/* SSL_CTX_get_verify_callback (slot 1449, LVO -8694) */
APTR ami_SSL_CTX_get_verify_callback(SSL_CTX *ctx __asm("a0"),
                                      struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    return g_verify_callback;   /* never NULL; sentinel 1UL if not set */
}

ULONG ami_SSL_CTX_set_options(SSL_CTX *ctx __asm("a0"), ULONG op __asm("d0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xC2);   /* set_options */
    (void)ctx;
    return op;   /* return the same options as if all were accepted */
}

LONG ami_SSL_CTX_set_cipher_list(SSL_CTX *ctx __asm("a0"), STRPTR s __asm("a1"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xC5);   /* set_cipher_list */
    (void)ctx; (void)s;
    return 1;
}

LONG ami_SSL_CTX_load_verify_locations(SSL_CTX *ctx __asm("a0"),
                                        STRPTR file __asm("a1"), STRPTR path __asm("a2"),
                                        struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xC6);   /* load_verify_locations */
    (void)ctx; (void)file; (void)path;
    return 1;
}

/* ---- SSL object functions ------------------------------------------------ */

SSL *ami_SSL_new(SSL_CTX *ctx __asm("a0"),
                  struct AmiSSLBase *base __asm("a6"))
{
    struct ExecBase *SysBase = base->SysBase;
    struct SslSess *s;
    APTR tb;
    (void)ctx;
    if (!base->BsdBase) return NULL;
    probe_marker(base->BsdBase, 0xA2);
    s = sess_alloc();                  /* daemon SSLObject created later at connect */
    if (!s) return (SSL *)0;
    /* Pin this session to the CALLING task's SocketBase so all of its socket I/O
     * (sess_connect/read/write) is immune to sibling tasks clobbering
     * base->BsdBase — the cause of concurrent image-load "0 bytes read" fails. */
    tb = SysBase ? task_bb_get((APTR)FindTask((STRPTR)0)) : (APTR)0;
    s->bbase = tb ? tb : base->BsdBase;
    return sess_handle(s);
}

void ami_SSL_free(SSL *ssl __asm("a0"),
                   struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    (void)base;
    if (!s) return;
    /* Proxy model: iBrowse owns the socket (it closes its own fd, which the daemon
     * sees as EOF and tears down the server side).  We just release the session. */
    s->oracle_id = 0;
    s->used = 0;
}

LONG ami_SSL_set_fd(SSL *ssl __asm("a0"), LONG fd __asm("d0"),
                    struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    probe_marker(base->BsdBase, 0xA3);
    probe_marker(base->BsdBase, 0xFD000000UL | ((ULONG)fd & 0xFFFF));  /* the app fd */
    if (!s) return 0;
    s->fd = fd;          /* the app's own socket to server:443 */
    return 1;
}

/* SSL_ctrl — handles all SSL_ctrl() calls.
 *
 * SSL_set_tlsext_host_name() is a C macro in the AmiSSL headers that expands to:
 *   SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)hostname)
 * where SSL_CTRL_SET_TLSEXT_HOSTNAME == 55.
 *
 * We detect cmd==55 and forward the hostname to the Pi via BSDSSL_LVO_SET_SNI.
 * All other cmd values return 0 (unsupported).
 */
LONG ami_SSL_ctrl(SSL *ssl __asm("a0"), LONG cmd __asm("d0"),
                   LONG larg __asm("d1"), APTR parg __asm("a1"),
                   struct AmiSSLBase *base __asm("a6"))
{
    (void)larg;
    /* SSL_CTRL_SET_TLSEXT_HOSTNAME = 55 */
    if (cmd == 55) {
        if (!ssl || !parg) return 0;
        probe_marker(base->BsdBase, 0xA4);
        /* Remember the SNI per-session (it's the oracle NEW hostname = the cert
         * verification name) and globally (AWeb's local cert-CN check). */
        {
            STRPTR src = (STRPTR)parg;
            struct SslSess *se = sess_from_ssl(ssl);
            UWORD  i;
            for (i = 0; i < 255 && src[i]; i++) {
                g_last_sni[i] = src[i];
                if (se) se->sni[i] = src[i];
            }
            g_last_sni[i] = 0;
            if (se) se->sni[i] = 0;
        }
        return 1;
    }
    return 0;   /* unsupported cmd */
}

/* SSL_CTX_ctrl — handles specific ctrl commands; stubs the rest.
 *
 * Build 20 — handle cmd=123/124 (SSL_CTRL_SET/GET_VERIFY_CERT_STORE):
 *   cmd=123: SSL_CTRL_SET_VERIFY_CERT_STORE — stores parg as the verify store.
 *            Returns 1 (success) so iBrowse proceeds instead of aborting.
 *   cmd=124: SSL_CTRL_GET_VERIFY_CERT_STORE — writes g_verify_store to *parg
 *            so iBrowse's local store variable is ALWAYS initialised to a
 *            non-NULL value (1UL sentinel or what was SET by cmd=123).
 *            Without this write, *parg is uninitialized stack garbage; iBrowse
 *            then passes the garbage to X509_STORE_get_verify_cb which returns
 *            a bad function pointer → JSR bad → #80000004.
 *            Returns 1 (store exists). */
LONG ami_SSL_CTX_ctrl(SSL_CTX *ctx __asm("a0"), LONG cmd __asm("d0"),
                       LONG larg __asm("d1"), APTR parg __asm("a1"),
                       struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)larg;
    probe_marker(base->BsdBase, 0xC1000000UL | ((ULONG)cmd & 0xFFFF));  /* CTX_ctrl cmd */

    /* SSL_CTRL_SET_VERIFY_CERT_STORE (123): iBrowse attaches an X509_STORE
     * to the SSL_CTX.  Store the pointer so GET can return it. */
    if (cmd == 123) {
        g_verify_store = parg ? parg : (APTR)1UL;
        return 1;   /* success */
    }

    /* SSL_CTRL_GET_VERIFY_CERT_STORE (124): iBrowse retrieves the store it just
     * set.  MUST write to *parg; otherwise iBrowse's local variable is
     * uninitialised and the crash follows.  Returns 1 (store exists). */
    if (cmd == 124) {
        if (parg) {
            APTR *pp = (APTR *)parg;
            *pp = g_verify_store;   /* 1UL sentinel or real store from cmd=123 */
        }
        return 1;
    }

    return 0;   /* all other cmds: unsupported, return 0 */
}

/* ---- SSL_CTX ex_data storage (LVO -9264/-9270, slots 1544/1545) ----------
 *
 * iBrowse stores application-specific data in the SSL_CTX via set_ex_data,
 * then retrieves it with get_ex_data.  Real OpenSSL supports multiple "slots"
 * identified by an index from SSL_CTX_get_ex_new_index().
 *
 * If get_ex_data returns NULL/0 and iBrowse dereferences the result as a
 * struct pointer → #80000004 Illegal Instruction crash.
 *
 * Fix: use a global array indexed by idx to store and retrieve the actual
 * values set_ex_data receives.  Per-context storage is omitted — iBrowse
 * typically uses one SSL_CTX at a time, so a global works in practice.
 *
 * Calling convention (from FD file):
 *   SSL_CTX_set_ex_data(ssl,idx,data)(a0,d0,a1)
 *   SSL_CTX_get_ex_data(ssl,idx)(a0,d0)
 */
#define AMISSL_EXDATA_MAX 8
static APTR g_ctx_exdata[AMISSL_EXDATA_MAX];

LONG ami_SSL_CTX_set_ex_data(SSL_CTX *ctx __asm("a0"),
                               LONG idx  __asm("d0"),
                               APTR data __asm("a1"),
                               struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    if (idx >= 0 && (ULONG)idx < AMISSL_EXDATA_MAX)
        g_ctx_exdata[(ULONG)idx] = data;
    return 1;   /* success */
}

APTR ami_SSL_CTX_get_ex_data(SSL_CTX *ctx __asm("a0"),
                               LONG idx  __asm("d0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    APTR v;
    (void)ctx;
    if (idx >= 0 && (ULONG)idx < AMISSL_EXDATA_MAX) {
        v = g_ctx_exdata[(ULONG)idx];
        /* Build 18: never return NULL — static array starts zero-initialised;
         * returning 0 hands iBrowse a NULL struct pointer which it then
         * dereferences for a function pointer → JSR 0 → #80000004.
         * Return 1UL as a safe sentinel when no data has been stored yet. */
        return v ? v : (APTR)1UL;
    }
    return (APTR)1UL;   /* non-NULL sentinel for out-of-range idx */
}

/* ---- SSL (not CTX) ex_data (LVO -9228/-9234, slots 1538/1539) -------------
 * SSL_set_ex_data(ssl,idx,data)(a0,d0,a1) → int; SSL_get_ex_data(ssl,idx)(a0,d0).
 * YAM stores its per-connection pointer on the SSL object and CHECKS the return
 * (ssl.c:762 `SSL_set_ex_data(...) == 0` is treated as failure → it aborts the
 * secure session).  Our table previously stubbed these to 0, so YAM failed before
 * connecting.  Store one value per session (apps use a single index) and return 1. */
LONG ami_SSL_set_ex_data(SSL *ssl __asm("a0"), LONG idx __asm("d0"),
                          APTR data __asm("a1"), struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    (void)idx; (void)base;
    if (s) s->exdata = data;
    return 1;   /* success; YAM aborts on 0 */
}

APTR ami_SSL_get_ex_data(SSL *ssl __asm("a0"), LONG idx __asm("d0"),
                          struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    (void)idx; (void)base;
    return (s && s->exdata) ? s->exdata : (APTR)0;
}

/* ---- BIO SSL path (LVO -1728 to -2070, slots 288-345; -8166 to -8184, slots 1361-1364) ---
 *
 * iBrowse 3.x uses OpenSSL's BIO abstraction for HTTPS connections:
 *
 *   ctx = SSL_CTX_new(method)
 *   bio = BIO_new_ssl_connect(ctx)            ← slot 1363
 *   BIO_set_conn_hostname(bio,"host:443")     ← BIO_ctrl(bio,100,0,"host:443")
 *   BIO_do_connect(bio)                       ← BIO_ctrl(bio,10,0,NULL)
 *   BIO_get_ssl(bio,&ssl)                     ← BIO_ctrl(bio,110,0,&ssl)
 *   BIO_read(bio,buf,len)  / BIO_write(...)   ← slots 292, 294
 *
 * BIO_do_connect (cmd=10) does the complete TCP+TLS handshake:
 *   gethostbyname → socket → connect → SSL_new → SSL_set_fd → SSL_set_sni → SSL_connect
 *
 * State is kept in globals (safe: iBrowse is single-threaded, one BIO at a time).
 *
 * Wrapper requirement: ami_BIO_ctrl / ami_BIO_read / ami_BIO_write call bsdsocket,
 * which clobbers a6.  Each is invoked via WrapBIOCtrl / WrapBIORead / WrapBIOWrite
 * in amissl_start.S, which saves/restores a6 (AmiSSLBase) around the call.
 * ami_BIO_new_ssl_connect does NOT call bsdsocket so it needs no wrapper.
 */

/* BIO global state — one active BIO at a time */
static ULONG g_bio_ctx_id        = 0;   /* SSL_CTX id (from BIO_new_ssl_connect or BIO_new_ssl) */
static ULONG g_bio_ssl_id        = 0;   /* SSL id (created in BIO_do_connect) */
static LONG  g_bio_fd            = -1;  /* socket fd (created in BIO_do_connect) */
static struct SslSess *g_bio_sess = (struct SslSess *)0;  /* Model B session (BIO path) */
static char  g_bio_hostname[256] = {0}; /* hostname (set by BIO_ctrl cmd=100 or BIO_new_connect) */
static UWORD g_bio_port          = 443; /* port (set by BIO_ctrl cmd=100 or BIO_new_connect) */


/* ---- BIO_f_ssl (slot 1361, LVO -8166) ------------------------------------ */
APTR ami_BIO_f_ssl(struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xD0);
    return (APTR)1UL;   /* non-NULL SSL BIO method sentinel */
}

/* ---- BIO_new_ssl (slot 1362, LVO -8172) ---------------------------------- */
/* iBrowse may call BIO_new_ssl(ctx,1) + BIO_new_connect("host:port") + BIO_push
 * instead of BIO_new_ssl_connect.  Store ctx_id so BIO_do_connect can use it. */
APTR ami_BIO_new_ssl(SSL_CTX *ctx __asm("a0"), LONG client __asm("d0"),
                      struct AmiSSLBase *base __asm("a6"))
{
    (void)client;
    probe_marker(base->BsdBase, 0xD1);
    if (ctx) {
        g_bio_ctx_id  = (ULONG)ctx;
        g_bio_ssl_id  = 0;
        g_bio_fd      = -1;
    }
    return (APTR)1UL;
}

/* ---- BIO_new_ssl_connect (slot 1363, LVO -8178) --------------------------
 * Save ctx_id and initialise BIO global state.  Return a non-NULL BIO handle. */
APTR ami_BIO_new_ssl_connect(SSL_CTX *ctx __asm("a0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    probe_marker(base->BsdBase, 0xD2);
    g_bio_ctx_id      = (ULONG)ctx;
    g_bio_ssl_id      = 0;
    g_bio_fd          = -1;
    g_bio_port        = 443;
    g_bio_hostname[0] = '\0';
    return (APTR)1UL;   /* non-NULL BIO handle sentinel */
}

/* ---- BIO_new_buffer_ssl_connect (slot 1364, LVO -8184) ------------------- */
APTR ami_BIO_new_buffer_ssl_connect(SSL_CTX *ctx __asm("a0"),
                                     struct AmiSSLBase *base __asm("a6"))
{
    /* Delegate: same BIO state as BIO_new_ssl_connect */
    return ami_BIO_new_ssl_connect(ctx, base);
}

/* ---- BIO_new (slot 288, LVO -1728) --------------------------------------- */
APTR ami_BIO_new(APTR method __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)method;
    probe_marker(base->BsdBase, 0xD3);
    return (APTR)1UL;
}

/* ---- BIO_ctrl (slot 297, LVO -1782) — called via WrapBIOCtrl -------------
 * Calling convention: BIO_ctrl(bp,cmd,larg,parg)(a0,d0,d1,a1) → LONG
 *
 * Handles:
 *   cmd=100  BIO_C_SET_CONNECT: parse/store hostname[:port] or port string
 *   cmd= 11  BIO_CTRL_FLUSH: no-op, return success
 *   cmd=110  BIO_C_GET_SSL: write ssl_id into *parg
 *   cmd= 10  BIO_C_DO_STATE_MACHINE (BIO_do_connect): full TCP+TLS handshake
 */
LONG ami_BIO_ctrl(APTR bio __asm("a0"), LONG cmd __asm("d0"),
                   LONG larg __asm("d1"), APTR parg __asm("a1"),
                   struct AmiSSLBase *base __asm("a6"))
{
    (void)bio;

    /* --- BIO_C_SET_CONNECT (100): set hostname or port --- */
    if (cmd == 100) {
        if (larg == 0 && parg) {
            /* hostname or "hostname:port" */
            STRPTR src = (STRPTR)parg;
            UWORD  i   = 0;
            while (i < 255 && src[i] && src[i] != ':') {
                g_bio_hostname[i] = src[i];
                i++;
            }
            g_bio_hostname[i] = '\0';
            if (src[i] == ':') {
                STRPTR ps = src + i + 1;
                UWORD  p  = 0;
                while (*ps >= '0' && *ps <= '9')
                    p = (UWORD)(p * 10 + (*ps++ - '0'));
                if (p) g_bio_port = p;
            }
        } else if (larg == 1 && parg) {
            /* separate port string, e.g. "443" */
            STRPTR ps = (STRPTR)parg;
            UWORD  p  = 0;
            while (*ps >= '0' && *ps <= '9')
                p = (UWORD)(p * 10 + (*ps++ - '0'));
            if (p) g_bio_port = p;
        }
        return 1;
    }

    /* --- BIO_CTRL_FLUSH (11): flush — always succeeds --- */
    if (cmd == 11) {
        return 1;
    }

    /* --- BIO_C_GET_SSL (110): write ssl_id into *parg --- */
    if (cmd == 110) {
        if (parg) {
            ULONG *pp = (ULONG *)parg;
            *pp = g_bio_ssl_id;   /* 0 if not yet connected */
        }
        return (g_bio_ssl_id != 0) ? 1 : 0;
    }

    /* --- BIO_C_DO_STATE_MACHINE (10): BIO_do_connect — full TCP+TLS handshake --- */
    if (cmd == 10) {
        struct ami_hostent    *he;
        struct ami_sockaddr_in sa;
        LONG                   fd;
        ULONG                  ssl_id;
        ULONG                  ip_addr;  /* IPv4 in network byte order */
        APTR                   bbase;
        ULONG                  ctx_to_use;

        probe_marker(base->BsdBase, 0xB000000AUL);   /* BIO_do_connect: entry */
        if (!base->BsdBase || !g_bio_hostname[0]) return 0;

        /* Use whichever ctx_id is available; prefer the one set by BIO_new_ssl_connect
         * or BIO_new_ssl, fall back to the most recently created SSL_CTX. */
        ctx_to_use = g_bio_ctx_id ? g_bio_ctx_id : g_last_ctx_id;
        if (!ctx_to_use) return 0;

        bbase = base->BsdBase;

        /* 1. DNS resolution — sends BSDOP_GETHOSTBYNAME to Pi.
         * Read IP immediately before any other bsdsocket call might invalidate
         * the static hostent buffer returned by gethostbyname. */
        he = _bsd_gethostbyname(bbase, (STRPTR)g_bio_hostname);

        probe_marker(bbase, 0xB1000000UL | (he ? 1UL : 0UL));   /* gethostbyname returned (1=non-NULL) */
        if (!he || !he->h_addr_list || !he->h_addr_list[0]) return 0;
        ip_addr = *(ULONG *)he->h_addr_list[0];   /* 4 bytes, network byte order */
        probe_marker(bbase, 0xB2000000UL | (ip_addr & 0xFFFFFFUL));   /* DNS ok: ip low 3 bytes */

        /* 2. Create TCP socket */
        fd = _bsd_socket(bbase, 2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0);
        if (fd < 0) return 0;

        /* 3. TCP connect to host:port
         * 68k is big-endian = network byte order; no byte swap needed for port or IP. */
        sa.sin_family      = 2;   /* AF_INET */
        sa.sin_port        = g_bio_port;
        sa.sin_addr        = ip_addr;
        sa.sin_zero[0]     = 0; sa.sin_zero[1] = 0;
        sa.sin_zero[2]     = 0; sa.sin_zero[3] = 0;
        sa.sin_zero[4]     = 0; sa.sin_zero[5] = 0;
        sa.sin_zero[6]     = 0; sa.sin_zero[7] = 0;
        probe_marker(bbase, 0xB3000000UL | ((ULONG)fd & 0xFFFF));   /* got socket fd */
        if (_bsd_connect(bbase, fd, (APTR)&sa, 16) != 0) return 0;
        probe_marker(bbase, 0xB4000000UL | ((ULONG)g_bio_port & 0xFFFF));   /* connected to server:port */

        /* 4-7. Model B: adopt the just-connected socket as a session and run the
         *      oracle handshake (NEW + pump).  g_bio_ssl_id holds the SSL* handle
         *      (sess index) so BIO_get_ssl / subsequent SSL_* calls map correctly. */
        {
            struct SslSess *se = sess_alloc();
            UWORD i;
            (void)ssl_id;
            if (!se) { _bsd_closesocket(bbase, fd); return 0; }
            se->fd = fd;
            for (i = 0; i < 255 && g_bio_hostname[i]; i++) se->sni[i] = g_bio_hostname[i];
            se->sni[i] = 0;
            if (sess_connect(bbase, se) != 1) {   /* opens its own control socket */
                se->used = 0;
                _bsd_closesocket(bbase, fd);
                return 0;   /* failure */
            }
            g_bio_sess   = se;
            g_bio_ssl_id = (ULONG)sess_handle(se);
            g_bio_fd     = fd;
            return 1;   /* success */
        }
    }

    return 0;   /* unsupported cmd */
}

/* ---- BIO_new_connect (slot 345, LVO -2070) --------------------------------
 * Creates a TCP connect BIO for a given "hostname:port" string.
 * iBrowse may use this + BIO_new_ssl + BIO_push instead of BIO_new_ssl_connect.
 * We parse the hostname:port here and store it so BIO_do_connect can use it.
 * Does NOT call bsdsocket (so no wrapper needed). */
APTR ami_BIO_new_connect(STRPTR host_port __asm("a0"),
                          struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    g_bio_ssl_id  = 0;
    g_bio_fd      = -1;
    g_bio_port    = 443;
    g_bio_hostname[0] = '\0';

    if (host_port) {
        STRPTR src = host_port;
        UWORD  i   = 0;
        /* Copy hostname up to ':' or end of string */
        while (i < 255 && src[i] && src[i] != ':') {
            g_bio_hostname[i] = src[i];
            i++;
        }
        g_bio_hostname[i] = '\0';
        /* Parse port if present */
        if (src[i] == ':') {
            STRPTR ps = src + i + 1;
            UWORD  p  = 0;
            while (*ps >= '0' && *ps <= '9')
                p = (UWORD)(p * 10 + (*ps++ - '0'));
            if (p) g_bio_port = p;
        }
    }
    return (APTR)1UL;
}

/* ---- BIO_read (slot 292, LVO -1752) — called via WrapBIORead -------------
 * Calling convention: BIO_read(b,data,len)(a0,a1,d0) → LONG
 * Proxies through g_bio_ssl_id → BSDSSL_LVO_READ (SSL_read on Pi). */
LONG ami_BIO_read(APTR bio __asm("a0"), APTR buf __asm("a1"), LONG len __asm("d0"),
                  struct AmiSSLBase *base __asm("a6"))
{
    (void)bio;
    if (!base->BsdBase || !g_bio_sess || len <= 0) return -1;
    return sess_read(base->BsdBase, g_bio_sess, (UBYTE *)buf, len);
}

/* ---- BIO_write (slot 294, LVO -1764) — called via WrapBIOWrite -----------
 * Calling convention: BIO_write(b,data,len)(a0,a1,d0) → LONG
 * Proxies through g_bio_ssl_id → BSDSSL_LVO_WRITE (SSL_write on Pi). */
LONG ami_BIO_write(APTR bio __asm("a0"), CONST_APTR buf __asm("a1"), LONG len __asm("d0"),
                   struct AmiSSLBase *base __asm("a6"))
{
    (void)bio;
    if (!base->BsdBase || !g_bio_sess || len <= 0) return -1;
    return sess_write(base->BsdBase, g_bio_sess, (const UBYTE *)buf, len);
}

/* ---- SSL_CTX_get_ssl_method (LVO -24216, slot 4036) ----------------------
 * Returns the SSL_METHOD stored in the context.
 * Returns non-NULL sentinel so NULL dereferences don't crash iBrowse.
 * Calling convention: SSL_CTX_get_ssl_method(ctx)(a0) → SSL_METHOD*
 */
SSL_METHOD *ami_SSL_CTX_get_ssl_method(SSL_CTX *ctx __asm("a0"),
                                        struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (SSL_METHOD *)1UL;
}

LONG ami_SSL_connect(SSL *ssl __asm("a0"),
                     struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    if (!base->BsdBase || !s || s->fd < 0) return -1;
    if (!s->sni[0]) {                       /* fall back to last SNI if app didn't set one */
        UWORD i;
        for (i = 0; i < 255 && g_last_sni[i]; i++) s->sni[i] = g_last_sni[i];
        s->sni[i] = 0;
    }
    return sess_connect(base->BsdBase, s);   /* opens its own control socket; 1 ok / -1 fail */
}

LONG ami_SSL_shutdown(SSL *ssl __asm("a0"),
                       struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    (void)base;
    /* Proxy model: closing iBrowse's fd (which it does next) signals the daemon to
     * tear down the TLS connection.  Nothing to send here. */
    if (s) s->oracle_id = 0;
    return 1;
}

LONG ami_SSL_read(SSL *ssl __asm("a0"), APTR buf __asm("a1"), LONG num __asm("d0"),
                  struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    if (!base->BsdBase || !s) return -1;
    if (num == 0) return 0;     /* real SSL_read(0) returns 0, not -1 */
    if (!s->oracle_id || num < 0) return -1;
    return sess_read(base->BsdBase, s, (UBYTE *)buf, num);
}

LONG ami_SSL_write(SSL *ssl __asm("a0"), CONST_APTR buf __asm("a1"), LONG num __asm("d0"),
                   struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    if (!base->BsdBase || !s || !s->oracle_id || num <= 0) return -1;
    return sess_write(base->BsdBase, s, (const UBYTE *)buf, num);
}

LONG ami_SSL_get_error(SSL *ssl __asm("a0"), LONG ret __asm("d0"),
                       struct AmiSSLBase *base __asm("a6"))
{
    struct SslSess *s = sess_from_ssl(ssl);
    LONG rv;
    if (s && s->want_read) rv = 2;        /* SSL_ERROR_WANT_READ — non-blocking, retry */
    else if (ret > 0)      rv = 0;        /* SSL_ERROR_NONE */
    else if (ret == 0)     rv = 6;        /* SSL_ERROR_ZERO_RETURN */
    else                   rv = 5;        /* SSL_ERROR_SYSCALL */
    if (base->BsdBase && g_diag_ssl_emit < DIAG_SSL_CAP) {   /* DIAG: ret asked, err answered */
        g_diag_ssl_emit++;
        dbg_probe(base->BsdBase, 0x6E000000UL | (((ULONG)ret & 0xFFFUL) << 12)
                       | ((ULONG)rv & 0xFFFUL));
    }
    return rv;
}

/* ---- Error / misc stubs -------------------------------------------------- */

ULONG ami_ERR_get_error(struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    return 0;   /* 0 = no error in queue (safe; iBrowse treats 0 as "no SSL error") */
}

ULONG ami_ERR_peek_error(struct AmiSSLBase *base __asm("a6"))
{ (void)base; return 0; }

void ami_ERR_clear_error(struct AmiSSLBase *base __asm("a6"))
{ (void)base; }

STRPTR ami_ERR_error_string(ULONG e __asm("d0"), STRPTR buf __asm("a0"),
                              struct AmiSSLBase *base __asm("a6"))
{
    static const char msg[] = "a314ssl error";
    (void)e; (void)base;
    if (buf) {
        UWORD i;
        for (i = 0; i < sizeof(msg); i++) buf[i] = msg[i];
        return buf;
    }
    return (STRPTR)msg;
}

/* Report 0 — exactly as a314SSLlib does (its WORKING shim).  iBrowse's read loop
 * is SSL_pending()-gated: if pending>0 it re-reads the SSL buffer WITHOUT polling;
 * only when pending==0 does it fall to WaitSelect.  Returning our daemon's real
 * buffered count made iBrowse take the no-poll fast path, read a few chunks, then
 * stop (diagnostics: it never called WaitSelect/FIONREAD while we held plaintext).
 * Returning 0 pushes it onto the select-driven path our WaitSelect patch handles:
 * that patch forces the SSL fd readable whenever s->pending>0, so iBrowse keeps
 * reading until the whole response is drained — the a314SSLlib model. */
LONG ami_SSL_pending(SSL *ssl __asm("a0"),
                     struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return 0;
}

APTR ami_SSL_get_peer_certificate(SSL *ssl __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    /* Real cert is on Pi; Amiga side has no X509 struct.
     * Return non-NULL sentinel — if iBrowse dereferences NULL → crash. */
    (void)ssl; (void)base;
    return (APTR)1UL;
}

LONG ami_SSL_get_verify_result(SSL *ssl __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{ (void)ssl; (void)base; return 0; /* X509_V_OK */ }

LONG ami_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx __asm("a0"),
                                           struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    probe_marker(base->BsdBase, 0xC7);
    return 1;
}

void ami_SSL_set_verify(SSL *ssl __asm("a0"), LONG mode __asm("d0"),
                         APTR cb __asm("a1"),
                         struct AmiSSLBase *base __asm("a6"))
{
    /* Store into the same globals so SSL_get_verify_callback returns the right value. */
    g_verify_mode     = mode;
    g_verify_callback = cb ? cb : (APTR)dummy_verify_cb;
    (void)ssl; (void)base;
}

/* ---- SSL* object getter functions returning callbacks / pointers ------------ */
/*
 * These are the SSL* counterparts to the SSL_CTX* getters above.
 * After SSL_new(), iBrowse reads back verify callbacks and CTX pointers.
 * Returning NULL causes JSR 0 → #80000004 crash.
 *
 * Slot assignments (verified from FD file ##bias 8316, line 1201):
 *   SSL_get_verify_callback  slot 1403  LVO  -8418
 *   SSL_get_SSL_CTX          slot 1532  LVO  -9192
 *   SSL_get_info_callback    slot 1534  LVO  -9204
 */

/* SSL_get_verify_callback (slot 1403, LVO -8418) — per-SSL* object getter.
 * Called after SSL_new to retrieve the inherited verify callback.
 * Was StubRetZero (NULL) → iBrowse calls through NULL → JSR 0 → #80000004! */
APTR ami_SSL_get_verify_callback(SSL *ssl __asm("a0"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return g_verify_callback;   /* never NULL; sentinel 1UL if not set */
}

/* SSL_get_SSL_CTX (slot 1532, LVO -9192) — returns SSL_CTX* from SSL*.
 * iBrowse calls this to retrieve ctx for SSL_CTX_get_ex_data / verify ops.
 * Was StubRetZero (NULL) → iBrowse passes NULL to SSL_CTX_* → crash!
 * Return sentinel 1UL — ami_SSL_CTX_get_ex_data ignores the ctx arg anyway. */
SSL_CTX *ami_SSL_get_SSL_CTX(SSL *ssl __asm("a0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return (SSL_CTX *)SSL_CTX_SENTINEL;   /* in-range sentinel; real ctx unavailable client-side */
}

/* SSL_get_info_callback (slot 1534, LVO -9204) — per-SSL* info callback getter.
 * Was StubRetZero (NULL) → if iBrowse calls through NULL → JSR 0 → #80000004! */
APTR ami_SSL_get_info_callback(SSL *ssl __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* ---- SSL_CTX / X509_STORE getter functions returning callbacks -------------- */
/*
 * These functions return function pointers or opaque data that iBrowse may call
 * through directly.  Returning 0 (= StubRetZero) causes JSR 0 → #80000004 crash.
 *
 * Slot assignments (from amissl_lib.fd, verified):
 *   SSL_CTX_get_info_callback              slot 3232  LVO -19392
 *   SSL_CTX_get_default_passwd_cb          slot 4593  LVO -27558
 *   SSL_CTX_get_default_passwd_cb_userdata slot 4594  LVO -27564
 *   X509_STORE_get_verify                  slot 4796  LVO -28776
 *   X509_STORE_get_verify_cb              slot 4797  LVO -28782
 */

/* ASN1_STRING_length (slot 36, LVO -216) — length of an ASN1 string.  In AWeb's
 * hostname check this is the length of the cert CN; we return strlen(g_last_sni)
 * so the CN matches the SNI host.  (Other ASN1 uses are rare in these clients.) */
LONG ami_ASN1_STRING_length(APTR asn1 __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    UWORD n = 0;
    (void)asn1; (void)base;
    while (g_last_sni[n]) n++;
    return (LONG)n;
}

/* ASN1_STRING_data (slot 39, LVO -234) — bytes of an ASN1 string = the cert CN,
 * which we report as the SNI hostname so AWeb's CN-vs-host compare matches. */
APTR ami_ASN1_STRING_data(APTR asn1 __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)asn1; (void)base;
    return (APTR)g_last_sni;
}

/* X509_verify_cert (slot 1974, LVO -11844) — verify the cert chain in an
 * X509_STORE_CTX.  Returns 1 on success.  AWeb does its OWN local chain
 * verification after connect; but the Pi already performed the real verification
 * during the TLS handshake (CERT_REQUIRED + system CA bundle), so reporting 1
 * (verified) here is correct for our architecture and stops AWeb's cert prompt. */
LONG ami_X509_verify_cert(APTR ctx __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return 1;
}

/* X509_STORE_CTX_init (slot 2025, LVO -12150) — initialise a verify context.
 * (ctx, store, cert, chain)(a0,a1,a2,a3).  Returns 1 on success.  AWeb checks
 * this == 1 before calling X509_verify_cert. */
LONG ami_X509_STORE_CTX_init(APTR ctx __asm("a0"), APTR store __asm("a1"),
                              APTR cert __asm("a2"), APTR chain __asm("a3"),
                              struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)store; (void)cert; (void)chain; (void)base;
    return 1;
}

/* OPENSSL_sk_num (slot 1554, LVO -9324) — number of elements in a stack.
 * AWeb iterates `for(i=0;i<OPENSSL_sk_num(s);i++) OPENSSL_sk_value(s,i)`.  Our
 * StubRetZero returned a huge value -> ~infinite loop spinning on sk_value.
 * Return 0 = empty stack so the loop body never runs. */
LONG ami_OPENSSL_sk_num(APTR sk __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)sk; (void)base;
    return 0;
}

/* OPENSSL_sk_value (slot 1555, LVO -9330) — element at index; return NULL. */
APTR ami_OPENSSL_sk_value(APTR sk __asm("a0"), LONG idx __asm("d0"),
                           struct AmiSSLBase *base __asm("a6"))
{
    (void)sk; (void)idx; (void)base;
    return (APTR)0;
}

/* SSL_CTX_up_ref (slot 4450, LVO -26700) — increments the SSL_CTX reference
 * count, returns int 1 on success.  AWeb 3.6b8 calls this (its handle is shared)
 * and a higher-level loop spins on it while our StubRetZero returned a high
 * pointer; the correct return is 1.  The Pi keeps contexts persistent (global,
 * never freed during the debug phase) so no real refcount bookkeeping is needed. */
LONG ami_SSL_CTX_up_ref(APTR ctx __asm("a0"),
                         struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return 1;
}

/* SSL_CTX_sess_get_get_cb (slot 3229, LVO -19374) */
APTR ami_SSL_CTX_sess_get_get_cb(SSL_CTX *ctx __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_info_callback (slot 3232, LVO -19392) */
APTR ami_SSL_CTX_get_info_callback(SSL_CTX *ctx __asm("a0"),
                                    struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_sess_get_new_cb (slot 3233, LVO -19398) */
APTR ami_SSL_CTX_sess_get_new_cb(SSL_CTX *ctx __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_client_cert_cb (slot 3234, LVO -19404) */
APTR ami_SSL_CTX_get_client_cert_cb(SSL_CTX *ctx __asm("a0"),
                                     struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_sess_get_remove_cb (slot 3235, LVO -19410) */
APTR ami_SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx __asm("a0"),
                                     struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* ---- Build 5: fix NULL-returning getter slots 3230, 3236, 3237 ---------------
 *
 * The FD file (##bias 19362 → slot 3227) shows the true slot layout:
 *   Slot 3229 = SSL_CTX_sess_set_new_cb      (SETTER — stub OK)
 *   Slot 3230 = SSL_CTX_sess_get_get_cb      (GETTER — was StubRetZero → CRASH!)
 *   Slot 3231 = SSL_CTX_sess_set_get_cb      (SETTER — stub OK)
 *   Slot 3232 = SSL_CTX_get_info_callback    (GETTER — fixed in build 3)
 *   Slot 3233 = SSL_CTX_set_client_cert_cb   (SETTER — stub OK)
 *   Slot 3234 = SSL_CTX_sess_set_remove_cb   (SETTER — stub OK)
 *   Slot 3235 = SSL_CTX_sess_get_new_cb      (GETTER — fixed in build 3, mislabeled)
 *   Slot 3236 = SSL_CTX_get_client_cert_cb   (GETTER — was StubRetZero → CRASH!)
 *   Slot 3237 = SSL_CTX_sess_get_remove_cb   (GETTER — was StubRetZero → CRASH!)
 *
 * Pattern: iBrowse saves old callbacks before setting new ones, then later calls
 * through the saved pointers.  NULL saved ptr → JSR 0 → #80000004.
 * We use suffix _real to distinguish from the mislabeled build-3 functions.
 */

/* SSL_CTX_sess_get_get_cb (slot 3230, LVO -19380) — GETTER for session-get callback. */
APTR ami_SSL_CTX_sess_get_get_cb_real(SSL_CTX *ctx __asm("a0"),
                                       struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_client_cert_cb (slot 3236, LVO -19416) — GETTER for client-cert callback. */
APTR ami_SSL_CTX_get_client_cert_cb_real(SSL_CTX *ctx __asm("a0"),
                                          struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_sess_get_remove_cb (slot 3237, LVO -19422) — GETTER for session-remove callback. */
APTR ami_SSL_CTX_sess_get_remove_cb_real(SSL_CTX *ctx __asm("a0"),
                                          struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_default_passwd_cb (slot 4593, LVO -27558) */
APTR ami_SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx __asm("a0"),
                                        struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_default_passwd_cb_userdata (slot 4594, LVO -27564) */
APTR ami_SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx __asm("a0"),
                                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)1UL;   /* non-NULL sentinel */
}

/* X509_STORE_get_verify (slot 4796, LVO -28776) */
APTR ami_X509_STORE_get_verify(APTR store __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{
    (void)store; (void)base;
    return (APTR)dummy_verify_cb;   /* real callable no-op, JSR-safe */
}

/* X509_STORE_get_verify_cb (slot 4797, LVO -28782)
 * Returns the verify callback stored by SSL_CTX_set_verify.
 * CRITICAL: must return a callable function, not NULL or 1UL sentinel.
 *   NULL  → iBrowse might JSR NULL → crash
 *   1UL   → iBrowse's NULL check passes, then JSR 1 → crash on 68020
 *   dummy_verify_cb → real 68K function, safe to call, returns 1 (accept) */
APTR ami_X509_STORE_get_verify_cb(APTR store __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    (void)store; (void)base;
    return g_verify_callback;   /* dummy_verify_cb or real cb — always callable */
}

/* ---- SSL cipher / version info stubs ----------------------------------------
 * iBrowse calls these after SSL_connect to populate the padlock info display.
 * All return non-NULL values so iBrowse's string handling code doesn't crash.
 *
 * SSL_CIPHER* is an opaque handle; we use a sentinel value (1) so that
 * SSL_CIPHER_get_* functions can recognise it as "the dummy TLS 1.3 cipher".
 * iBrowse treats it as fully opaque and only passes it back to other
 * SSL_CIPHER_get_* functions — never dereferences it directly.
 *
 * LVO table slots:
 *   SSL_get_current_cipher  slot 1377  LVO  -8262
 *   SSL_CIPHER_get_bits     slot 1378  LVO  -8268
 *   SSL_CIPHER_get_version  slot 1379  LVO  -8274
 *   SSL_CIPHER_get_name     slot 1380  LVO  -8280
 *   SSL_get_version         slot 1481  LVO  -8886
 */

APTR ami_SSL_get_current_cipher(SSL *ssl __asm("a0"),
                                 struct AmiSSLBase *base __asm("a6"))
{ (void)ssl; (void)base; return (APTR)1UL; /* dummy non-NULL sentinel */ }

LONG ami_SSL_CIPHER_get_bits(APTR cipher __asm("a0"), LONG *alg_bits __asm("a1"),
                              struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    if (!cipher) return 0;
    if (alg_bits) *alg_bits = 256;
    return 256;   /* AES-256 equivalent */
}

STRPTR ami_SSL_CIPHER_get_version(APTR cipher __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    static const char ver[] = "TLSv1.3";
    (void)base;
    return (STRPTR)(cipher ? ver : ver);   /* always non-NULL */
}

STRPTR ami_SSL_CIPHER_get_name(APTR cipher __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{
    static const char name[] = "TLS_AES_256_GCM_SHA384";
    static const char none[] = "(NONE)";
    (void)base;
    return (STRPTR)(cipher ? name : none);
}

/* SSL_get_version: always "TLSv1.3" — Pi only negotiates TLS 1.2+ anyway */
STRPTR ami_SSL_get_version(SSL *ssl __asm("a0"),
                            struct AmiSSLBase *base __asm("a6"))
{
    static const char ver[] = "TLSv1.3";
    (void)ssl; (void)base;
    return (STRPTR)ver;
}
