/* gpntest — does this bsdsocket implementation support getpeername()?
 *
 * Connects a TCP socket to the AmiSSL-Tunnel daemon at 127.0.0.1:8443 (no TLS, no
 * AmiSSL, no DNS — just a plain connect to a known local port), then calls
 * getpeername() and prints the peer port.  If it prints 8443, getpeername works
 * and returns the real port — which is exactly what the shim's sess_connect now
 * relies on to send the right CONNECT port (instead of a hardcoded 443).
 *
 * Build (WSL):  m68k-amigaos-gcc -O2 -noixemul -Wall -o gpntest gpntest.c
 * Run on Amiga: gpntest >SYS:gpntest.log     (needs the daemon listening on 8443)
 *
 * 68k is big-endian, so network byte order == host byte order: we store the
 * port/addr directly and read sin_port directly — no htons/ntohs needed.
 */
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct Library *SocketBase = 0;

int main(void)
{
    struct sockaddr_in sa, pn;
    LONG s, i, len, ret;
    UWORD port;

    SocketBase = OpenLibrary((CONST_STRPTR)"bsdsocket.library", 4);
    if (!SocketBase) {
        Printf("FAIL: cannot open bsdsocket.library\n");
        return 20;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        Printf("FAIL: socket() returned %ld\n", s);
        CloseLibrary(SocketBase);
        return 20;
    }

    for (i = 0; i < (LONG)sizeof(sa); i++) ((UBYTE *)&sa)[i] = 0;
    sa.sin_family      = AF_INET;
    sa.sin_port        = 8443;          /* big-endian == network order on 68k */
    sa.sin_addr.s_addr = 0x7F000001UL;  /* 127.0.0.1 */

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        Printf("FAIL: connect to 127.0.0.1:8443 failed (is the daemon running?)\n");
        CloseSocket(s);
        CloseLibrary(SocketBase);
        return 20;
    }

    for (i = 0; i < (LONG)sizeof(pn); i++) ((UBYTE *)&pn)[i] = 0;
    len = (LONG)sizeof(pn);
    ret = getpeername(s, (struct sockaddr *)&pn, (int *)&len);

    if (ret == 0) {
        port = pn.sin_port;   /* network order == host order on 68k */
        Printf("OK: getpeername ret=0  peer-port=%ld  (expect 8443)\n", (LONG)port);
        if (port == 8443)
            Printf("RESULT: bsdsocket getpeername WORKS -> shim dynamic-port fix is valid here.\n");
        else
            Printf("RESULT: getpeername returned wrong port (%ld) -> investigate.\n", (LONG)port);
    } else {
        Printf("RESULT: getpeername FAILED ret=%ld -> this bsdsocket does NOT implement it; "
               "shim falls back to 443 here (still correct on real stacks like Roadshow).\n", ret);
    }

    CloseSocket(s);
    CloseLibrary(SocketBase);
    return 0;
}
