/*
 * sippycup media guard: keep the softphone's media inside the approved scope.
 *
 * PJSUA starts its media stream inside the same call that processes the far
 * end's SDP answer: two RTCP packets leave before the ACK, the first RTP
 * packet 2-3 ms later, and two more RTCP packets (the RTCP BYE) are sent by
 * the hang-up itself. The driver, a separate process that reads PJSUA's log,
 * can only hang up afterwards. This library is preloaded into PJSUA
 * (LD_PRELOAD) and decides in sendto()/send(), before the kernel sees the
 * datagram, whether a media datagram may go to its destination. A refused
 * datagram is dropped, reported on stderr and answered as sent, so PJSUA
 * carries on until the driver's media-scope stop hangs the call up.
 *
 * It needs no capability and no packet filter, and it never touches
 * signaling: only UDP datagrams that do not start like a SIP message (a
 * letter, CR or LF) are judged. Everything PJSUA 2.17 sends on a datagram
 * socket goes through sendto() or send() (the image build checks its import
 * table), and RTP, RTCP, SRTP and SRTCP all start with the version bits 10.
 *
 * Rules (environment SIPPYCUP_MEDIA_GUARD_RULES, written by the driver):
 *     v1;addr=LIST;ports=RANGE
 * LIST is "*" (any address), "-" (none) or comma-separated CIDR networks (IPv4 or IPv6;
 * a literal address is /32 or /128; at most 256); RANGE is "*" or START-END.
 * A media datagram passes when its destination address is inside LIST and,
 * unless it is RTCP, its destination port is inside RANGE. These are the
 * driver's own rules (media_destination_refusal). Without the variable the
 * library does nothing. With a value it cannot parse it drops every media
 * datagram (fail closed).
 *
 * stderr lines (the driver reads them from PJSUA's console):
 *     sippycup-media-guard: active v1 prog=NAME addr=LIST ports=RANGE
 *     sippycup-media-guard: blocked RTP|RTCP|OTHER to ADDRESS port PORT
 *     sippycup-media-guard: more datagrams are being blocked and are not listed
 *     sippycup-media-guard: error REASON; every media datagram is dropped
 * At most 200 blocked datagrams are listed one by one.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_NETWORKS 256
#define RULES_MAX 16384
#define MAX_REPORTED 200
#define PREFIX "sippycup-media-guard: "

struct network {
    int family;              /* AF_INET or AF_INET6 */
    unsigned char address[16];
    int prefix;
};

static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*real_send)(int, const void *, size_t, int);

static int guard_mode;       /* 0 = off, 1 = rules in force, 2 = drop all media */
static int any_address;
static int any_port;
static int port_start, port_end;
static struct network networks[MAX_NETWORKS];
static int network_count;
static int reported;

static void say(const char *text)
{
    ssize_t ignored = write(2, text, strlen(text));
    (void)ignored;
}

static int parse_network(char *text, struct network *out)
{
    char *slash = strchr(text, '/');
    char *end = NULL;
    long prefix = -1;

    if (slash != NULL) {
        *slash = '\0';
        if (slash[1] == '\0')
            return -1;
        prefix = strtol(slash + 1, &end, 10);
        if (*end != '\0' || prefix < 0)
            return -1;
    }
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, text, out->address) == 1) {
        out->family = AF_INET;
        out->prefix = prefix < 0 ? 32 : (int)prefix;
        return out->prefix <= 32 ? 0 : -1;
    }
    if (inet_pton(AF_INET6, text, out->address) == 1) {
        out->family = AF_INET6;
        out->prefix = prefix < 0 ? 128 : (int)prefix;
        return out->prefix <= 128 ? 0 : -1;
    }
    return -1;
}

static int parse_rules(const char *value)
{
    static char copy[RULES_MAX];
    char *addr, *ports, *item, *save = NULL, *end = NULL;

    if (strlen(value) >= sizeof(copy) || strncmp(value, "v1;addr=", 8) != 0)
        return -1;
    strcpy(copy, value);
    addr = copy + 8;
    ports = strstr(addr, ";ports=");
    if (ports == NULL)
        return -1;
    *ports = '\0';
    ports += 7;
    if (strcmp(addr, "*") == 0) {
        any_address = 1;
    } else if (strcmp(addr, "-") == 0) {
        network_count = 0;       /* no address is admitted */
    } else {
        if (*addr == '\0')
            return -1;
        for (item = strtok_r(addr, ",", &save); item != NULL; item = strtok_r(NULL, ",", &save)) {
            if (network_count >= MAX_NETWORKS || parse_network(item, &networks[network_count]) != 0)
                return -1;
            network_count++;
        }
        if (network_count == 0)
            return -1;
    }
    if (strcmp(ports, "*") == 0) {
        any_port = 1;
        return 0;
    }
    port_start = (int)strtol(ports, &end, 10);
    if (end == ports || *end != '-' || end[1] == '\0')
        return -1;
    ports = end + 1;
    port_end = (int)strtol(ports, &end, 10);
    if (*end != '\0' || port_start < 1 || port_end > 65535 || port_start > port_end)
        return -1;
    return 0;
}

__attribute__((constructor)) static void media_guard_start(void)
{
    const char *value = getenv("SIPPYCUP_MEDIA_GUARD_RULES");
    static char shown[RULES_MAX], line[RULES_MAX + 256];
    size_t index;

    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_send = dlsym(RTLD_NEXT, "send");
    if (value == NULL)
        return;
    if (parse_rules(value) != 0) {
        guard_mode = 2;
        say(PREFIX "error the rules could not be read; every media datagram is dropped\n");
        return;
    }
    guard_mode = 1;
    /* "v1;addr=A;ports=P" is printed as "v1 prog=NAME addr=A ports=P". */
    snprintf(shown, sizeof(shown), "%s", value + 3);
    for (index = 0; shown[index] != '\0'; index++)
        if (shown[index] == ';')
            shown[index] = ' ';
    snprintf(line, sizeof(line), PREFIX "active v1 prog=%s %s\n", program_invocation_short_name, shown);
    say(line);
}

static int inside(const unsigned char *address, int family)
{
    int index, bit;

    if (any_address)
        return 1;
    for (index = 0; index < network_count; index++) {
        const struct network *network = &networks[index];
        int matched = 1;
        if (network->family != family)
            continue;
        for (bit = 0; bit < network->prefix; bit++) {
            int mask = 0x80 >> (bit % 8);
            if ((address[bit / 8] & mask) != (network->address[bit / 8] & mask)) {
                matched = 0;
                break;
            }
        }
        if (matched)
            return 1;
    }
    return 0;
}

/* 1 when the datagram must be dropped. */
static int refused(int fd, const void *buffer, size_t length, const struct sockaddr *to, socklen_t to_length)
{
    static const unsigned char mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    const unsigned char *data = buffer;
    struct sockaddr_storage peer;
    unsigned char address[16];
    char text[INET6_ADDRSTRLEN] = "?";
    char line[160];
    const char *kind;
    int family, port, type = 0, allowed, count;
    socklen_t size = sizeof(type);

    if (guard_mode == 0 || buffer == NULL || length == 0)
        return 0;
    /* A SIP request, response or keep-alive: never judged here. */
    if ((data[0] >= 'A' && data[0] <= 'Z') || (data[0] >= 'a' && data[0] <= 'z')
            || data[0] == '\r' || data[0] == '\n')
        return 0;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) != 0 || type != SOCK_DGRAM)
        return 0;
    if (to == NULL) {
        socklen_t peer_length = sizeof(peer);
        if (getpeername(fd, (struct sockaddr *)&peer, &peer_length) != 0)
            return 0;            /* not connected: the kernel refuses it */
        to = (const struct sockaddr *)&peer;
        to_length = peer_length;
    }
    if (to->sa_family == AF_INET && to_length >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)to;
        family = AF_INET;
        memcpy(address, &in->sin_addr, 4);
        port = ntohs(in->sin_port);
    } else if (to->sa_family == AF_INET6 && to_length >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)to;
        port = ntohs(in6->sin6_port);
        if (memcmp(&in6->sin6_addr, mapped, 12) == 0) {
            family = AF_INET;
            memcpy(address, (const unsigned char *)&in6->sin6_addr + 12, 4);
        } else {
            family = AF_INET6;
            memcpy(address, &in6->sin6_addr, 16);
        }
    } else {
        return 0;                /* not an IP datagram (for example AF_UNIX) */
    }
    if ((data[0] & 0xc0) != 0x80)
        kind = "OTHER";
    else if (length >= 2 && data[1] >= 192 && data[1] <= 223)
        kind = "RTCP";           /* RFC 5761 packet types 192-223 */
    else
        kind = "RTP";
    allowed = guard_mode == 1 && inside(address, family)
        && (kind[2] == 'C' || any_port || (port >= port_start && port <= port_end));
    if (allowed)
        return 0;
    count = __atomic_add_fetch(&reported, 1, __ATOMIC_SEQ_CST);
    if (count <= MAX_REPORTED) {
        inet_ntop(family, address, text, sizeof(text));
        snprintf(line, sizeof(line), PREFIX "blocked %s to %s port %d\n", kind, text, port);
        say(line);
    } else if (count == MAX_REPORTED + 1) {
        say(PREFIX "more datagrams are being blocked and are not listed\n");
    }
    return 1;
}

ssize_t sendto(int fd, const void *buffer, size_t length, int flags,
               const struct sockaddr *to, socklen_t to_length)
{
    if (real_sendto == NULL)
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    if (refused(fd, buffer, length, to, to_length))
        return (ssize_t)length;
    if (real_sendto == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_sendto(fd, buffer, length, flags, to, to_length);
}

ssize_t send(int fd, const void *buffer, size_t length, int flags)
{
    if (real_send == NULL)
        real_send = dlsym(RTLD_NEXT, "send");
    if (refused(fd, buffer, length, NULL, 0))
        return (ssize_t)length;
    if (real_send == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_send(fd, buffer, length, flags);
}
