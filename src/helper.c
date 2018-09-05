#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <base/llog.h>
#if !defined(_WIN32)
#include <sys/ioctl.h>
#include <net/if.h>
#endif
#if __APPLE__
#include <net/bpf.h>
#include <net/if_dl.h>
#endif
#include "helper.h"
#include "config.h"

const char *ip2str(void *ip)
{
    const uint8_t *sip = (uint8_t *)ip;
    static char str[IP_STR_LEN];
    snprintf(str, sizeof(str), "%d.%d.%d.%d", sip[0], sip[1], sip[2], sip[3]);
    return str;
}
void *str2ip(const char *ip)
{
    static uint8_t bin[4];
    int p[4];
    int i;
    sscanf(ip, "%d.%d.%d.%d", &p[0], &p[1], &p[2], &p[3]);
    for (i=0; i<4; i++) {
        bin[i] = p[i];
    }
    return bin;
}
int set_immediate_mode(pcap_t *p)
{
#if __APPLE__
    int fd;
    int on = 1;
    fd = pcap_fileno(p);
    return ioctl(fd, BIOCIMMEDIATE, &on);
#elif defined(_WIN32)
    return pcap_setmintocopy(p, 0); // low latency
#endif
}
void print_hex(const void *buf, int len)
{
    int i;
    const uint8_t *packet = buf;

    for (i=0; i < len; ++i) {
        printf(" %02x", packet[i]);
        if ( (i + 1) % 16 == 0 ) {
            printf("\n");
        }
    }

    printf("\n\n");
}

#if defined(_WIN32)
// https://stackoverflow.com/questions/47748975/how-to-get-selected-adapters-mac-address-in-winpcap
#include <winsock2.h>
#include <iphlpapi.h>

// Compare the guid parts of both names and see if they match
int compare_guid(wchar_t *wszPcapName, wchar_t *wszIfName)
{
    wchar_t *pc, *ic;

    // Find first { char in device name from pcap
    for (pc = wszPcapName; ; ++pc)
    {
        if (!*pc)
            return -1;

        if (*pc == L'{'){
            pc++;
            break;
        }
    }

    // Find first { char in interface name from windows
    for (ic = wszIfName; ; ++ic)
    {
        if (!*ic)
            return 1;

        if (*ic == L'{'){
            ic++;
            break;
        }
    }

    // See if the rest of the GUID string matches
    for (;; ++pc,++ic)
    {
        if (!pc)
            return -1;

        if (!ic)
            return 1;

        if ((*pc == L'}') && (*ic == L'}'))
            return 0;

        if (*pc != *ic)
            return *ic - *pc;
    }
}
#endif

// Find mac address using GetIFTable, since the GetAdaptersAddresses etc     functions
// ony work with adapters that have an IP address
int get_mac_address(pcap_if_t *d, pcap_t *p, u_char mac_addr[6])
{
#if defined(_WIN32)
    // Declare and initialize variables.

    wchar_t* wszWideName = NULL;

    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    int nRVal = 0;

    unsigned int i;


    /* variables used for GetIfTable and GetIfEntry */
    MIB_IFTABLE *pIfTable;
    MIB_IFROW *pIfRow;

    // Allocate memory for our pointers.
    pIfTable = (MIB_IFTABLE *)malloc(sizeof(MIB_IFTABLE));
    if (pIfTable == NULL) {
        return 0;
    }
    // Make an initial call to GetIfTable to get the
    // necessary size into dwSize
    dwSize = sizeof(MIB_IFTABLE);
    dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE);

    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        free(pIfTable);
        pIfTable = (MIB_IFTABLE *)malloc(dwSize);
        if (pIfTable == NULL) {
            return 0;
        }

        dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE);
    }

    if (dwRetVal != NO_ERROR)
        goto done;

    // Convert input pcap device name to a wide string for compare
    {
        size_t stISize,stOSize;

        stISize = strlen(d->name) + 1;

        wszWideName = malloc(stISize * sizeof(wchar_t));

        if (!wszWideName)
            goto done;

        mbstowcs_s(&stOSize,wszWideName,stISize, d->name, stISize);
    }

    for (i = 0; i < pIfTable->dwNumEntries; i++) {
        pIfRow = (MIB_IFROW *)& pIfTable->table[i];

        if (!compare_guid(wszWideName, pIfRow->wszName)){
            if (pIfRow->dwPhysAddrLen != 6)
                continue;

            memcpy(mac_addr, pIfRow->bPhysAddr, 6);
            nRVal = 1;
            break;
        }
    }

done:
    if (pIfTable != NULL)
        free(pIfTable);
    pIfTable = NULL;

    if (wszWideName != NULL)
        free(wszWideName);
    wszWideName = NULL;

    return nRVal == 1 ? 0 : -1;
#elif defined(__linux__)
    int fd = pcap_fileno(p);
    struct ifreq buffer;
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, d->name);
    int result = ioctl(fd, SIOCGIFHWADDR, &buffer);
    if (result < 0)
    {
        fprintf(stderr, "%s %d\n", strerror(errno), fd);
        exit(1);
    }
    memcpy(mac_addr, buffer.ifr_hwaddr.sa_data, 6);
    return result;
#elif defined(__APPLE__)
#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))
    pcap_addr_t *alladdrs;
    pcap_addr_t *a;
    struct sockaddr_dl* link;

    alladdrs = d->addresses;
    for (a = alladdrs; a != NULL; a = a->next) {
        if(a->addr->sa_family == AF_LINK) {
            link = (struct sockaddr_dl*)a->addr->sa_data;

            caddr_t macaddr = LLADDR(link);
            fprintf(stderr, "sdl_alen %d\n", link->sdl_alen);

            if (link->sdl_alen == 6) {
                memcpy(mac_addr, macaddr, 6);
                return 0;
            } else if(link->sdl_alen > 6) {
                memcpy(mac_addr, (uint8_t *)macaddr + 1, 6);
                return 0;
            }
        }
    }
    return -1;
#else
    #error("platform not support");
#endif
}

#if defined(_WIN32)
static void win32_init_winsocket() __attribute__((constructor));
static void win32_init_winsocket()
{
    int result;
    WSADATA data;

    // Initialize Winsock
    result = WSAStartup(MAKEWORD(2,2), &data);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        exit(1);
    }
}
// http://web.mit.edu/freebsd/head/crypto/heimdal/lib/roken/sendmsg.c
ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
    int srv;
    DWORD num_bytes_sent = 0;

    /* TODO: For _WIN32_WINNT >= 0x0600 we can use WSASendMsg using
       WSAMSG which is a much more direct analogue to sendmsg(). */

    srv = WSASendTo(s, (LPWSABUF)msg->msg_iov, msg->msg_iovlen,
		  &num_bytes_sent, flags, msg->msg_name, msg->msg_namelen, NULL, NULL);

    if (srv == 0) {
        return (int) num_bytes_sent;
    }

    /* srv == SOCKET_ERROR and WSAGetLastError() == WSA_IO_PENDING
       indicates that a non-blocking transfer has been scheduled.
       We'll have to check for that if we ever support non-blocking
       I/O. */
    LLOG(LLOG_ERROR, "sendmsg fd: %d last err:%d len %d", s, WSAGetLastError(), msg->msg_iovlen);
    return -1;
}
#endif
