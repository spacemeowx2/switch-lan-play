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
    return 0;
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
            // fprintf(stderr, "sdl_alen %d\n", link->sdl_alen);

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

int parse_addr(const char *str, struct sockaddr_in *addr)
{
    int len = strlen(str);
    if (len < 1 || len > 1000) {
        return -1;
    }

    int addr_start;
    int addr_len;
    int port_start;
    int port_len;

    // find ':'
    int i=0;
    while (i < len && str[i] != ':') i++;
    if (i >= len) {
        return -1;
    }
    addr_start = 0;
    addr_len = i - addr_start;
    port_start = i + 1;
    port_len = len - port_start;

    char addr_str[128];
    if (addr_len >= sizeof(addr_str)) {
        return -1;
    }
    memcpy(addr_str, str + addr_start, addr_len);
    addr_str[addr_len] = '\0';

    char port_str[6];
    if (port_len >= sizeof(port_str)) {
        return 0;
    }
    memcpy(port_str, str + port_start, port_len);
    port_str[port_len] = '\0';

    // parse port
    char *err;
    long int conv_res = strtol(port_str, &err, 10);
    if (port_str[0] == '\0' || *err != '\0') {
        return -1;
    }
    if (conv_res < 0 || conv_res > UINT16_MAX) {
        return -1;
    }
    uint16_t port = conv_res;

    struct addrinfo hints;
    struct addrinfo *addrs;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    int ret = getaddrinfo(addr_str, port_str, &hints, &addrs);
    if (ret != 0) {
        LLOG(LLOG_ERROR, "getaddrinfo %d %d", ret);
        return -1;
    }

    addr->sin_family = AF_INET;
    addr->sin_addr = ((struct sockaddr_in *)addrs->ai_addr)->sin_addr;
    addr->sin_port = htons(port);

    freeaddrinfo(addrs);

    return 0;
}

#if defined(_WIN32)
#ifndef _MSC_VER
static void win32_init_winsocket() __attribute__((constructor));
#endif
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
#endif
