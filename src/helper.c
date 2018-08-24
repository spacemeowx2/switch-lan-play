#include <stdio.h>
#include <stdint.h>
#if __APPLE__
#include <sys/ioctl.h>
#include <net/bpf.h>
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
#if __APPLE__
int set_immediate_mode(int fd)
{
    int on = 1;
    return ioctl(fd, BIOCIMMEDIATE, &on);
}
#endif
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
#pragma comment(lib, "IPHLPAPI.lib")

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

// Find mac address using GetIFTable, since the GetAdaptersAddresses etc     functions
// ony work with adapters that have an IP address
int get_mac_address(pcap_if_t *d, u_char mac_addr[6])
{
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

    return nRVal;
}
#endif
