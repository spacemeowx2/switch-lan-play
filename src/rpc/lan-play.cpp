#include <uvw.hpp>
#include "lan-play.hpp"
#include "../lan-play.h"

void LanPlay::applyConfig() {
    options.broadcast = config.broadcast;
    options.fake_internet = config.fakeInternet;
    options.pmtu = config.pmtu;
    options_netif(config.netif.c_str());
    options_relay_server_addr(config.relayServer.c_str());
    options_socks5_server_addr(config.socks5Server.c_str());
    lastConfig = config;
}

LanPlay::LanPlay(): lan_play(&real_lan_play), status(LanPlayStatus::None) {
    lan_play->loop = uv_default_loop();
}

const LanPlayConfig LanPlay::getLastConfig() {
    return lastConfig;
}

int LanPlay::start() {
    int ret = 0;
    if (status == LanPlayStatus::Running) {
        lastError = "Already running";
        return -1;
    }
    applyConfig();
    ret = lan_play_init(lan_play);
    if (ret == 0) {
        status = LanPlayStatus::Running;
    } else {
        lastError = lan_play->last_err;
    }
    return ret;
}

int LanPlay::stop() {
    int ret = 0;
    if (status == LanPlayStatus::None) {
        lastError = "Already stopped";
        return -1;
    }
    ret = lan_play_close(lan_play);
    if (ret == 0) {
        status = LanPlayStatus::None;
    } else {
        lastError = lan_play->last_err;
    }
    return ret;
}

const LanPlayStatus LanPlay::getStatus() {
    return status;
}

const std::string LanPlay::getLastError() {
    return lastError;
}

const std::string LanPlay::getVersion() {
    return LANPLAY_VERSION;
}

int LanPlay::getNetInterfaces(std::vector<NetInterface> &list) {
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *d;
    pcap_if_t *allDevs;

    if (pcap_findalldevs(&allDevs, errBuf)) {
        eprintf("Error pcap_findalldevs: %s\n", errBuf);
        lastError = errBuf;
        return -1;
    }

    list.clear();
    for (d = allDevs; d; d = d->next) {
        NetInterface netif(d->name);
        if (d->description) {
            netif.description = d->description;
        }
        if (d->addresses) {
            struct pcap_addr *taddr;
            struct sockaddr_in *sin;
            char revIP[100];
            for (taddr = d->addresses; taddr; taddr = taddr->next)
            {
                sin = (struct sockaddr_in *)taddr->addr;
                if (sin->sin_family == AF_INET) {
                    strncpy(revIP, inet_ntoa(sin->sin_addr), sizeof(revIP));
                    netif.ips.push_back(std::string(revIP));
                }
            }
        }
        list.push_back(netif);
    }

    return 0;
}
