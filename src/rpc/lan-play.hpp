#pragma once
#include <string>
#include <vector>

struct NetInterface {
    std::string name;
    std::string description;
    std::vector<std::string> ips;
    NetInterface(std::string name): name(name) {}
};

enum class LanPlayStatus {
    None,
    Running,
};

struct LanPlayConfig {
    std::string relayServer;
    std::string socks5Server;
    std::string netif;
    bool fakeInternet;
    bool broadcast;
    int pmtu;
    LanPlayConfig():
        relayServer(""),
        socks5Server(""),
        netif(""),
        fakeInternet(false),
        broadcast(false),
        pmtu(0)
    {}
};

class LanPlay {
    private:
        std::string lastError;
        struct lan_play *lan_play;
        LanPlayConfig lastConfig;
        LanPlayStatus status;
        void applyConfig();
    public:
        LanPlayConfig config;
        LanPlay();
        ~LanPlay() {}
        const LanPlayConfig getLastConfig();
        const LanPlayStatus getStatus();
        const std::string getLastError();
        const std::string getVersion();
        int start();
        int stop();
        int getNetInterfaces(std::vector<NetInterface> &list);
};
