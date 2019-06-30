#include <uvw.hpp>
#include <string>
#include <algorithm>
#include "lan-play.h"

struct NetInterface {
    std::string name;
    std::string description;
    std::vector<std::string> ips;
    NetInterface(std::string name): name(name) {}
};

struct RPCError {
    std::string error;
    RPCError(std::string error): error(error) {}
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
        void applyConfig() {
            options.broadcast = config.broadcast;
            options.fake_internet = config.fakeInternet;
            options.pmtu = config.pmtu;
            options_netif(config.netif.c_str());
            options_relay_server_addr(config.relayServer.c_str());
            options_socks5_server_addr(config.socks5Server.c_str());
            lastConfig = config;
        }
    public:
        LanPlayConfig config;
        LanPlay(): lan_play(&real_lan_play), status(LanPlayStatus::None) {
            lan_play->loop = uv_default_loop();
        }
        ~LanPlay() {}
        const LanPlayConfig getLastConfig() {
            return lastConfig;
        }
        int start() {
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
        int stop() {
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
        LanPlayStatus getStatus() {
            return status;
        }
        std::string getLastError() {
            return lastError;
        }
        int getNetInterfaces(std::vector<NetInterface> &list) {
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
};

class RPCServer {
    private:
        LanPlay lanPlay;
    private:
        std::string stringReplace(std::string str, std::string src, std::string dst) {
            std::string::size_type pos = str.find(src, 0);
            auto srcLen = src.size();
            auto dstLen = dst.size();
            while (pos != std::string::npos) {
                str.replace(pos, srcLen, dst);
                pos = str.find(src, pos + dstLen);
            }
            return str;
        }
        std::string escape(std::string value) {
            return "\"" + stringReplace(value, "\"", "\\\"") + "\"";
        }
        std::string kv(std::string key, std::string value) {
            return key + "=" + escape(value) + "\n";
        }
        std::string kv(std::string key, int value) {
            return key + "=" + std::to_string(value) + "\n";
        }
        std::string kv(std::string key, bool value) {
            if (value) {
                return key + "=true\n";
            } else {
                return key + "=false\n";
            }
        }
        std::string success(std::string value = "") {
            return kv("success", value);
        }
        std::string error(std::string value) {
            return kv("error", value);
        }
        std::string getConfig(const LanPlayConfig &config) {
            std::string out;

            out += "[config]\n";
            out += kv("netif", config.netif);
            out += kv("relayServer", config.relayServer);
            out += kv("socks5Server", config.socks5Server);
            out += kv("pmtu", config.pmtu);
            out += kv("fakeInternet", config.fakeInternet);
            out += kv("broadcast", config.broadcast);

            return out;
        }
    public:
        RPCServer(){}
        ~RPCServer(){}
        std::string onMessage(std::string message) {
            std::string out;
            auto ePos = message.find('=');
            std::string key, value;
            if (ePos == std::string::npos) {
                key = message;
            } else {
                key = message.substr(0, ePos);
                value = message.substr(ePos + 1, message.length());
            }
            if (key == "status") {
                auto status = lanPlay.getStatus();
                if (status == LanPlayStatus::None) {
                    out = success("None");
                } else if (status == LanPlayStatus::Running) {
                    out = success("Running");
                }
            } else if (key == "listIf") {
                std::vector<NetInterface> list;
                if (lanPlay.getNetInterfaces(list) == 0) {
                    out = success();
                    for (auto netif : list) {
                        out += "[[interfaces]]\n";
                        out += kv("name", netif.name);
                        out += kv("description", netif.description);
                        out += "ips=[\n";
                        for (auto ip : netif.ips) {
                            out += "  " + escape(ip) + ",\n";
                        }
                        out += "]\n";
                    }
                } else {
                    out = error(lanPlay.getLastError());
                }
            } else if (key == "version") {
                out = success(LANPLAY_VERSION);
            } else if (key == "start") {
                if (lanPlay.start() == 0) {
                    out = success();
                } else {
                    out = error(lanPlay.getLastError());
                }
            } else if (key == "stop") {
                if (lanPlay.stop() == 0) {
                    out = success();
                } else {
                    out = error(lanPlay.getLastError());
                }
            } else if (key == "config") {
                out = success();
                out += getConfig(lanPlay.config);
            } else if (key == "lastConfig") {
                out = success();
                out += getConfig(lanPlay.getLastConfig());
            } else if (key == "netif") {
                lanPlay.config.netif = value;
                out = success();
                out += getConfig(lanPlay.config);
            } else if (key == "relayServer") {
                lanPlay.config.relayServer = value;
                out = success();
                out += getConfig(lanPlay.config);
            } else if (key == "socks5Server") {
                lanPlay.config.socks5Server = value;
                out = success();
                out += getConfig(lanPlay.config);
            } else if (key == "debug") {
                out = success();
                out += kv("debug", options.relay_server_addr);
            } else {
                out = error("command not found: " + key);
            }
            return out;
        }
};

class ReadLine {
    private:
        using ReadLineCallback = std::function<void(std::string line)>;
        std::string buffer;
    public:
        ReadLineCallback callback;
        ReadLine(ReadLineCallback callback): callback(callback) {}
        ReadLine(): callback([](std::string){}) {}
        ~ReadLine(){}
        void feed(const char *ptr, size_t length) {
            std::string buf(ptr, length);
            buffer += buf;

            size_t index = buffer.find('\n');
            while (index != std::string::npos) {
                std::string line = buffer.substr(0, index);
                buffer = buffer.substr(index + 1);
                auto len = line.length();
                if (line[len - 1] == '\r') {
                    line = line.substr(0, len - 1);
                }
                callback(line);
                index = buffer.find('\n');
            }
        }
};

class RPCTCPServer {
    private:
        std::shared_ptr<RPCServer> rpcServer;
        std::string bindAddr;
        uint16_t bindPort;
        std::string token;
        std::shared_ptr<uvw::Loop> loop;
        std::shared_ptr<uvw::TCPHandle> server;
        void initServer() {
            server->bind(this->bindAddr, this->bindPort);
            server->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &err, uvw::TCPHandle &) {
                LLOG(LLOG_ERROR, "server erroor: %s", err.what());
            });
            server->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv) {
                auto client = srv.loop().resource<uvw::TCPHandle>();
                auto rl = std::make_shared<ReadLine>();
                auto authed = std::make_shared<bool>(false);

                rl->callback = [this, weakClient = std::weak_ptr<uvw::TCPHandle>(client), weakRl = std::weak_ptr<ReadLine>(rl), authed](std::string line) {
                    std::string result;
                    auto client = weakClient.lock();
                    auto rl = weakRl.lock();
                    if (client && rl) {
                        if (*authed) {
                            result = this->dataCallback(line, *client);
                        } else {
                            if (line == this->token) {
                                *authed = true;
                                result = "success=\"authorized\"";
                            } else {
                                result = "error=\"authorized failed: invalid token\"";
                            }
                        }
                        result += "\n# end\n";
                        auto length = result.length();
                        auto data = new char[length];
                        memcpy(data, result.c_str(), length);
                        client->write(data, length);
                    } else {
                        LLOG(LLOG_WARNING, "client or rl weak_ptr lost");
                    }
                };

                client->on<uvw::DataEvent>([this, rl](uvw::DataEvent &e, uvw::TCPHandle &tcp) {
                    rl->feed(e.data.get(), e.length);
                });
                client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle &client) {
                    client.close();
                });

                srv.accept(*client);
                client->read();
            });

            server->listen();
        }
        std::string dataCallback(std::string line, uvw::TCPHandle &tcp) {
            return rpcServer->onMessage(line);
        }
    public:
        RPCTCPServer(
            std::shared_ptr<RPCServer> rpcServer, const char *bind_addr, uint16_t port, const char *token
        ):
            rpcServer(rpcServer),
            bindAddr(std::string(bind_addr)),
            bindPort(port),
            loop(uvw::Loop::getDefault()),
            server(loop->resource<uvw::TCPHandle>())
        {
            if (token) {
                this->token = std::string(token);
            } else {
                this->token = "";
            }
        }
        int run() {
            initServer();
            if (!loop->run()) {
                return -1;
            }
            return 0;
        }
        ~RPCTCPServer() {}
};

int rpc_main(const char *bind_addr, const char *token)
{
    char addr_str[128];
    uint16_t port;
    if (parse_ip_port(bind_addr, addr_str, sizeof(addr_str), &port) != 0) {
        eprintf("Failed to parse rpc server: %s\n", bind_addr);
        return -1;
    }

    auto server = std::make_shared<RPCServer>();
    RPCTCPServer tcpServer(server, addr_str, port, token);
    LLOG(LLOG_INFO, "rpc server listening at %s", bind_addr);
    return tcpServer.run();
}
