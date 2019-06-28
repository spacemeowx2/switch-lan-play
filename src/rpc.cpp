#include "lan-play.h"
#include <uvw.hpp>
#include <string>
#include <algorithm>

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

class LanPlay {
    private:
        std::string lastError;
    public:
        LanPlay() {}
        ~LanPlay() {}
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
    public:
        RPCServer(){}
        ~RPCServer(){}
        std::string onMessage(std::string message) {
            std::string out;
            if (message == "status") {
                out = kv("success", "none");
            } else if (message == "list_if") {
                std::vector<NetInterface> list;
                if (lanPlay.getNetInterfaces(list) == 0) {
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
                    out = kv("error", lanPlay.getLastError());
                }
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
            server->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv) {
                auto client = srv.loop().resource<uvw::TCPHandle>();
                auto rl = std::make_shared<ReadLine>();
                auto authed = std::make_shared<bool>(false);

                rl->callback = [this, weakClient = std::weak_ptr(client), weakRl = std::weak_ptr(rl), authed](std::string line) {
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
