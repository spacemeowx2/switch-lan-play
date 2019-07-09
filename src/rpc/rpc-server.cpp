#include "rpc-server.hpp"
#include <base/llog.h>

namespace slp {
namespace rpc {

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
std::string kv(std::string key, const char *value) {
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
std::string error(std::string value) {
    return kv("error", value);
}
std::string getConfig(std::string prefix, const LanPlayConfig &config) {
    std::string out;

    out += "[" + prefix + "]\n";
    out += kv("netif", config.netif);
    out += kv("relayServer", config.relayServer);
    out += kv("socks5Server", config.socks5Server);
    out += kv("pmtu", config.pmtu);
    out += kv("fakeInternet", config.fakeInternet);
    out += kv("broadcast", config.broadcast);

    return out;
}
std::string getConfig(const LanPlayConfig &config) {
    return getConfig("config", config);
}

RPCServer::RPCServer(std::shared_ptr<uvw::Loop> loop):
    loop(loop)
{};

std::shared_ptr<RPCServerSession> RPCServer::createSession() {
    return std::make_shared<RPCServerSession>(this->shared_from_this());
}

RPCServerSession::RPCServerSession(std::shared_ptr<RPCServer> server):
    weakServer(server),
    sendBack([](std::string){ return false; })
{}

std::string RPCServerSession::onMessage(std::string message) {
    auto server = weakServer.lock();
    if (server) {
        auto &lanPlay = server->lanPlay;
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
                out = kv("status", "None");
            } else if (status == LanPlayStatus::Running) {
                out = kv("status", "Running");
            }
        } else if (key == "listIf") {
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
                out = error(lanPlay.getLastError());
            }
        } else if (key == "version") {
            out = kv("version", lanPlay.getVersion());
        } else if (key == "start") {
            if (lanPlay.start() == 0) {
                out = kv("status", "Running");
            } else {
                out = error(lanPlay.getLastError());
            }
        } else if (key == "stop") {
            if (lanPlay.stop() == 0) {
                out = kv("status", "None");
            } else {
                out = error(lanPlay.getLastError());
            }
        } else if (key == "config") {
            out = getConfig(lanPlay.config);
        } else if (key == "lastConfig") {
            out = getConfig("lastConfig", lanPlay.getLastConfig());
        } else if (key == "netif") {
            lanPlay.config.netif = value;
            out = getConfig(lanPlay.config);
        } else if (key == "relayServer") {
            lanPlay.config.relayServer = value;
            out = getConfig(lanPlay.config);
        } else if (key == "socks5Server") {
            lanPlay.config.socks5Server = value;
            out = getConfig(lanPlay.config);
        } else if (key == "fakeInternet") {
            lanPlay.config.fakeInternet = value == "true";
            out = getConfig(lanPlay.config);
        } else if (key == "broadcast") {
            lanPlay.config.broadcast = value == "true";
            out = getConfig(lanPlay.config);
        } else if (key == "pmtu") {
            try {
                lanPlay.config.pmtu = std::stoi(value, nullptr, 0);
                out = getConfig(lanPlay.config);
            } catch (std::invalid_argument e) {
                out = error(e.what());
            }
        } else {
            out = error("command not found: " + key);
        }
        return out;
    }
    return "server lost";
}

}
}
