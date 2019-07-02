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
            out = success(lanPlay.getVersion());
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
        } else if (key == "stdout") {
            out = "";
            auto timer = server->loop->resource<uvw::TimerHandle>();
            timer->on<uvw::TimerEvent>([this] (uvw::TimerEvent &e, uvw::TimerHandle &timer) {
                 if (!this->sendBack("timer")) {
                     LLOG(LLOG_DEBUG, "timer stop");
                     timer.close();
                 }
            });
            timer->start(uvw::TimerHandle::Time{0}, uvw::TimerHandle::Time{1000});
        } else {
            out = error("command not found: " + key);
        }
        return out;
    }
    return "server lost";
}

}
}
