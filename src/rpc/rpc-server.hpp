#pragma once
#include <string>
#include "lan-play.hpp"

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
            } else {
                out = error("command not found: " + key);
            }
            return out;
        }
};
