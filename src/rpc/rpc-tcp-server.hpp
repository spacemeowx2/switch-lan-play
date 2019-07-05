#pragma once
#include <uvw.hpp>
#include <base/llog.h>
#include <cstring>
#include "rpc-server.hpp"
#include "read-line.hpp"

namespace slp {
namespace rpc {

class BaseTCPConnection {
    protected:
        std::weak_ptr<uvw::TCPHandle> weak_tcp;
        ReadLine rl;
        virtual void onData(uvw::DataEvent &e) {
            rl.feed(e.data.get(), e.length);
        };
        virtual void onSend(std::string &result, std::shared_ptr<uvw::TCPHandle> &client) = 0;
    public:
        BaseTCPConnection(
            std::shared_ptr<uvw::TCPHandle> tcp,
            std::function<std::string(std::string line, uvw::TCPHandle &tcp)> callback
        ):
            weak_tcp(tcp)
        {
            rl.callback = [this, callback](std::string line) {
                std::string result;
                auto client = weak_tcp.lock();
                if (client) {
                    result = callback(line, *client);
                    auto length = result.length();
                    if (length > 0) {
                        auto data = new char[length];
                        memcpy(data, result.c_str(), length);
                        client->write(data, length);
                    }
                } else {
                    LLOG(LLOG_WARNING, "client or rl weak_ptr lost");
                }
            };
            tcp->on<uvw::DataEvent>([this](uvw::DataEvent &e, uvw::TCPHandle &tcp) {
                this->onData(e);
            });
        };
        ~BaseTCPConnection() {
        };
        bool close() {
            auto client = weak_tcp.lock();
            if (client) {
                client->close();
                return true;
            } else {
                LLOG(LLOG_WARNING, "close: client or rl weak_ptr lost");
                return false;
            }
        }
        bool send(std::string result) {
            auto client = weak_tcp.lock();
            if (client) {
                onSend(result, client);
                return true;
            } else {
                LLOG(LLOG_WARNING, "send: client or rl weak_ptr lost");
                return false;
            }
        }
};

class TCPConnection : public BaseTCPConnection {
    protected:
        bool authed;
        std::string token;
        virtual void onSend(std::string &result, std::shared_ptr<uvw::TCPHandle> &client) {
            auto length = result.length();
            if (length > 0) {
                auto data = new char[length];
                memcpy(data, result.c_str(), length);
                client->write(data, length);
            }
        }
    public:
        TCPConnection(
            std::shared_ptr<uvw::TCPHandle> tcp,
            std::function<std::string(std::string line, uvw::TCPHandle &tcp)> callback,
            std::string token
        ):
            BaseTCPConnection(tcp, [this, callback](std::string line, uvw::TCPHandle &client) {
                std::string result;
                if (authed) {
                    result = callback(line, client);
                } else {
                    if (line == this->token) {
                        authed = true;
                        result = "success=\"authorized\"";
                    } else {
                        result = "error=\"authorized failed: invalid token\"";
                    }
                }
                result += "\n# end\n";
                return result;
            }),
            authed(false),
            token(token)
        {};
        ~TCPConnection() {
        };
};

template <typename T>
class BaseRPCTCPServer {
    protected:
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
                auto session = rpcServer->createSession();
                auto wsConn = std::make_shared<T>(
                    client,
                    [this, session] (std::string line, uvw::TCPHandle &tcp) -> std::string {
                        return session->onMessage(line);
                    },
                    this->token
                );
                session->sendBack = [conn = std::weak_ptr<T>(wsConn)] (std::string str) -> bool {
                    auto c = conn.lock();
                    if (c) {
                        c->send(str);
                        return true;
                    }
                    return false;
                };

                client->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &e, uvw::TCPHandle &tcp) {
                    tcp.close();
                });
                client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle &tcp) {
                    tcp.close();
                });
                client->on<uvw::CloseEvent>([wsConn](const uvw::CloseEvent &, uvw::TCPHandle &) {
                });

                srv.accept(*client);
                client->read();
            });

            server->listen();
        }
    public:
        BaseRPCTCPServer(
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
        ~BaseRPCTCPServer() {}
};
using RPCTCPServer = BaseRPCTCPServer<TCPConnection>;

}
}
