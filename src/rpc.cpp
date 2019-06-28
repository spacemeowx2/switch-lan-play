#include "lan-play.h"
#include <uvw.hpp>
#include <string>


class RPCServer {
    public:
        RPCServer(){}
        ~RPCServer(){}
        std::string onCommand(std::string command) {
            return command;
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

                rl->callback = [this, client, rl, authed](std::string line) {
                    std::string result;
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
                    result += "\n";
                    auto length = result.length();
                    auto data = new char[length];
                    memcpy(data, result.c_str(), length);
                    client->write(data, length);
                };

                client->on<uvw::DataEvent>([this, rl](uvw::DataEvent &e, uvw::TCPHandle &tcp) {
                    rl->feed(e.data.get(), e.length);
                });
                client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle &client) { client.close(); });

                srv.accept(*client);
                client->read();
            });

            server->listen();
        }
        std::string dataCallback(std::string line, uvw::TCPHandle &tcp) {
            return rpcServer->onCommand(line);
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
