#pragma once
#include <uvw.hpp>
#include <string>
#include "lan-play.hpp"

namespace slp {
namespace rpc {

class RPCServerSession;
class RPCServer : public std::enable_shared_from_this<RPCServer> {
    private:
        std::shared_ptr<uvw::Loop> loop;
        friend class RPCServerSession;
        LanPlay lanPlay;
    public:
        RPCServer(std::shared_ptr<uvw::Loop> loop);
        RPCServer(): loop(uvw::Loop::getDefault()) {};
        ~RPCServer(){};
        std::shared_ptr<RPCServerSession> createSession();
};

class RPCServerSession {
    private:
        std::weak_ptr<RPCServer> weakServer;
    public:
        std::function<bool(std::string)> sendBack;
        RPCServerSession(std::shared_ptr<RPCServer> server);
        ~RPCServerSession(){};
        std::string onMessage(std::string message);
};

}
}
