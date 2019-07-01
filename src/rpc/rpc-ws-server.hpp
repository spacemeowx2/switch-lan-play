#pragma once
#include <unordered_map>
#include <uvw.hpp>
#include <base/llog.h>
#include "rpc-server.hpp"
#include "read-line.hpp"
#include "rpc-tcp-server.hpp"

namespace slp {
namespace rpc {

enum class WSCState;

class WSConnection : public BaseTCPConnection {
    protected:
        WSCState wsState;
        std::string token;
        std::unordered_map<std::string, std::string> headers;
        virtual void onData(uvw::DataEvent &e);
        bool handshaked;
        std::function<std::string(std::string line, uvw::TCPHandle &tcp)> callback;
    public:
        WSConnection(
            std::shared_ptr<uvw::TCPHandle> tcp,
            std::function<std::string(std::string line, uvw::TCPHandle &tcp)> callback,
            std::string token
        );
        ~WSConnection() {};
};

using RPCWSServer = BaseRPCTCPServer<WSConnection>;

}
}
