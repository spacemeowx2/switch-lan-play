#pragma once
#include <unordered_map>
#include <uvw.hpp>
#include <base/llog.h>
#include "rpc-server.hpp"
#include "read-line.hpp"
#include "rpc-tcp-server.hpp"
#include "buffer-list.hpp"

namespace slp {
namespace rpc {

enum class WSCState;

struct WSFrame {
    bool fin;
    bool rsv1;
    bool rsv2;
    bool rsv3;
    bool mask;
    uint8_t opcode;
    uint64_t length;
    char maskBytes[4];
    std::unique_ptr<char[]> data;
    void clear() {
        fin = false;
        rsv1 = rsv2 = rsv3 = false;
        mask = false;
        opcode = 0;
        length = 0;
        memset(maskBytes, 0, 4);
        data.reset();
    }
};

class WSConnection : public BaseTCPConnection {
    protected:
        WSCState wsState;
        bool authed;
        std::size_t pos;
        std::string token;
        std::string path;
        std::unordered_map<std::string, std::string> headers;
        bool handshaked;
        std::function<std::string(std::string line, uvw::TCPHandle &tcp)> callback;
        BufferList bl;
        WSFrame frame;

        virtual void onData(uvw::DataEvent &e);
        virtual void onSend(std::string &result, std::shared_ptr<uvw::TCPHandle> &client);
        void onFrame();
        void sendText(std::shared_ptr<uvw::TCPHandle> &tcp, std::string &str);
        std::string sendFile(const std::string path);
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
