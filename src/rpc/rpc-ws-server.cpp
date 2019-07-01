#include "rpc-ws-server.hpp"
#include "sha1.h"
#include "base64.hpp"
#include <algorithm>

namespace slp {
namespace rpc {

const char HTTP_RESP_400[] = "HTTP/1.1 400 Bad Request\r\n"
    "Content-Length: 0\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: Close\r\n" "\r\n";
const char HTTP_RESP_101_PART[] = "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Protocol: switch-lan-play-rpc\r\n"
    "Sec-WebSocket-Accept: ";

enum class WSCState {
    DO_HEADER,
    WAIT_HTTP,
    WAIT_DECODE_HEADER,
    WAITING_FOR_16_BIT_LENGTH,
    WAITING_FOR_64_BIT_LENGTH,
    WAITING_FOR_MASK_KEY,
    WAITING_FOR_PAYLOAD,
    DEAD
};

std::string tolower(const std::string str) {
    std::string data = str;
    std::transform(data.begin(), data.end(), data.begin(), ::tolower);
    return data;
}

void WSConnection::onData(uvw::DataEvent &e) {
    if (wsState == WSCState::DO_HEADER || wsState == WSCState::WAIT_HTTP) {
        rl.feed(e.data.get(), e.length);
    } else if (wsState == WSCState::DEAD) {
        return;
    } else {
        LLOG(LLOG_DEBUG, "onData len: %d", e.length);
    }
}

WSConnection::WSConnection(
    std::shared_ptr<uvw::TCPHandle> tcp,
    std::function<std::string(std::string line, uvw::TCPHandle &tcp)> callback,
    std::string token
):
    BaseTCPConnection(tcp, [this](std::string line, uvw::TCPHandle &tcp) -> std::string {
        if (wsState == WSCState::DO_HEADER) {
            if (line != "GET / HTTP/1.1") {
                wsState = WSCState::DEAD;
                return HTTP_RESP_400;
            }
            wsState = WSCState::WAIT_HTTP;
        } else if (wsState == WSCState::WAIT_HTTP) {
            if (line.length() > 0) {
                auto ePos = line.find(':');
                if (ePos == std::string::npos) {
                    wsState = WSCState::DEAD;
                    return HTTP_RESP_400;
                }
                std::string key, value;
                key = tolower(line.substr(0, ePos));
                while (line[ePos + 1] == ' ') {
                    ePos += 1;
                }
                value = line.substr(ePos + 1, line.length());

                headers[key] = value;
            } else {
                if (
                    headers["upgrade"] == "websocket"
                    && headers["connection"] == "Upgrade"
                    && headers["sec-websocket-version"] == "13"
                    && headers["sec-websocket-protocol"] == "switch-lan-play-rpc"
                    && headers["sec-websocket-key"].length() > 0
                ) {
                    auto key = headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                    SHA1_CTX hashctx;
                    unsigned char digest[20];
                    SHA1Init(&hashctx);
                    SHA1Update(&hashctx, (const unsigned char *)key.c_str(), key.length());
                    SHA1Final(digest, &hashctx);
                    auto accept = base64_encode(digest, sizeof(digest));
                    wsState = WSCState::WAIT_DECODE_HEADER;
                    std::string result(HTTP_RESP_101_PART);
                    return result + accept + "\r\n\r\n";
                } else {
                    wsState = WSCState::DEAD;
                    return HTTP_RESP_400;
                }
            }
        }
        return "";
    }),
    wsState(WSCState::DO_HEADER),
    token(token),
    handshaked(false),
    callback(callback)
{};

}
}
