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
        return rl.feed(e.data.get(), e.length);
    } else if (wsState == WSCState::DEAD) {
        return;
    }

    if (wsState == WSCState::WAIT_DECODE_HEADER) {
        bl.add(std::move(e.data), e.length);
        if (bl.size() >= 2) {
            frame.clear();

            auto firstByte = bl[0];
            auto secondByte = bl[1];

            frame.fin = !!(firstByte & 0x80);
            frame.rsv1 = !!(firstByte & 0x40);
            frame.rsv2 = !!(firstByte & 0x20);
            frame.rsv3 = !!(firstByte & 0x10);
            frame.mask = !!(secondByte & 0x80);

            frame.opcode = firstByte & 0x0F;
            frame.length = secondByte & 0x7F;

            if (frame.length == 126) {
                wsState = WSCState::WAITING_FOR_16_BIT_LENGTH;
            } else if (frame.length == 127) {
                wsState = WSCState::WAITING_FOR_64_BIT_LENGTH;
            } else {
                wsState = WSCState::WAITING_FOR_MASK_KEY;
                frame.data = std::make_unique<char[]>(frame.length);
            }

            bl.advance(2);
        }
    }
    if (wsState == WSCState::WAITING_FOR_16_BIT_LENGTH) {
        if (bl.size() >= 2) {
            frame.length = (bl[0] << 8) | bl[1];
            wsState = WSCState::WAITING_FOR_MASK_KEY;
            frame.data = std::make_unique<char[]>(frame.length);
            bl.advance(2);
        }
    }
    if (wsState == WSCState::WAITING_FOR_64_BIT_LENGTH) {
        LLOG(LLOG_ERROR, "Unsupported 64bit websocket frame");
        wsState = WSCState::DEAD;
    }
    if (wsState == WSCState::WAITING_FOR_MASK_KEY) {
        if (frame.mask) {
            if (bl.size() >= 4) {
                wsState = WSCState::WAITING_FOR_PAYLOAD;
                bl.copyTo(0, frame.maskBytes, 4);
                bl.advance(4);
            }
        } else {
            wsState = WSCState::WAITING_FOR_PAYLOAD;
        }
    }
    if (wsState == WSCState::WAITING_FOR_PAYLOAD) {
        if (bl.size() >= frame.length) {
            bl.copyTo(0, frame.data.get(), frame.length);
            bl.advance(frame.length);
            if (frame.mask) {
                for (unsigned int i = 0; i < frame.length; i++) {
                    frame.data[i] ^= frame.maskBytes[i % 4];
                }
            }
            wsState = WSCState::WAIT_DECODE_HEADER;
            onFrame();
        }
    }
}

void WSConnection::onFrame() {
    if (frame.opcode != 1) {
        LLOG(LLOG_DEBUG, "ignore frame opcode %d len %d", frame.opcode, frame.length);
    }

    std::string line(frame.data.get(), frame.length);
    frame.data.reset();

    auto client = weak_tcp.lock();
    if (client) {
        std::string result;
        if (authed) {
            result = callback(line, *client);
        } else {
            if (line == this->token) {
                authed = true;
                result = "success=\"authorized\"";
            } else {
                result = "error=\"authorized failed: invalid token\"";
            }
        }
        auto length = result.length();
        if (length > 0) {
            this->sendText(*client, result);
        }
    } else {
        LLOG(LLOG_WARNING, "client or rl weak_ptr lost");
    }
}

void WSConnection::sendText(uvw::TCPHandle &client, std::string &str) {
    char header[14];
    int headerSize = 0;
    auto length = str.length();

    // fin=1, opcode=1
    header[0] = 0x81;
    // mask=0
    if (length < 126) {
        header[1] = length & 0x7f;
        headerSize = 2;
    } else if (length < 65536) {
        header[1] = 126 & 0x7f;
        header[2] = length >> 8;
        header[3] = length;
        headerSize = 4;
    } else {
        LLOG(LLOG_ERROR, "sendText too large %d", length);
        return;
        headerSize = 10;
    }

    client.write(header, headerSize);

    auto data = new char[length];
    memcpy(data, str.c_str(), length);
    client.write(data, length);
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
    authed(false),
    token(token),
    handshaked(false),
    callback(callback)
{};

}
}
