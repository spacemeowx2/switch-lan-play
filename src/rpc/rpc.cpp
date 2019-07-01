#include <string>
#include <algorithm>
#include <base/llog.h>
#include "../helper.h"
#include "../rpc.h"
#include "rpc-server.hpp"
#include "rpc-tcp-server.hpp"
#include "rpc-ws-server.hpp"

int rpc_main(const char *bind_addr, const char *token, const char *protocol)
{
    char addr_str[128];
    uint16_t port;
    if (parse_ip_port(bind_addr, addr_str, sizeof(addr_str), &port) != 0) {
        eprintf("Failed to parse rpc server: %s\n", bind_addr);
        return -1;
    }

    auto server = std::make_shared<RPCServer>();
    if (protocol == nullptr || strcmp(protocol, "tcp") == 0) {
        slp::rpc::RPCTCPServer tcpServer(server, addr_str, port, token);
        LLOG(LLOG_INFO, "rpc server(tcp) listening at %s", bind_addr);
        return tcpServer.run();
    } else if (strcmp(protocol, "ws") == 0) {
        slp::rpc::RPCWSServer wsServer(server, addr_str, port, token);
        LLOG(LLOG_INFO, "rpc server(ws) listening at %s", bind_addr);
        return wsServer.run();
    } else {
        eprintf("Unknown rpc protocol: %s\n", protocol);
        return -1;
    }
}
