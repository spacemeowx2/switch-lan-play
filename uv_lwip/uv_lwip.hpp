#pragma once
#include "util.hpp"
#include "uv_lwip.h"
#include "assert.h"
#include <base/debug.h>
#include <base/llog.h>
#include <uvw.hpp>
#include <set>

namespace slp {
namespace lwip {

template<typename T>
class Leakable : public std::enable_shared_from_this<T> {
    private:
        std::shared_ptr<void> sPtr{nullptr};
    protected:
        void leak() noexcept {
            this->sPtr = this->shared_from_this();
        }
        void reset() noexcept {
            this->sPtr.reset();
        }
};

class IConnection;
struct UvlWriteReq {
    using Deleter = void(*)(char *);
    uvl_write_t req;
    std::unique_ptr<char[], Deleter> data;
    uv_buf_t buf;
    std::shared_ptr<IConnection> parent;
    UvlWriteReq(std::unique_ptr<char[], Deleter> dt, unsigned int len, std::shared_ptr<IConnection> parent) :
        data{std::move(dt)},
        buf{uv_buf_init(data.get(), len)},
        parent(parent) {
        this->req.data = this;
    }
};
class UvLwipBase;
class IConnection : public Leakable<IConnection> {
    protected:
        static void writeCallback(uvl_write_t *req, int status) {
            UvlWriteReq *r = static_cast<UvlWriteReq *>(req->data);
            if (status == 0) {
                r->parent->onWrite();
            } else {
                LLOG(LLOG_DEBUG, "IConnection::writeCallback %d", status);
            }
            delete r;
        }
        static void allocCallback(uvl_tcp_t *, std::size_t suggested, uv_buf_t *buf) {
            auto size = static_cast<unsigned int>(suggested);
            *buf = uv_buf_init(new char[size], size);
        }
        void closeCallback(uvl_tcp_t *) {
            this->onClosed();
            this->reset();
        }
        void readCallback(uvl_tcp_t *handle, ssize_t nread, const uv_buf_t *buf) {
            std::unique_ptr<char []> data = std::unique_ptr<char []>{buf->base};
            if (nread > 0) {
                this->onData(std::move(data), static_cast<unsigned int>(nread));
            } else {
                if (!this->closing) {
                    this->onClose();
                }
            }
        }
        uvl_tcp_t client;
        std::weak_ptr<UvLwipBase> lwip;
        bool closing;
    public:
        explicit IConnection(std::shared_ptr<UvLwipBase> lwip);
        virtual ~IConnection();
        bool init() {
            this->leak();
            return true;
        }
        sockaddr_in getLocalAddr() {
            return this->client.local_addr;
        }
        bool accept(uvl_t *uvl) {
            auto ret = uvl_accept(uvl, &this->client) == 0;
            if (ret) {
                this->onConnection();
            }
            return ret;
        }
        bool write(std::unique_ptr<char[]> data, unsigned int len) {
            auto buf = std::unique_ptr<char[], UvlWriteReq::Deleter>{
                data.release(), [](char *ptr) { delete[] ptr; }
            };
            auto req = new UvlWriteReq(std::move(buf), len, shared_from_this());
            return uvl_write(&req->req, &this->client, &req->buf, 1, IConnection::writeCallback) == 0;
        }
        bool write(const char *data, unsigned int len) {
            auto buf = std::unique_ptr<char[], UvlWriteReq::Deleter>{
                (char *)data, [](char *) {}
            };
            auto req = new UvlWriteReq(std::move(buf), len, shared_from_this());
            return uvl_write(&req->req, &this->client, &req->buf, 1, IConnection::writeCallback) == 0;
        }
        void read() {
            RT_ASSERT(uvl_read_start(
                &this->client,
                IConnection::allocCallback,
                MakeCallback(&IConnection::readCallback)
            ) == 0);
        }
        void stop() {
            RT_ASSERT(uvl_read_stop(&this->client) == 0);
        }
        void close(bool skipRemove = false);
        virtual void onConnection() = 0;
        virtual void onData(std::unique_ptr<char []>, unsigned int len) = 0;
        virtual void onWrite() = 0;
        virtual void onClose() = 0;
        virtual void onClosed() = 0;
};

class UvLwipBase : public std::enable_shared_from_this<UvLwipBase> {
    private:
        friend class IConnection;
        void onClose(uvl_tcp_t *handle) {
        }
        void onConnect(uvl_t *handle, int status) {
            assert(status == 0);

            auto conn = newConnection(shared_from_this());
            if (!conn) {
                LLOG(LLOG_DEBUG, "newConnection return nullptr");
                uvl_tcp_t tcp;
                tcp.data = this;
                if (uvl_accept(handle, &tcp) == 0) {
                    uvl_tcp_close(&tcp, MakeCallback(&UvLwipBase::onClose));
                }
            }
            if (!conn->init()) {
                return;
            }
            if (!conn->accept(&this->uvl)) {
                return;
            }
            this->connSet.insert(conn);
        }
        void removeConnection(std::shared_ptr<IConnection> e) {
            this->connSet.erase(e);
        }
        int onUvlOutput(uvl_t *handle, const uv_buf_t bufs[], unsigned int nbufs) {
            uint8_t buffer[8192];
            uint8_t *buf = buffer;
            uint32_t len = 0;

            for (unsigned int i = 0; i < nbufs; i++) {
                RT_ASSERT(len + bufs[i].len < sizeof(buffer))
                memcpy(buf, bufs[i].base, bufs[i].len);
                buf += bufs[i].len;
                len += bufs[i].len;
            }
            return this->uvlOutput(buffer, len);
        }
        uvl_t uvl;
        std::set<std::shared_ptr<IConnection>> connSet;
    protected:
        uv_loop_t *loop;
        virtual int uvlOutput(void *buffer, uint32_t len) = 0;
        virtual std::shared_ptr<IConnection> newConnection(std::shared_ptr<UvLwipBase> self) = 0;
    public:
        UvLwipBase(uv_loop_t *loop) : loop(loop) {
            RT_ASSERT(uvl_init(this->loop, &this->uvl) == 0);
            RT_ASSERT(uvl_bind(&this->uvl, MakeCallback(&UvLwipBase::onUvlOutput)) == 0);
            RT_ASSERT(uvl_listen(&this->uvl, MakeCallback(&UvLwipBase::onConnect)) == 0);

            this->uvl.data = this;
        }
        virtual ~UvLwipBase() {
        };
        bool input(const uv_buf_t buf) {
            return uvl_input(&this->uvl, buf);
        }
        void release() {
            uvl_close(&this->uvl, NULL);
            for (auto &i : connSet) {
                i->close(true);
            }
        }
};

IConnection::IConnection(std::shared_ptr<UvLwipBase> lwip) :lwip(lwip), closing(false) {
    LLOG(LLOG_DEBUG, "IConnection::IConnection");
    this->client.data = this;
    RT_ASSERT(uvl_tcp_init(lwip->loop, &this->client) == 0);
}

IConnection::~IConnection() {
    LLOG(LLOG_DEBUG, "IConnection::~IConnection");
}

void IConnection::close(bool skipRemove) {
    if (!skipRemove) {
        if (auto p = lwip.lock()) {
            p->removeConnection(shared_from_this());
        }
    }
    if (!this->closing) {
        this->closing = true;
        RT_ASSERT(uvl_tcp_close(&this->client, MakeCallback(&IConnection::closeCallback)) == 0);
    }
}

}
}
