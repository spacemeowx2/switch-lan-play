#pragma once
#include <string>
#include <functional>

namespace slp {
namespace rpc {

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

}
}
