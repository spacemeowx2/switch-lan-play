#pragma once

namespace slp {

template<typename T, typename Res, typename U, typename ...Args>
class CallbackHelper {
    public:
        template<Res (T::*F)(U, Args...)>
        static Res Callback(U u, Args... args) {
            T *o = static_cast<T *>(u->data);
            return (o->*F)(u, args...);
        }
};

}
