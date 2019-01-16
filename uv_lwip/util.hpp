#pragma once

namespace slp {

template<typename T>
struct FromThisType;

template<typename C, typename R, typename ...Args>
struct FromThisType<R(C::*)(Args...)> {
    typedef C type;
};

template<auto CallbackImpl>
static auto CallbackHelper();

template<
    auto CallbackImpl,
    typename R,
    typename ThisType = typename FromThisType<decltype(CallbackImpl)>::type,
    typename FirstType,
    typename ...Args,
    R (ThisType::*F)(FirstType u, Args...) = CallbackImpl
>
static R CallbackHelper(FirstType f, Args... args) {
    ThisType *o = static_cast<ThisType *>(f->data);
    return (o->*F)(f, args...);
}

}
