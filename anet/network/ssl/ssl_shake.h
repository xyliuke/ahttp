//
// Created by ke liu on 16/12/2017.
// Copyright (c) 2017 ke liu. All rights reserved.
//

#ifndef ANET_SSL_SHAKE_H
#define ANET_SSL_SHAKE_H

#include <memory>
#include <openssl/ossl_typ.h>
#include <functional>
#include "uv_wrapper.hpp"

namespace plan9
{
    class ssl_shake : public ssl_interface {
    public:
        ssl_shake();
        void do_shake(int fd, std::function<void(std::shared_ptr<ssl_shake>)> callback);
        void read(char* data, long len, std::function<void(char* data, long len)> callback);
        void write(char* data, long len, std::function<void(char* data, long len)> callback);

        void on_connect(int tcp_id, std::function<void(std::shared_ptr<common_callback>)> callback);
        void on_read(int tcp_id, char* data, long len, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<char>, long)> callback);
    private:
        class ssl_shake_impl;
        std::shared_ptr<ssl_shake_impl> impl;
    };
}


#endif //ANET_SSL_SHAKE_H
