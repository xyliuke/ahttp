//
//  thread_wrap.hpp
//  libuv_test
//
//  Created by ke liu on 11/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#ifndef thread_wrap_hpp
#define thread_wrap_hpp

#include <string>
#include <functional>
#include "../libuv/include/uv.h"
#include "../common/common_callback.hpp"

namespace plan9 {

    struct ssl_interface {
        virtual void on_connect(int tcp_id, std::function<void(std::shared_ptr<common_callback>)> callback) = 0;
        virtual void on_read(int tcp_id, char* data, long len, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<char>, long)> callback) = 0;
        virtual void write(char* data, long len, std::function<void(std::shared_ptr<common_callback>, char* data, long len)> callback)= 0;
    };

    class uv_wrapper {
    public:
        static void init(std::function<void(void)> callback);

        static void set_ssl_impl(std::function<std::shared_ptr<ssl_interface>()> callback);

        static void set_concurrent_pool_size(int size);

        static int post_serial_queue(std::function<void(void)> callback);

        static void cancel_serial(int id);

        static int post_concurrent_queue(std::function<void(void)> callback);

        static void cancel_concurrent(int id);

        static void post_idle(std::function<void(void)> callback);

        static int post_timer(std::function<void(void)> callback, long time, long repeat);

        static int post_timer(std::function<void(void)> callback, long time, long repeat, int repeat_times);

        static void cancel_timer(int timer_id);

        static void resolve(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)> callback);

        //TCP 相关
        static void connect(std::string ip, int port, std::function<void(std::shared_ptr<common_callback>, int tcp_id)> connect_callback,
                            std::function<void(int tcp_id, std::shared_ptr<char> data, int len)> read_callback,
                            std::function<void(std::shared_ptr<common_callback>, int tcp_id)> close_callback);

        static void connect(std::string ip, int port, bool ssl_enable, std::function<void(std::shared_ptr<common_callback>, int)> connect_callback,
                std::function<void(std::shared_ptr<common_callback>, int tcp_id)> ssl_connect_callback,
                std::function<void(int tcp_id, std::shared_ptr<char> data, int len)> read_callback,
                std::function<void(std::shared_ptr<common_callback>, int tcp_id)> close_callback);

        static void connect_ssl(std::string ip, int port,
                std::function<void(std::shared_ptr<common_callback>, int)> connect_callback,
                std::function<void(std::shared_ptr<common_callback>, int tcp_id)> ssl_connect_callback,
                std::function<void(int tcp_id, std::shared_ptr<char> data, int len)> read_callback,
                std::function<void(std::shared_ptr<common_callback>, int tcp_id)> close_callback);

        static void reconnect(int tcp_id);

        static void close(int tcp_id);

        static void write(int tcp_id, char* data, int len, std::function<void(std::shared_ptr<common_callback>)> callback);
        static void write_uv(int tcp_id, char* data, int len, std::function<void(std::shared_ptr<common_callback>)> callback);

        static bool tcp_alive(int tcp_id);

        static int get_fd(int tcp_id);
    };

}

#endif /* thread_wrap_hpp */
