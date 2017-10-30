//
//  thread_wrap.cpp
//  libuv_test
//
//  Created by ke liu on 11/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#include "uv_wrapper.hpp"
#include <map>
#include <sstream>
#include <list>
#include <vector>

namespace plan9 {

    static uv_thread_t *thread = nullptr;
    static uv_loop_t *loop = nullptr;
    static std::map<int, uv_timer_t *> timer_map;
    static const int TIMER_EVER_LOOP = -1234;
    static std::map<int, uv_work_t *> concurrent_map;
    static std::list<uv_work_t *> reuse_concurrent_array;
    static std::list<uv_idle_t *> reuse_idle_array;
    static std::list<uv_timer_t *> reuse_timer_array;

    template<typename T>
    class function_wrap {
    public:
        function_wrap(T func) : function(func) {
        }

        function_wrap(T func, int times) : function(func) {
            if (times > 0 || times == TIMER_EVER_LOOP) {
                max_times = times;
                current_times = times;
            }
        }

        ~function_wrap() {
            function = nullptr;
        }

        bool minus() {
            if (current_times == 0) {
                return true;
            } else if (current_times == TIMER_EVER_LOOP) {
                return false;
            }
            current_times--;
            return false;
        }

        int id;
        bool is_canceled;
        T function;

    private:
        int max_times;
        int current_times;
    };

    static std::map<int, function_wrap<std::function<void(void)>> *> serial_map;

    static uv_mutex_t *get_timer_mutex() {
        static uv_mutex_t *timer_map_mutex = nullptr;
        if (timer_map_mutex == nullptr) {
            timer_map_mutex = new uv_mutex_t;
            uv_mutex_init(timer_map_mutex);
        }
        return timer_map_mutex;
    }

    static uv_mutex_t *get_serial_mutex() {
        static uv_mutex_t *mutex = nullptr;
        if (mutex == nullptr) {
            mutex = new uv_mutex_t;
            uv_mutex_init(mutex);
        }
        return mutex;
    }

    static uv_mutex_t *get_concurrent_mutex() {
        static uv_mutex_t *mutex = nullptr;
        if (mutex == nullptr) {
            mutex = new uv_mutex_t;
            uv_mutex_init(mutex);
        }
        return mutex;
    }

    static void idle_callback(uv_idle_t *handle) {
        if (handle->data != nullptr) {
            auto func = (function_wrap<std::function<void(void)>> *) (handle->data);
            if (func->function != nullptr) {
                func->function();
            }
            delete func;
            handle->data = nullptr;
            reuse_idle_array.push_back(handle);
        }
        uv_close((uv_handle_t *) handle, nullptr);
    }

    static void idle_loop_callback(uv_idle_t *handle) {
    }

    static void thread_cb(void *arg) {
        loop = new uv_loop_t;
        uv_loop_init(loop);
        if (arg != nullptr) {
            auto func = (function_wrap<std::function<void(void)>> *) arg;
            if (func->function != nullptr) {
                func->function();
            }
            delete (func);
        }
        uv_idle_t *idle = new uv_idle_t;
        uv_idle_init(loop, idle);
        uv_idle_start(idle, idle_loop_callback);
        uv_run(loop, UV_RUN_DEFAULT);
        uv_loop_close(loop);
        delete thread;
        thread = nullptr;
        delete loop;
        loop = nullptr;
    }

    static void async_callback(uv_async_t *async) {
        if (async->data != nullptr) {
            auto func = (function_wrap<std::function<void(void)>> *) async->data;
            if (!func->is_canceled) {
                if (func->function != nullptr) {
                    func->function();
                }
            }
            uv_mutex_trylock(get_serial_mutex());
            serial_map.erase(func->id);
            uv_mutex_unlock(get_serial_mutex());
            delete func;
        }
        uv_close((uv_handle_t *) async, nullptr);
    }

    static void init_loop(std::function<void(void)> callback) {
        if (thread == nullptr && loop == nullptr) {
            thread = new uv_thread_t;
            uv_thread_create(thread, thread_cb, new function_wrap<std::function<void(void)>>(callback));
        } else {
            if (callback) {
                callback();
            }
        }
    }

    static void timer_callback(uv_timer_t *handle) {
        if (handle->data != nullptr) {
            auto func = (function_wrap<std::function<void(void)>> *) handle->data;
            if (func->minus()) {
                uv_timer_stop(handle);
                uv_mutex_trylock(get_timer_mutex());
                timer_map.erase(func->id);
                reuse_timer_array.push_back(handle);
                uv_mutex_unlock(get_timer_mutex());
                delete func;
            } else {
                if (func->function != nullptr) {
                    func->function();
                }
            }
        }
    }

    static void queue_callback(uv_work_t *work) {
        if (work->data != nullptr) {
            auto func = (function_wrap<std::function<void(void)>> *) (work->data);
            if (func->function != nullptr) {
                func->function();
            }
            work->data = nullptr;
            uv_mutex_trylock(get_concurrent_mutex());
            concurrent_map.erase(func->id);
            reuse_concurrent_array.push_back(work);
            uv_mutex_unlock(get_concurrent_mutex());
            delete (func);
        }
    }

    void uv_wrapper::init(std::function<void(void)> callback) {
        init_loop(callback);
    }

    int uv_wrapper::post_serial_queue(std::function<void()> callback) {
        static int count = 0;
        count++;
        uv_async_t *async = new uv_async_t;
        auto f = new function_wrap<std::function<void(void)>>(callback);
        f->id = count;
        f->is_canceled = false;
        async->data = (void *) f;
        uv_async_init(loop, async, async_callback);
        uv_mutex_trylock(get_serial_mutex());
        serial_map[count] = f;
        uv_mutex_unlock(get_serial_mutex());
        uv_async_send(async);
        return count;
    }

    void uv_wrapper::cancel_serial(int id) {
        uv_mutex_trylock(get_serial_mutex());
        if (serial_map.find(id) != serial_map.end()) {
            auto f = serial_map[id];
            f->is_canceled = true;
        }
        uv_mutex_unlock(get_serial_mutex());
    }

    void uv_wrapper::set_concurrent_pool_size(int size) {
        std::stringstream ss;
        ss << size;
        std::string s = ss.str();
        uv_os_setenv("UV_THREADPOOL_SIZE", s.c_str());
    }

    int uv_wrapper::post_concurrent_queue(std::function<void()> callback) {
        static int count = 0;
        count++;

        uv_mutex_trylock(get_concurrent_mutex());

        uv_work_t *work = nullptr;
        if (reuse_concurrent_array.size() > 0) {
            work = *(reuse_concurrent_array.begin());
            reuse_concurrent_array.erase(reuse_concurrent_array.begin());
        } else {
            work = new uv_work_t;
        }

        auto f = new function_wrap<std::function<void(void)>>(callback);
        f->id = count;
        work->data = (void *) (f);
        concurrent_map[count] = work;

        uv_mutex_unlock(get_concurrent_mutex());
        uv_queue_work(loop, work, queue_callback, nullptr);

        return count;
    }

    void uv_wrapper::cancel_concurrent(int id) {
        uv_mutex_trylock(get_concurrent_mutex());
        if (concurrent_map.find(id) != concurrent_map.end()) {
            auto f = concurrent_map[id];
            uv_cancel((uv_req_t *) f);
        }
        uv_mutex_unlock(get_concurrent_mutex());
    }

    void uv_wrapper::post_idle(std::function<void()> callback) {
        uv_idle_t *idle_handle = nullptr;
        if (reuse_idle_array.size() > 0) {
            idle_handle = *(reuse_idle_array.begin());
            reuse_idle_array.erase(reuse_idle_array.begin());
        } else {
            idle_handle = new uv_idle_t;
        }
        idle_handle->data = new function_wrap<std::function<void(void)>>(callback);
        uv_idle_init(loop, idle_handle);
        uv_idle_start(idle_handle, idle_callback);
    }

    int uv_wrapper::post_timer(std::function<void()> callback, long time, long repeat) {
        return post_timer(callback, time, repeat, TIMER_EVER_LOOP);
    }

    int uv_wrapper::post_timer(std::function<void()> callback, long time, long repeat, int times) {
        static int timer_id = 0;
        timer_id++;

        uv_mutex_trylock(get_timer_mutex());
        uv_timer_t *timer = nullptr;
        if (reuse_timer_array.size() > 0) {
            timer = *(reuse_timer_array.begin());
            reuse_timer_array.erase(reuse_timer_array.begin());
        } else {
            timer = new uv_timer_t;
        }
        timer_map[timer_id] = timer;
        auto func = new function_wrap<std::function<void(void)>>(callback, times);
        func->id = timer_id;
        timer->data = (void *) (func);
        uv_mutex_unlock(get_timer_mutex());
        uv_timer_init(loop, timer);
        uv_timer_start(timer, timer_callback, time, repeat);

        return timer_id;
    }

    void uv_wrapper::cancel_timer(int timer_id) {
        uv_mutex_trylock(get_timer_mutex());
        if (timer_map.find(timer_id) != timer_map.end()) {
            auto t = timer_map[timer_id];
            uv_timer_stop(t);
            timer_map.erase(timer_id);
            reuse_timer_array.push_back(t);
        }
        uv_mutex_unlock(get_timer_mutex());
    }

    static void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
        if (status >= 0) {
            std::shared_ptr<std::vector<std::string>> ret(new std::vector<std::string>);// = res->ai_addrlen
            struct addrinfo *next = res;
            while (next != nullptr) {
                if (next->ai_family == PF_INET) {
                    char addr[17] = {'\0'};
                    uv_ip4_name((struct sockaddr_in *) next->ai_addr, addr, 16);
                    std::string ip = std::string(addr);
                    ret->push_back(ip);
                } else if (next->ai_family == PF_INET6) {
                    char addr[17] = {'\0'};
                    uv_ip6_name((struct sockaddr_in6 *) next->ai_addr, addr, 16);
                    std::string ip = std::string(addr);
                    ret->push_back(ip);
                }
                next = next->ai_next;
            }
            if (resolver != nullptr && resolver->data != nullptr) {
                auto func = (function_wrap<std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>> *) resolver->data;
                std::shared_ptr<common_callback> cb(new common_callback);
                func->function(cb, ret);
            }
            delete (resolver);
            delete (res);
        } else {
            std::string resaon = std::string(uv_err_name(status));
            if (resolver != nullptr && resolver->data != nullptr) {
                auto func = (function_wrap<std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>> *) resolver->data;
                std::shared_ptr<common_callback> cb(new common_callback(false, -1, resaon));
                func->function(cb, nullptr);
            }
            delete (resolver);
            delete (res);
        }
    }

    void uv_wrapper::resolve(std::string url, int port, std::function<void(std::shared_ptr<common_callback>,
            std::shared_ptr<std::vector<std::string>>)> callback) {
        if (loop == nullptr) {
            if (callback) {
                std::shared_ptr<common_callback> cb(new common_callback(false, -1, "loop must be init"));
                callback(cb, nullptr);
            }
            return;
        }
        uv_getaddrinfo_t *resolver = new uv_getaddrinfo_t;
        auto func = new function_wrap<std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>>(callback);
        resolver->data = func;
        struct addrinfo *hints = new addrinfo;
        hints->ai_family = PF_INET;
        hints->ai_socktype = SOCK_STREAM;
        hints->ai_protocol = IPPROTO_TCP;
        hints->ai_flags = 0;
        std::stringstream ss;
        ss << port;
        std::string p = ss.str();
        int ret = uv_getaddrinfo(loop, resolver, on_resolved, url.c_str(), p.c_str(), hints);
        if (ret) {
            if (callback) {
                std::shared_ptr<common_callback> cb(new common_callback(false, -1, "call getadrinfo fail"));
                callback(cb, nullptr);
            }
        }
    }


    static std::map<int, uv_tcp_t*> tcp_array;
    static std::map<int, std::function<void(std::shared_ptr<common_callback>, int tcp_id)>> tcp_close_callback_map;
    static std::map<int, std::function<void(int, char*, int len)>> tcp_read_callback_map;
    static std::map<int, char*> tcp_read_buf_map;

    static void read_callback(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
        if (nread > 0) {
            if (handle != nullptr && handle->data != nullptr) {
                auto func = (function_wrap<std::function<void(std::shared_ptr<common_callback>, int)>> *) (handle->data);
                if (tcp_read_callback_map.find(func->id) != tcp_read_callback_map.end()) {
                    auto callback = tcp_read_callback_map[func->id];
                    callback(func->id, buf->base, nread);
                }
            }
        } else {
            if (handle != nullptr && handle->data != nullptr) {
                auto func = (function_wrap<std::function<void(std::shared_ptr<common_callback>, int)>> *) (handle->data);
                uv_wrapper::close(func->id);
            }
        }
    }

    static void alloc_callback(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
        *buf = uv_buf_init((char*)malloc(suggested_size), suggested_size);
    }


    static void connect_event_callback(uv_connect_t* handle, int status) {
        if (handle != nullptr && handle->data != nullptr) {
            auto func = (function_wrap<std::function<void(std::shared_ptr<common_callback>, int)>> *) (handle->data);
            if (handle->type == UV_CONNECT) {
                if (status >= 0) {
                    auto tcp_handle = tcp_array[func->id];
                    uv_read_start((uv_stream_t*)tcp_handle, alloc_callback, read_callback);
                    if (func->function != nullptr) {
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        func->function(ccb, func->id);
                    }
                } else {
                    std::string reason = std::string(uv_err_name(status));
                    if (func->function != nullptr) {
                        std::shared_ptr<common_callback> ccb(new common_callback(false, status, reason));
                        func->function(ccb, func->id);
                    }
                }
            } else if (handle->type == UV_DISCONNECT) {
                if (tcp_close_callback_map.find(func->id) != tcp_close_callback_map.end()) {
                    auto close_callback = tcp_close_callback_map[func->id];
                    if (close_callback != nullptr) {
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        close_callback(ccb, func->id);
                    }
                }
            }
        }
    }

    void uv_wrapper::connect(std::string ip, int port, std::function<void(std::shared_ptr<common_callback>, int tcp_id)> connect_callback,
            std::function<void(int, char*, int len)> read_callback,
            std::function<void(std::shared_ptr<common_callback>, int tcp_id)> close_callback) {
        if (loop == nullptr) {
            if (connect_callback) {
                std::shared_ptr<common_callback> cb(new common_callback(false, -1, "loop must be init"));
                connect_callback(cb, -1);
            }
            return;
        }

        static int count = 1;

        uv_connect_t* req = new uv_connect_t;
        auto func = new function_wrap<std::function<void(std::shared_ptr<common_callback>, int)>>(connect_callback);
        func->id = count;
        req->data = func;

        if (close_callback != nullptr) {
            tcp_close_callback_map[count] = close_callback;
        }

        if (read_callback != nullptr) {
            tcp_read_callback_map[count] = read_callback;
        }

        uv_tcp_t* tcp = new uv_tcp_t;
        tcp->data = func;
        tcp_array[count] = tcp;
        struct sockaddr_in* addr = new sockaddr_in;
        uv_ip4_addr(ip.c_str(), port, addr);

        uv_tcp_init(loop, tcp);
        uv_tcp_nodelay(tcp, 1);
        uv_tcp_connect(req, tcp, (struct sockaddr*)addr, connect_event_callback);

        count ++;
    }

    void uv_wrapper::reconnect(int tcp_id) {
        //TODO 待实现

    }

    void uv_wrapper::close(int tcp_id) {
        if (tcp_array.find(tcp_id) != tcp_array.end()) {
            auto tcp = tcp_array[tcp_id];
            uv_close((uv_handle_t*)tcp, nullptr);
            tcp_array.erase(tcp_id);
            if (tcp_close_callback_map.find(tcp_id) != tcp_close_callback_map.end()) {
                auto callback = tcp_close_callback_map[tcp_id];
                std::shared_ptr<common_callback> ccb(new common_callback);
                callback(ccb, tcp_id);
            }
        }
    }

    static void write_callback(uv_write_t* req, int status) {
        if (req != nullptr && req->data != nullptr) {
            auto func = (function_wrap<std::function<void(std::shared_ptr<common_callback>)>>*)(req->data);
            if (func->function != nullptr) {
                std::shared_ptr<common_callback> ccb;
                if (status >= 0) {
                    ccb.reset(new common_callback);
                } else {
                    ccb.reset(new common_callback(false, status, uv_err_name(status)));
                }
                func->function(ccb);
            }
        }
    }

    void uv_wrapper::write(int tcp_id, char *data, int len, std::function<void(std::shared_ptr<common_callback>)> callback) {
        if (tcp_array.find(tcp_id) != tcp_array.end()) {
            auto tcp = tcp_array[tcp_id];
            uv_write_t* write = new uv_write_t;
            auto func = new function_wrap<std::function<void(std::shared_ptr<common_callback>)>>(callback);
            func->id = tcp_id;
            write->data = func;
            uv_buf_t buf = uv_buf_init(data, len);
            uv_write(write, (uv_stream_t*)tcp, &buf, 1, write_callback);
        }
    }

    bool uv_wrapper::tcp_alive(int tcp_id) {
        if (tcp_array.find(tcp_id) != tcp_array.end()) {
            return true;
        }
        return false;
    }
}





