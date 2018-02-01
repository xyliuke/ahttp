//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include <assert.h>
#include <set>
#include <iostream>
#include "ahttp1.h"
#include "state_machine.h"
#include "uv_wrapper.hpp"

namespace plan9
{
    class ahttp1::ahttp_impl : public state_machine {
    public:
        ahttp_impl() {

            STATE_MACHINE_ADD_ROW(this, init_state, FETCH, begin_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "init_state, FETCH, begin_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, init_state, PUSH_WAITING_QUEUE, wait_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "init_state, PUSH_WAITING_QUEUE, wait_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, wait_state, FETCH, begin_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "wait_state, FETCH, begin_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, begin_state, SEND, send_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "begin_state, SEND, send_ing_state" << std::endl;
                //TODO 在事件中改变状态，有问题
                send();
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, begin_state, DNS_RESOLVE, dns_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "begin_state, DNS_RESOLVE, dns_ing_state" << std::endl;
                get_resolver()(request->get_domain(), request->get_port(), [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<std::vector<std::string>> ips){
                    if (ccb->success) {
                        this->push_ips(ips);
                        process_event(DNS_RESOLVE_OK);
                    } else {
                        process_event(DNS_RESOLVE_ERROR);
                    }
                });
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, dns_ing_state, DNS_RESOLVE_OK, dns_end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "dns_ing_state, DNS_RESOLVE_OK, dns_end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, begin_state, OPEN, connecting_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "begin_state, OPEN, connecting_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, dns_ing_state, DNS_RESOLVE_ERROR, end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "dns_ing_state, DNS_RESOLVE_ERROR, end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, dns_end_state, OPEN, connecting_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "dns_end_state, OPEN, connecting_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connecting_state, OPEN_SUCCESS, connected_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "connecting_state, OPEN_SUCCESS, connected_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connecting_state, CLOSE, disconnect_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "connecting_state, CLOSE, disconnect_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connected_state, SSL_CONNECT, ssl_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "connected_state, SSL_CONNECT, ssl_ing_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, ssl_ing_state, SSL_CONNECT_SUCCESS, ssl_end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "ssl_ing_state, SSL_CONNECT_SUCCESS, ssl_end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, ssl_ing_state, CLOSE, disconnect_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "ssl_ing_state, CLOSE, disconnect_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connected_state, SEND, send_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "connected_state, SEND, send_ing_state" << std::endl;
                send();
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, disconnect_state, GIVE_UP, end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "disconnect_state, GIVE_UP, end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, disconnect_state, SWITCH_IP, connecting_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "disconnect_state, SWITCH_IP, connecting_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, disconnect_state, RETRY, dns_end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "disconnect_state, RETRY, dns_end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, ssl_end_state, SEND, send_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "ssl_end_state, SEND, send_ing_state" << std::endl;
                send();
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, send_ing_state, SEND_FINISH, send_end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "send_ing_state, SEND_FINISH, send_end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, send_end_state, RECV, read_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "send_end_state, RECV, read_ing_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_ing_state, RECV_FINISH, read_end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "read_ing_state, RECV_FINISH, read_end_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, REDIRECT_OUTER, begin_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "read_end_state, REDIRECT_OUTER, begin_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, REDIRECT_INNER, send_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "read_end_state, REDIRECT_INNER, send_ing_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, FORWARD, send_ing_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "read_end_state, FORWARD, send_ing_state" << std::endl;
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, FINISH, end_state, [=](state_machine* fsm) -> bool {
                std::cout << __LINE__ << " : " << "read_end_state, FINISH, end_state" << std::endl;
                return true;
            });

            set_init_state<init_state>();
            start();
        }

        void exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            this->request = request;
            this->response = std::make_shared<ahttp_response>();
            this->callback = callback;
            mgr->push(this);
        }

    private:

        typedef enum http_event_ {
            FETCH,//开始执行请求数据操作
            PUSH_WAITING_QUEUE,//压入请求队列
            DNS_RESOLVE,//dns解析
            DNS_RESOLVE_OK,//dns解析成功
            DNS_RESOLVE_ERROR,//dns解析失败
            OPEN,//连接TCP
            OPEN_SUCCESS,//连接成功
            CLOSE,//关闭TCP
            SSL_CONNECT,//SSL握手开始
            SSL_CONNECT_SUCCESS,//SSL握手成功
            SEND,//发送数据
            SEND_FINISH,//发送数据完成
            RECV,//接收数据
            RECV_FINISH,//接收数据完成
            GIVE_UP,//没有连接上服务器，直接放弃连接
            RETRY,//重试连接服务器
            REDIRECT_INNER,//重定向内部
            REDIRECT_OUTER,//重定向外部
            FORWARD,//
            FINISH,//请求结束
            SWITCH_IP//换IP重新连接
        } http_event;

        // HTTP的初始状态
        struct init_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };

        //开始执行请求
        struct begin_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* impl = (ahttp_impl*)fsm;
                if (event == REDIRECT_OUTER) {
                    //重定向
//                    impl->process_event(SEND);
                } else {
                    if (impl->is_reused_tcp()) {
                        impl->process_event(SEND);
                    } else {
                        if (impl->request->is_ip_format_host()) {
//                    ip直连
                            impl->process_event(OPEN);
                        } else {
                            impl->process_event(DNS_RESOLVE);
                        }
                    }
                }

            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //在请求队列中等待
        struct wait_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //dns解析中
        struct dns_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //dns解析完成
        struct dns_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* impl = (ahttp_impl*)fsm;
                if (event == SWITCH_IP) {
                    //换下一个IP
                    impl->change_ip();
                }
                impl->process_event(OPEN);
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //连接中
        struct connecting_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* http = (ahttp_impl*)fsm;
                http->mgr->connect(http);
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //连接完成
        struct connected_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* http = (ahttp_impl*)fsm;
                if (http->request->is_use_ssl()) {
                    //HTTPS
                    http->process_event(SSL_CONNECT);
                } else {
                    //HTTP
                    http->process_event(SEND);
                }
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //断开连接
        struct disconnect_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //ssl ing
        struct ssl_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //ssl end
        struct ssl_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //发送数据中
        struct send_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //发送数据结束
        struct send_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* http = (ahttp_impl*)fsm;
                http->process_event(RECV);
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //读取数据中
        struct read_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //读取数据结束
        struct read_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* http = (ahttp_impl*)fsm;
                //TODO 判断Redirect/Forward情况
                http->process_event(FINISH);
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };
        //请求结束状态
        struct end_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
                ahttp_impl* http = (ahttp_impl*)fsm;
                http->remove_http();
                http->send_callback();
            }

            void on_exit(int event, state_machine *fsm) override {
                std::cout << typeid(this).name() << "  " << __FUNCTION__ << std::endl;
            }
        };

        void no_transition(std::shared_ptr<state> begin, int event) override {
            std::cout << "no transition event " <<  event << std::endl;
            assert(true);
        }

        std::shared_ptr<ahttp_request> request;
        std::shared_ptr<ahttp_response> response;
        std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback;

        class ahttp_mgr {
        public:
            ahttp_mgr() : url_ips(std::make_shared<std::map<std::string, std::shared_ptr<std::vector<std::string>>>>()),
                url_tcp(std::make_shared<std::map<std::string, int>>()),
                tcp_http(std::make_shared<std::map<int, std::shared_ptr<std::vector<ahttp_impl*>>>>()){
            }
            /**
             * 添加请求到队列
             * @param impl
             */
            void push(ahttp_impl* impl) {
                if (is_exceed_max_connection_num()) {
                    //超过最大连接数
                    impl->process_event(PUSH_WAITING_QUEUE);
                } else {
                    assign_reused_tcp(impl);
                    impl->process_event(FETCH);
                }
            }

            void push_ips(ahttp_impl* http, std::shared_ptr<std::vector<std::string>> ips) {
                if (http) {
                    (*url_ips)[http->request->get_domain()] = ips;
                }
            }

            std::string get_ip(ahttp_impl* http) {
                if (http) {
                    if (url_ips->find(http->request->get_domain()) != url_ips->end()) {
                        //TODO 设置IP的选择性
                        return (*(*url_ips)[http->request->get_domain()])[0];
                    }
                }
                return "";
            }

            void switch_ip(ahttp_impl* http) {}

            bool is_reused_tcp(ahttp_impl *http) {
                if (http && url_tcp->find(http->request->get_domain()) != url_tcp->end()) {
                    int tcp_id = (*url_tcp)[http->request->get_domain()];
                    if (uv_wrapper::tcp_alive(tcp_id)) {
                        return true;
                    } else {
                        close(tcp_id);
                    }
                }
                return false;
            }

            void connect(ahttp_impl* impl) {
                int tcp_id = uv_wrapper::connect(get_ip(impl), impl->request->get_port(), impl->request->is_use_ssl(), impl->request->get_domain(),
                        [=](std::shared_ptr<common_callback> ccb, int tcp_id) {
                            if (ccb->success) {
                                impl->process_event(OPEN_SUCCESS);
                            } else {
                                impl->process_event(CLOSE);
                            }
                        }, [=](std::shared_ptr<common_callback> ccb, int tcp_id) {

                        }, [=](int tcp_id, std::shared_ptr<char> data, int len) {
                            ahttp_impl* http = get_http(tcp_id);
                            if (http) {
                                bool finish = http->response->append_response_data(data, len);
                                if (finish) {
                                    http->process_event(RECV_FINISH);
                                }
                            }
                        }, [=](std::shared_ptr<common_callback> ccb, int tcp_id) {
                            close(tcp_id);
                        });

                push(tcp_id, impl);
            }

            void send(ahttp_impl* impl) {
                //找到对应的TCP_ID
                const int tcp_id = get_tcp_id(impl);
                impl->request->get_http_data([=](std::shared_ptr<char> data, int len, int sent, int total){
                    uv_wrapper::write(tcp_id, data, len, [=](std::shared_ptr<common_callback> write_callback){
                        if ((sent + len) >= total) {
                            //发送完成
                            impl->process_event(SEND_FINISH);
                        }
                    });
                });
            }

            void remove_top_http(int tcp_id) {
                if (tcp_http->find(tcp_id) != tcp_http->end()) {
                    auto list = (*tcp_http)[tcp_id];
                    if (list->size() > 0) {
                        list->erase(list->begin());
                    }
                }
            }

            void remove_http(ahttp_impl* http) {
                auto it = tcp_http->begin();
                while (it != tcp_http->end()) {
                    auto list = it->second;
                    auto itt = list->begin();
                    while (itt != list->end()){
                        if ((*itt) == http) {
                            list->erase(itt);
                            return;
                        }
                        itt ++;
                    }
                    it ++;
                }
            }

        private:
            bool is_exceed_max_connection_num() {
                return false;
            }

            int get_tcp_id(ahttp_impl* impl) {
                auto it = tcp_http->begin();
                while (it != tcp_http->end()) {
                    auto list = it->second;
                    auto itt = list->begin();
                    while (itt != list->end()){
                        if ((*itt) == impl) {
                            return it->first;
                        }
                        itt ++;
                    }
                    it ++;
                }
                return -1;
            }

            ahttp_impl* get_http(int tcp_id) {
                if (tcp_http->find(tcp_id) != tcp_http->end()) {
                    auto list = (*tcp_http)[tcp_id];
                    if (list->size() > 0) {
                        return (*list)[0];
                    }
                }
                return nullptr;
            }
            void push(int tcp_id, ahttp_impl* http) {
                (*url_tcp)[http->request->get_domain()] = tcp_id;
                std::shared_ptr<std::vector<ahttp_impl*>> list;
                if (tcp_http->find(tcp_id) != tcp_http->end()) {
                    list = (*tcp_http)[tcp_id];
                } else {
                    list = std::make_shared<std::vector<ahttp_impl*>>();
                    (*tcp_http)[tcp_id] = list;
                }
                list->push_back(http);
            }

            void close(int tcp_id) {
                tcp_http->erase(tcp_id);
                auto it = url_tcp->begin();
                while (it != url_tcp->end()) {
                    if (it->second == tcp_id) {
                        url_tcp->erase(it);
                        break;
                    }
                    it ++;
                }
            }

            void assign_reused_tcp(ahttp_impl* http) {
                if (is_reused_tcp(http)) {
                    int tcp_id = (*url_tcp)[http->request->get_domain()];
                    if (tcp_id > 0) {
                        push(tcp_id, http);
                    }
                }
            }

            std::shared_ptr<std::map<std::string, std::shared_ptr<std::vector<std::string>>>> url_ips;
            std::shared_ptr<std::map<int, std::shared_ptr<std::vector<ahttp_impl*>>>> tcp_http;
            std::shared_ptr<std::map<std::string, int>> url_tcp;
        };

        static std::shared_ptr<ahttp_mgr> mgr;

        std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> get_resolver() {
            if (dns_resolve_callback) {
                return dns_resolve_callback;
            }
            static std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> default_dns_resolve = nullptr;
            if (!default_dns_resolve) {
                default_dns_resolve = std::bind(&uv_wrapper::resolve, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
            }
            return default_dns_resolve;
        }
        std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> dns_resolve_callback;

        void push_ips(std::shared_ptr<std::vector<std::string>> ips) {
            mgr->push_ips(this, ips);
        }

        void change_ip() {
            mgr->switch_ip(this);
        }

        void send() {
            mgr->send(this);
        }

        void send_callback() {
            if (callback) {
                callback(common_callback::get(), request, response);
            }
        }

        bool is_reused_tcp() {
            return mgr->is_reused_tcp(this);
        }

        void remove_http() {
            mgr->remove_http(this);
        }

    };

    std::shared_ptr<ahttp1::ahttp_impl::ahttp_mgr> ahttp1::ahttp_impl::mgr = std::make_shared<ahttp1::ahttp_impl::ahttp_mgr>();

    ahttp1::ahttp1() : impl(std::make_shared<ahttp1::ahttp_impl>()) {

    }

    void ahttp1::exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->exec(request, callback);
    }
}