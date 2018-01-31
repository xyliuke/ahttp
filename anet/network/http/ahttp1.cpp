//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include <assert.h>
#include <set>
#include "ahttp1.h"
#include "state_machine.h"
#include "uv_wrapper.hpp"

namespace plan9
{
    class ahttp1::ahttp_impl : public state_machine {
    public:
        ahttp_impl() {

            STATE_MACHINE_ADD_ROW(this, init_state, FETCH, begin_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, init_state, PUSH_WAITING_QUEUE, wait_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, wait_state, FETCH, begin_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, begin_state, SEND, send_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, begin_state, DNS_RESOLVE, dns_ing_state, [=](state_machine* fsm) -> bool {
                get_resolver()(request->get_domain(), request->get_port(), [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<std::vector<std::string>> ips){
                    if (ccb->success) {
                        this->ips = ips;
                    } else {
                        process_event(DNS_RESOLVE_ERROR);
                    }
                });
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, dns_ing_state, DNS_RESOLVE_OK, dns_end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, begin_state, OPEN, connecting_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, dns_ing_state, DNS_RESOLVE_ERROR, end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, dns_end_state, OPEN, connecting_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connecting_state, OPEN_SUCCESS, connected_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connecting_state, CLOSE, disconnect_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connected_state, SSL_CONNECT, ssl_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, ssl_ing_state, SSL_CONNECT_SUCCESS, ssl_end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, ssl_ing_state, CLOSE, disconnect_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, connected_state, SEND, send_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, disconnect_state, GIVE_UP, end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, disconnect_state, SWITCH_IP, connecting_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, disconnect_state, RETRY, dns_end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, ssl_end_state, SEND, send_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, send_ing_state, SEND_FINISH, send_end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, send_end_state, RECV, read_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_ing_state, RECV_FINISH, read_end_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, REDIRECT_OUTER, begin_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, REDIRECT_INNER, send_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, FORWARD, send_ing_state, [=](state_machine* fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(this, read_end_state, FINISH, end_state, [=](state_machine* fsm) -> bool {
                return true;
            });

            set_init_state<init_state>();
            start();
        }

        void exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            this->request = request;
            this->response = response;
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

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };

        //开始执行请求
        struct begin_state : public state {
            void on_entry(int event, state_machine *fsm) override {
                ahttp_impl* impl = (ahttp_impl*)fsm;
                if (event == REDIRECT_OUTER) {
                    //重定向
//                    impl->process_event(SEND);
                } else {
                    if (impl->request->is_ip_format_host()) {
//                    ip直连
                        impl->process_event(OPEN);
                    } else {
                        impl->process_event(DNS_RESOLVE);
                    }
                }

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //在请求队列中等待
        struct wait_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //dns解析中
        struct dns_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //dns解析完成
        struct dns_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //连接中
        struct connecting_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //连接完成
        struct connected_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //断开连接
        struct disconnect_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //ssl ing
        struct ssl_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //ssl end
        struct ssl_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //发送数据中
        struct send_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //发送数据结束
        struct send_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //读取数据中
        struct read_ing_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //读取数据结束
        struct read_end_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };
        //请求结束状态
        struct end_state : public state {
            void on_entry(int event, state_machine *fsm) override {

            }

            void on_exit(int event, state_machine *fsm) override {

            }
        };

        void no_transition(std::shared_ptr<state> begin, int event) override {
            assert(true);
        }

        std::shared_ptr<ahttp_request> request;
        std::shared_ptr<ahttp_response> response;
        class ahttp_mgr {
        public:
            /**
             * 添加请求到队列
             * @param impl
             */
            void push(ahttp_impl* impl) {
                if (is_exceed_max_connection_num()) {
                    //超过最大连接数
                    impl->process_event(PUSH_WAITING_QUEUE);
                } else {
                    impl->process_event(FETCH);
                }
            }

        private:
            bool is_exceed_max_connection_num() {
                return true;
            }
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
        std::shared_ptr<std::vector<std::string>> ips;

    };

    std::shared_ptr<ahttp1::ahttp_impl::ahttp_mgr> ahttp1::ahttp_impl::mgr = std::make_shared<ahttp1::ahttp_impl::ahttp_mgr>();

    ahttp1::ahttp1() : impl(std::make_shared<ahttp1::ahttp_impl>()) {

    }

    void ahttp1::exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->exec(request, callback);
    }
}