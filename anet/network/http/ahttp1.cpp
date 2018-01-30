//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include "ahttp1.h"
#include "state_machine.h"

namespace plan9
{

    class ahttp1::ahttp_impl {
    public:
        ahttp_impl() : fsm(std::make_shared<state_machine>()) {
            STATE_MACHINE_ADD_ROW(fsm.get(), init_state, FETCH, begin_state, [=](state_machine& fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(fsm.get(), init_state, PUSH_WAITING_QUENE, wait_state, [=](state_machine& fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(fsm.get(), begin_state, DNS_RESOLVE, dns_ing_state, [=](state_machine& fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(fsm.get(), dns_ing_state, DNS_RETURN, dns_end_state, [=](state_machine& fsm) -> bool {
                //解析成功
                return true;
            });
            STATE_MACHINE_ADD_ROW(fsm.get(), dns_ing_state, DNS_RETURN, end_state, [=](state_machine& fsm) -> bool {
                //解析失败
                return true;
            });
            STATE_MACHINE_ADD_ROW(fsm.get(), dns_end_state, OPEN, connecting_state, [=](state_machine& fsm) -> bool {
                return true;
            });
            STATE_MACHINE_ADD_ROW(fsm.get(), connecting_state, OPEN, connecting_state, [=](state_machine& fsm) -> bool {
                return true;
            });
        }

    private:

        typedef enum http_event_ {
            FETCH,//开始执行请求数据操作
            PUSH_WAITING_QUENE,//压入请求队列
            DNS_RESOLVE,//dns解析
            DNS_RETURN,//dns解析成功
            OPEN,//连接TCP
            OPEN_SUCCESS,//
            CLOSE,//关闭TCP

        } http_event;

        // HTTP的初始状态
        struct init_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //开始执行请求
        struct begin_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //在请求队列中等待
        struct wait_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //dns解析中
        struct dns_ing_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //dns解析完成
        struct dns_end_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //开始连接
//        struct connect_state : public state {
//            void on_entry(int event, state_machine &fsm) override {
//
//            }
//
//            void on_exit(int event, state_machine &fsm) override {
//
//            }
//        };
        //连接中
        struct connecting_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //连接完成
        struct connected_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //断开连接
        struct disconnect_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //ssl begin
        struct ssl_begin_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //ssl ing
        struct ssl_ing_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //ssl end
        struct ssl_end_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //发送数据开始
        struct send_begin_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //发送数据中
        struct send_ing_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //发送数据结束
        struct send_end_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //读取数据开始
        struct read_begin_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //读取数据中
        struct read_ing_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //读取数据结束
        struct read_end_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //请求结束状态
        struct end_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };

        std::shared_ptr<state_machine> fsm;

    };

    ahttp1::ahttp1() : impl(std::make_shared<ahttp1::ahttp_impl>()) {

    }
}