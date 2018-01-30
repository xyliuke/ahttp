//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include "ahttp1.h"
#include "state_machine.h"

namespace plan9
{

    class ahttp1::ahttp_impl {

    private:

        /**
         * HTTP的初始状态
         */
        struct init_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };
        //执行
        struct fetch_state : public state {
            void on_entry(int event, state_machine &fsm) override {

            }

            void on_exit(int event, state_machine &fsm) override {

            }
        };

    };

    ahttp1::ahttp1() : impl(std::make_shared<ahttp1::ahttp_impl>()) {

    }
}