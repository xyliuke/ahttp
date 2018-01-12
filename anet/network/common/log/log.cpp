//
// Created by ke liu on 12/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include "log.h"

namespace plan9
{

    class log::log_impl {

    };

    log::log() : impl(new log_impl){

    }

    log log::instance() {
        static log l;
        return l;
    }

    void log::debug(std::string msg) {

    }

    void log::debug(int msg) {
        int a = 0;
        a += msg;
    }

    void log::debug(std::function<int()> msg) {
        if (msg) {
            int a = msg();
            a ++;
        }
    }

}
