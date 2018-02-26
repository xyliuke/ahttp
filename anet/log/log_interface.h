//
// Created by ke liu on 07/02/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_LOG_INTERFACE_H
#define ANET_LOG_INTERFACE_H

#import <cstdarg>

namespace plan9 {
    typedef enum log_type_ {
        NET,
        IO,
        UI,
        LUA,
        OTHER,
    } log_type;
    typedef enum log_level_ {
        LOG_LEVEL_INFO,
        LOG_LEVEL_DEBUG,
        LOG_LEVEL_WARN,
        LOG_LEVEL_ERROR,
        LOG_LEVEL_FATAL
    } log_level;

    class log_interface {
    public:
        log_interface() : l(LOG_LEVEL_DEBUG) {
        }

        virtual log_interface& log(log_level level, log_type type) {
            return *this;
        }
        void set_level(log_level level) {
            l = level;
        }
        log_level get_level() {
            return l;
        }

    private:
        log_level l;
    };

    class log_mgr {
    public:
        template <log_type t>
        static void log(log_level l, ...) {
        }
        static void set_impl(log_interface& impl) {
            i = impl;
        }

    private:
        static log_interface& i;
    };
}



#endif //ANET_LOG_INTERFACE_H
