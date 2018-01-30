//
// Created by ke liu on 12/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_LOG_H
#define ANET_LOG_H

#include <memory>
#include <string>
#include <functional>

namespace plan9
{
    class log {
    public:
        static log instance();

        void debug(std::string msg);
        void debug(int msg);
        void debug(std::function<int()> msg);

    private:
        log();
        class log_impl;
        std::shared_ptr<log_impl> impl;
    };
}


#endif //ANET_LOG_H
