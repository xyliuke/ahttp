//
// Created by ke liu on 29/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_PING_H
#define ANET_PING_H


#include <functional>
#include <string>

namespace plan9
{
    class ping {
    public:
        static void to(std::string ip, std::function<void(bool)> callback);
    };
}



#endif //ANET_PING_H
