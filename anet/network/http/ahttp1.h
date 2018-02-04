//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_AHTTP1_H
#define ANET_AHTTP1_H

#include <memory>
#include "ahttp.hpp"

namespace plan9
{
    class ahttp1 {

    public:
        ahttp1();
        /**
         * 设置相同ip和端口号下的最大同时连接数
         * 未达到最大连接数数的请求，在已存在的tcp不空闲时，创建新的连接；存在空闲tcp时，优先复用原来tcp
         * 达到最大连接数时，等待tcp空闲，再复用tcp进行请求
         *
         * @param max 最大连接数
         */
        static void set_max_connection(int max);
        void exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
    private:
        class ahttp_impl;
        std::shared_ptr<ahttp_impl> impl;
    };
}


#endif //ANET_AHTTP1_H
