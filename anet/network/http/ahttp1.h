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

        /**
         * HTTP请求最基本的方法
         * @param request 请求参数的对象
         * @param callback 回调
         */
        void exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);

        /**
         * 是否验证域名
         * @param validate true 验证 false 不验证
         */
        void is_validate_domain(bool validate);

        /**
         * 是否验证证书
         * @param validate validate true 验证 false 不验证
         */
        void is_validate_cert(bool validate);

        /**
         * 设置低优先级，默认为高优先级
         * 设置低优先级后，会优先考虑复用tcp的情况，只有在没有tcp连接情况下，才会创建新的连接
         */
        void set_low_priority();

        /**
         * 设置高优先级
         * 默认为高优先级，默认情况下，
         * 未达到最大连接数数的请求，在已存在的tcp不空闲时，创建新的连接；存在空闲tcp时，优先复用原来tcp
         * 达到最大连接数时，等待tcp空闲，再复用tcp进行请求
         */
        void set_high_priority();

    private:
        class ahttp_impl;
        std::shared_ptr<ahttp_impl> impl;
    };
}


#endif //ANET_AHTTP1_H
