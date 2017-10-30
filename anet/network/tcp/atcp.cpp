//
//  atcp.cpp
//  anet
//
//  Created by ke liu on 18/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#include <sstream>
#include "atcp.hpp"
#include "uv.h"
#include "uv_wrapper.hpp"

namespace plan9
{
//    static void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
//        std::string resaon = std::string(uv_err_name(status));
//    }
//
//    void atcp::resolve(std::string url, int port, std::function<void()> callback) {
//        uv_thread_wrap::get_loop([=](uv_loop_t*  loop){
//            uv_getaddrinfo_t* resolver = new uv_getaddrinfo_t;
//            std::stringstream ss;
//            ss << port;
//            struct addrinfo *hints = new addrinfo;
//            hints->ai_family = PF_INET;
//            hints->ai_socktype = SOCK_STREAM;
//            hints->ai_protocol = IPPROTO_TCP;
//            hints->ai_flags = 0;
//            int ret = uv_getaddrinfo(loop, resolver, on_resolved, "www.baidu.com", "80", NULL);
//            if (ret) {
//
//            }
//        });
//    }
}
