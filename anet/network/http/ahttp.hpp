//
//  ahttp.hpp
//  anet
//
//  Created by ke liu on 22/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#ifndef ahttp_hpp
#define ahttp_hpp

#include <stdio.h>
#include <string>
#include <map>
#include <functional>
#include "common_callback.hpp"

namespace plan9 {

    class ahttp_request {
    public:
        ahttp_request();
        void append_header(std::string key, std::string value);
        void set_mothod(std::string method);
        void set_http_version(std::string version);
        void set_url(std::string url);

        std::string get_http_method_string();
        std::string get_http_header_string();
        std::string get_http_string();

        std::string get_domain();
        int get_port();
        std::string to_string();
    private:
        class ahttp_request_impl;
        std::shared_ptr<ahttp_request_impl> impl;
    };

    class ahttp_response {
    public:
        ahttp_response();

        bool append_response_data(char* data, int len);

        int get_response_code();
        int get_response_data_length();
        std::string to_string();
    private:
        class ahttp_response_impl;
        std::shared_ptr<ahttp_response_impl> impl;
    };

    class ahttp {
    public:
        ahttp();

        void exec(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        void exec2(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);

        //各个时间段事件回调
        void set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        void set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        void set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, int)> callback);
        void set_read_begin_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        void set_read_end_event_callback(std::function<void(std::shared_ptr<common_callback>, int)> callback);
        void set_disconnected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);

    private:
        class ahttp_impl;
        std::shared_ptr<ahttp_impl> impl;
    };
}

#endif /* ahttp_hpp */
