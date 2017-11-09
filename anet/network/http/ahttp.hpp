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
        void append_header(std::string key, int value);
        void append_header(std::shared_ptr<std::map<std::string, std::string>> headers);
        void set_method(std::string method);
        void set_http_version(std::string version);
        void set_url(std::string url);
        void append_data(std::shared_ptr<std::map<std::string, std::string>> data);
        void append_data(std::string key, std::string value);

        void set_reused_tcp(bool reused);
        bool is_reused_tcp();

        void set_timeout(int seconds);
        int get_timeout();

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

        template <typename T>
        T get_header(std::string key);
        std::string get_header(std::string key);
        std::shared_ptr<std::map<std::string, std::string>> get_headers();

        bool append_response_data(char* data, int len);
        void set_response_data_file(std::string file);
        int get_response_code();
        long get_response_data_length();
        long get_response_header_length();
        long get_response_length();
        long get_content_length();
        std::string get_body_string();
        std::string to_string();
    private:
        class ahttp_response_impl;
        std::shared_ptr<ahttp_response_impl> impl;
    };

    class ahttp {
    public:
        ahttp();

        void exec(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);

        void get(std::string url, std::shared_ptr<std::map<std::string, std::string>>header, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        void post(std::string url, std::shared_ptr<std::map<std::string, std::string>>header, std::shared_ptr<std::map<std::string, std::string>> data, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        void download(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);

        //各个时间段事件回调
        //解析DNS后事件
        void set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        //连接服务器后事件
        void set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        //客户端发送数据后事件
        void set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, int)> callback);
        //读取数据事件，每次读取数据都会触发，调用download函数时不要使用这个事件
        void set_read_event_callback(std::function<void(std::shared_ptr<common_callback>, long size)> callback);
        //第一次读到数据的事件
        void set_read_begin_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        //最后一次读到数据的事件
        void set_read_end_event_callback(std::function<void(std::shared_ptr<common_callback>, long)> callback);
        //关闭连接的事件
        void set_disconnected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);

    private:
        class ahttp_impl;
        std::shared_ptr<ahttp_impl> impl;
    };
}

#endif /* ahttp_hpp */
