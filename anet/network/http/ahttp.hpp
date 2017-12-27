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
#include "char_array.h"

namespace plan9 {

    class ahttp_request {
    public:
        ahttp_request();
        /**
         * 向header中添加数据
         * @param key header中key
         * @param value header中value
         */
        void append_header(std::string key, std::string value);
        /**
         * 向header中添加数据
         * @param key header中key
         * @param value header中value
         */
        void append_header(std::string key, int value);
        /**
         * 向header中添加一组数据
         * @param headers header集合
         */
        void append_header(std::shared_ptr<std::map<std::string, std::string>> headers);
        /**
         * 设置HTTP方法，目前支持GET/POST,默认为GET方法
         * @param method GET/POST
         */
        void set_method(std::string method);
        /**
         * 设置HTTP版本号，目前只支持1.1，默认为1.1
         * @param version 版本号
         */
        void set_http_version(std::string version);
        /**
         * 设置请求的url
         * @param url 请求链接
         */
        void set_url(std::string url);
        /**
         * 向body中添加数据，主要用于POST请求时
         * @param data 一组数据
         */
        void append_body_data(std::shared_ptr<std::map<std::string, std::string>> data);
        /**
         * 向body中添加数据，主要用于POST请求时
         * @param key key值
         * @param value value值
         */
        void append_body_data(std::string key, std::string value);

        void append_body_data_from_file(std::string key, std::string file);

        /**
         * 设置是否复用TCP，如果能复用的话
         * @param reused true为复用，默认为复用
         */
        void set_reused_tcp(bool reused);
        bool is_reused_tcp();
        /**
         * 设置超时时间，单位为秒，默认为30s
         * @param seconds 秒
         */
        void set_timeout(int seconds);
        int get_timeout();

        void set_keep_alive(bool keep_alive);
        bool is_keep_alive();

        bool is_use_ssl();

        /**
         * 将对象转化为字符串
         * @return 字符串结果
         */
        std::string to_string();

        //以下方法主要为内部使用
        std::string get_http_method_string();
        std::string get_http_header_string();
        std::string get_http_string();
        void get_http_data(std::function<void(char* data, long len, long sent, long total)>);

        std::string get_domain();
        int get_port();
        static inline int get_default_timeout() {
            return 30;
        }
    private:
        class ahttp_request_impl;
        std::shared_ptr<ahttp_request_impl> impl;
    };

    class ahttp_response {
    public:
        ahttp_response();
        /**
         * 通过key值获取header中数据，可以指定返回值转换的类型
         * @param key header中的key值，不区分大小写
         * @return header中key对应的值
         */
        template <typename T>
        T get_header(std::string key);
        /**
         * 获取header中的数据，返回字符串格式
         * @param key header中的key值，不区分大小写
         * @return header中key对应的值
         */
        std::string get_header(std::string key);
        /**
         * 获取所有header中的值
         * @return header集合
         */
        std::shared_ptr<std::map<std::string, std::string>> get_headers();

        /**
         * 设置数据写入文件
         * @param file 文件路径
         */
        void set_response_data_file(std::string file);
        /**
         * 获取HTTP 状态值
         * @return 状态值
         */
        int get_response_code();
        /**
         * 获取数据的body部分数据长度
         * @return body部分长度
         */
        long get_response_data_length();
        /**
         * 获取数据的header部分长度
         * @return header长度
         */
        long get_response_header_length();
        /**
         * 获取数据的总长度
         * @return 报文长度
         */
        long get_response_length();
        /**
         * 获取数据长度，通过header中的Content-Length来获取
         * @return 字节长度
         */
        long get_content_length();
        /**
         * 获取body的字符串
         * @return body部分的字符串
         */
        std::string get_body_string();
        /**
         * 将对象转化为字符串
         * @return 字符串
         */
        std::string to_string();
        //内部使用
        bool append_response_data(std::shared_ptr<char> data, int len);
    private:
        class ahttp_response_impl;
        std::shared_ptr<ahttp_response_impl> impl;
    };

    class ahttp {
    public:
        ahttp();
        ~ahttp();

        /**
         * 取消请求
         */
        void cancel();
        /**
         * HTTP请求最基本的方法
         * @param request 请求参数的对象
         * @param callback 回调
         */
        void exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        /**
         * 封装GET请求
         * @param url url字符串
         * @param header 请求头
         * @param callback 回调
         */
        void get(std::string url, std::shared_ptr<std::map<std::string, std::string>>header, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        void get(std::string url, int timeout, std::shared_ptr<std::map<std::string, std::string>>header, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        /**
         * 封装POST请求
         * @param url url字符串
         * @param header 请求头
         * @param data post的数据
         * @param callback 回调
         */
        void post(std::string url, std::shared_ptr<std::map<std::string, std::string>>header, std::shared_ptr<std::map<std::string, std::string>> data, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        void post(std::string url, int timeout, std::shared_ptr<std::map<std::string, std::string>>header, std::shared_ptr<std::map<std::string, std::string>> data, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        /**
         * 封装下载请求
         * @param url url字符串
         * @param file 本地的文件
         * @param header 请求头
         * @param process_callback 下载进度回调
         * @param callback 完成回调
         */
        void download(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);

        void upload(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
        /**
         * 设置dns解析的替换方案，默认使用libuv解析
         * @param callback 结果回调
         */
        void set_dns_resolve(std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> callback);
        //各个时间段事件回调
        //解析DNS后事件
        void set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        //连接服务器后事件
        void set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback);
        //客户端发送数据后事件
        void set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, long sent, long total)> callback);
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
