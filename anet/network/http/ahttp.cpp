//
//  ahttp.cpp
//  anet
//
//  Created by ke liu on 22/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#include <sstream>
#include "ahttp.hpp"
#include "uv_wrapper.hpp"
#include <vector>
#include <fstream>
#include <iostream>
#include "string_parser.hpp"
#include "tri_bool.h"
#include "zlib_wrap.hpp"
#include "case_insensitive_map.h"
#include "char_array.h"

namespace plan9 {

    class mutex_wrap {
    public:
        mutex_wrap() {
            uv_mutex_init(&mutex);
        }

        void lock() {
            uv_mutex_lock(&mutex);
        }

        void unlock() {
            uv_mutex_unlock(&mutex);
        }

        ~mutex_wrap() {
            uv_mutex_destroy(&mutex);
        }
    private:
        uv_mutex_t mutex;
    };

    class ahttp_request::ahttp_request_impl {
    public:
        ahttp_request_impl() : header(new case_insensitive_map), method("GET"), version("1.1"), port(80), path("/"),
                            timeout(30), reused_tcp(true) {
        }
        void append_header(std::string key, std::string value) {
            header->add(key, value);
        }
        void append_header(std::string key, int value) {
            std::stringstream ss;
            ss << value;
            append_header(key, ss.str());
        }

        void append_header(std::shared_ptr<std::map<std::string, std::string>> headers) {
            if (headers) {
                std::map<std::string, std::string>::const_iterator it = headers->begin();
                while (it != headers->end()) {
                    append_header(it->first, it->second);
                    it ++;
                }
            }
        }

        void set_method(std::string method) {
            this->method = method;
        }
        void set_http_version(std::string protocol) {
            this->version = protocol;
        }

        void set_url(std::string url) {
            this->url = string_parser::trim(url);
            size_t index_1 = url.find_first_of("://", 0);
            if (index_1 == std::string::npos) {
                return;
            }
            protocol = url.substr(0, index_1);

            size_t index_2 = url.find_first_of("/", index_1 + 3);
            if (index_2 == std::string::npos) {
                domain = url.substr(index_1 + 3, url.size() - index_1 - 2);
                path = "/";
            } else {
                domain = url.substr(index_1 + 3, index_2 - index_1 - 3);
                path = url.substr(index_2, url.size() - index_2);
            }
            size_t index_3 = domain.find_first_of(":", 0);
            if (index_3 != std::string::npos) {
                std::stringstream ss(domain.substr(index_3 + 1, domain.size() - index_3 - 1));
                ss >> port;
                domain = domain.substr(0, index_3);
            } else {
                std::string p_lower = string_parser::to_lower(protocol);
                if (p_lower == "https") {
                    port = 443;
                } else if (p_lower == "http") {
                    port = 80;
                }
            }
            if (!is_ip_format(domain)) {
                std::stringstream ss;
                ss << domain;
                ss << ":";
                ss << port;
                append_header("Host", ss.str());
            }
        }


        void append_body_data(std::shared_ptr<std::map<std::string, std::string>> data) {
            if (data && data->size() > 0) {
                if (boundary == "") {
                    boundary = get_boundary_string();
                    header->add("Content-Type", "Content-Type:multipart/form-data;boundary=" + boundary);
                }
                if (!this->data) {
                    this->data.reset(new std::map<std::string, std::string>);
                }

                std::map<std::string, std::string>::const_iterator it = data->begin();
                while (it != data->end()) {
                    (*this->data)[it->first] = it->second;
                    it ++;
                }
            }
        }

        void append_body_data_from_file(std::string key, std::string file) {
            if (!data_from_file) {
                data_from_file.reset(new std::map<std::string, std::string>);
            }

            if (boundary == "") {
                boundary = get_boundary_string();
                header->add("Content-Type", "multipart/form-data;boundary=" + boundary);
            }
            (*data_from_file)[key] = file;
        }

        void append_body_data(std::string key, std::string value) {
            if (!this->data) {
                this->data.reset(new std::map<std::string, std::string>);
            }
            if (boundary == "") {
                boundary = get_boundary_string();
                header->add("Content-Type", "multipart/form-data;boundary=" + boundary);
            }
            (*data)[key] = value;
        }

        void set_reused_tcp(bool reused) {
            reused_tcp = reused;
        }

        bool is_reused_tcp() {
            return reused_tcp;
        }

        void set_timeout(int seconds) {
            timeout = seconds;
        }

        int get_timeout() {
            return timeout;
        }

        std::string get_header(std::string key, bool* find) {
            return header->get(key, find);
        }

        void set_keep_alive(bool keep_alive) {
            append_header("Connection", "Keep-Alive");
        }
        bool is_keep_alive() {
            return true;
        }

        bool is_use_ssl() {
            return string_parser::to_lower(protocol) == "https";
        }

        std::shared_ptr<char_array> get_http_method_string () {
            std::shared_ptr<char_array> array(new char_array(20));
            array->append(method);
            array->append(" ");
            array->append(path);
            array->append(" ");
            array->append("HTTP/");
            array->append(version);
            return array;
        }

        std::shared_ptr<char_array> get_http_header_string() {
            std::shared_ptr<char_array> ss(new char_array(200));
            if (header != nullptr) {
                header->const_iteration([=](std::string key, std::string value) -> bool {
                    ss->append(key);
                    ss->append(":");
                    ss->append(value);
                    ss->append("\r\n");
                    return true;
                });
            }
            return ss;
        }

        std::shared_ptr<char_array> get_http_body_string(){
            std::shared_ptr<char_array> ret;
            if (data && data->size() > 0) {
                ret.reset(new char_array);
                ret->append(boundary);
                std::map<std::string, std::string>::const_iterator it = data->begin();
                while (it != data->end()) {
                    ret->append("\r\nContent-Disposition: form-data;name=\"");
                    ret->append(it->first);
                    ret->append("\r\n");
                    ret->append(it->second);
                    ret->append("\r\n");
                    ret->append(boundary);
                    it ++;
                }
            }
            return ret;
        }

        std::string get_domain() {
            return domain;
        }

        int get_port() {
            return port;
        }

        std::shared_ptr<char_array> get_http_string() {
            std::shared_ptr<char_array> method = get_http_method_string();
            std::shared_ptr<char_array> body = get_http_body_string();

            if (body && body->get_len() > 0) {
                append_header("Content-Length", body->get_len());
            }
            std::shared_ptr<char_array> header = get_http_header_string();
            method->append("\r\n");
            if (header) {
                method->append(header.get());
                method->append("\r\n");
            }
            if (body) {
                method->append(body.get());
                method->append("\r\n");
            }
            return method;
        }


        void get_http_data(std::function<void(std::shared_ptr<char> data, int len, int sent, int total)> callback) {
            if (callback) {
                std::shared_ptr<char_array> http = get_http_string();
                callback(http->get_data(), http->get_len(), 0, http->get_len());

                //上传文件
//                get_http_data_from_file(http.length(), callback);
            }
        }

        void get_http_data_from_file(long send, std::function<void(char* data, long len, long sent, long total)> callback) {
            if (callback && data_from_file && data_from_file->size() > 0) {
                using namespace std;

                std::function<void(char*, long, long)> func = bind(callback, placeholders::_1, placeholders::_2, placeholders::_3, 10);

                std::map<std::string, std::string>::const_iterator it = data_from_file->begin();
                long send_bytes = send;
                while (it != data_from_file->end()) {
                    stringstream ss;
                    ss << boundary;
                    ss << "\r\nContent-Disposition: form-data;name=\"";
                    ss << it->first;
                    ss << "\"\r\n";
                    char* buf1 = (char*)malloc(ss.str().length());
                    memcpy(buf1, (char*)(ss.str().c_str()), ss.str().length());
                    func(buf1, ss.str().length(), send_bytes);
                    send_bytes += ss.str().length();

                    string file = it->second;
                    ifstream ifs(file, ios::binary | ios::in);
                    if (ifs.is_open()) {
                        while (!ifs.eof()) {
                            char* buf = (char*) malloc(1024);
                            ifs.read(buf, 1024);
                            func(buf, ifs.gcount(), send_bytes);
                            send_bytes += ifs.gcount();
                        }
                    }

                    stringstream sss;
                    sss << "\r\n";
                    sss << boundary;
                    char* buf2 = (char*)malloc(ss.str().length());
                    memcpy(buf2, (char*)(sss.str().c_str()), sss.str().length());
                    func(buf2, sss.str().length(), send_bytes);
                    send_bytes += sss.str().length();

                    it ++;
                }
            }
        }

        static std::string get_boundary_string() {
            auto tp = std::chrono::system_clock::now();
            std::stringstream ss;
            ss << "--------------------------";
            ss << "Boundary";
            ss << tp.time_since_epoch().count();
            return ss.str();
        }
    private:
        std::shared_ptr<case_insensitive_map> header;
        std::shared_ptr<std::map<std::string, std::string>> data;
        std::shared_ptr<std::map<std::string, std::string>> data_from_file;
        std::string method;
        std::string version;
        std::string url;
        std::string protocol;
        std::string domain;
        std::string path;
        int port;
        std::string boundary;
        int timeout;
        bool reused_tcp;

    };

    ahttp_request::ahttp_request() : impl(new ahttp_request_impl) {

    }

    void ahttp_request::append_header(std::string key, std::string value) {
        impl->append_header(key, value);
    }

    void ahttp_request::append_header(std::string key, int value) {
        impl->append_header(key, value);
    }

    void ahttp_request::append_header(std::shared_ptr<std::map<std::string, std::string>> headers) {
        impl->append_header(headers);
    }

    void ahttp_request::set_method(std::string method) {
        impl->set_method(method);
    }

    void ahttp_request::set_http_version(std::string version) {
        impl->set_http_version(version);
    }

    void ahttp_request::set_url(std::string url) {
        impl->set_url(url);
    }

    void ahttp_request::append_body_data(std::shared_ptr<std::map<std::string, std::string>> data) {
        impl->append_body_data(data);
    }

    void ahttp_request::append_body_data(std::string key, std::string value) {
        impl->append_body_data(key, value);
    }

    void ahttp_request::append_body_data_from_file(std::string key, std::string file) {
        impl->append_body_data_from_file(key, file);
    }

    void ahttp_request::set_reused_tcp(bool reused) {
        impl->set_reused_tcp(reused);
    }

    bool ahttp_request::is_reused_tcp() {
        return impl->is_reused_tcp();
    }

    void ahttp_request::set_timeout(int seconds) {
        impl->set_timeout(seconds);
    }

    int ahttp_request::get_timeout() {
        return impl->get_timeout();
    }

    void ahttp_request::set_keep_alive(bool keep_alive) {
        impl->set_keep_alive(keep_alive);
    }

    bool ahttp_request::is_keep_alive() {
        return impl->is_keep_alive();
    }

    bool ahttp_request::is_use_ssl() {
        return impl->is_use_ssl();
    }

    bool ahttp_request::is_ip_format(std::string str) {
        return uv_wrapper::is_ip4(str) || uv_wrapper::is_ip6(str);
    }

    std::string ahttp_request::get_http_method_string() {
        return impl->get_http_method_string()->to_string();
    }

    std::string ahttp_request::get_http_header_string() {
        return impl->get_http_header_string()->to_string();
    }

    std::string ahttp_request::get_http_string() {
        return impl->get_http_string()->to_string();
    }

    void ahttp_request::get_http_data(std::function<void(std::shared_ptr<char> data, int len, int sent, int total)> callback) {
        return impl->get_http_data(callback);
    }

    std::string ahttp_request::to_string() {
        return impl->get_http_string()->to_string();
    }
    std::string ahttp_request::get_domain() {
        return impl->get_domain();
    }

    int ahttp_request::get_port() {
        return impl->get_port();
    }


    class ahttp_response::ahttp_response_impl {
    public:

        ahttp_response_impl() : header_buf((char*)malloc(65536)), header_buf_size(65536), header_len(0), block_num(0), status(-1),
                                data_buf(nullptr), data_buf_size(0), data_len(0), content_length(0), http_header_end_position(0),
                                http_status_end_position(0), headers(new case_insensitive_map),
                                transfer_encoding_chunked(tri_undefined), total_len(0) {
        }

        ~ahttp_response_impl() {
            if (header_buf != nullptr) {
                free(header_buf);
                header_buf = nullptr;
            }
            if (data_buf != nullptr) {
                free(data_buf);
                data_buf = nullptr;
            }
            if (ofstream) {
                ofstream->close();
            }
        }

        bool fill_header_buf(std::shared_ptr<char> data, int len, int* new_data_begin) {
            *new_data_begin = 0;
            if (http_header_end_position > 0) {
                return true;
            }
            int pos = find_header_end_position(data, len);
            http_header_end_position = pos + header_len;
            int real_len = 0;
            if (pos < 0) {
                real_len = len;
            } else {
                real_len = pos;
                *new_data_begin = pos + 1;
            }
            if (header_buf_size - this->header_len > real_len) {
                //有足够空间
            } else {
                header_buf = (char*)realloc(header_buf, real_len * 2 + header_buf_size);
                header_buf_size += real_len * 2;
            }
            memcpy(header_buf + this->header_len, data.get(), real_len);
            this->header_len += real_len;
            return pos >= 0;
        }

        int find_header_end_position(std::shared_ptr<char> data, int len) {
            for (int i = 0; i < len; ++i) {
                char c = *(data.get() + i);
                if (c == '\r' && i < (len - 3) && '\n' == *(data.get() + i + 1) && '\r' == *(data.get() + i + 2) && '\n' == *(data.get() + i + 3)) {
                    return i + 3;
                }
            }
            return -1;
        }

        bool fill_body_buf(char* data, int len) {
            if (data_buf == nullptr) {
                data_buf = (char*) malloc(len << 2);
                data_buf_size = (len << 2);
            }
            if (http_header_end_position > 0) {
                if (data_buf_size - data_len < len) {
                    //空间不够
                    data_buf = (char*) realloc(data_buf, data_len + (len << 2));
                }
                memcpy(data_buf + data_len, data, len);
                data_len += len;
                bool over = is_over(data_buf, data_len);
                if (over) {
                    parse_http_body();
                }
                return over;
            }
            return true;
        }

        bool fill_body_to_file(char* data, int len) {
            if (!ofstream) {
                ofstream.reset(new std::ofstream);
                ofstream->open(file, std::ios::app | std::ios::binary);
            }
            ofstream->write(data, len);
            data_len += len;
            bool over = is_over(data, len);
            if (over) {
                ofstream->close();
            }
            return over;
        }

        bool append_response_data(std::shared_ptr<char> data, int len) {
            total_len += len;
            block_num ++;
            int new_pos = 0;
            if (fill_header_buf(data, len, &new_pos)) {
                parse();
                if (new_pos < len) {
                    if (file != "") {
                        //保存到文件
                        return fill_body_to_file(data.get() + new_pos, len - new_pos);
                    } else {
                        return fill_body_buf(data.get() + new_pos, len - new_pos);
                    }
                }
            }
            return false;
        }

        void set_response_file(std::string file) {
            this->file = file;
        }

        bool is_over(char* data, int len) {
            if (get_content_length() > 0 && data_len >= get_content_length()) {
                return true;
            }
            if (len >= 6 && data[len - 5] == '0' && data[len - 4] == '\r' && data[len - 3] == '\n' && data[len - 2] == '\r' && data[len - 1] == '\n') {
                return true;
            }
            return false;
        }

        void parse() {
            parse_http_status();
            parse_http_header();
        }

        void parse_http_status() {
            if (http_version == "" && status < 0) {
                std::string header = find_response_status_string();
                std::shared_ptr<std::vector<std::string>> sp = string_parser::split(header, " ");
                if (sp->size() == 3) {
                    http_version = sp->at(0);
                    std::stringstream ss(sp->at(1));
                    ss >> status;
                }
            }
        }

        std::string find_response_status_string() {
            for (int i = 5; i < header_buf_size; i += 2) {
                char c = header_buf[i];
                if (c == '\r' && header_buf[i + 1] == '\n') {
                    http_status_end_position = i + 1;
                    return std::string(header_buf, 0, i);
                } else if (c == '\n' && header_buf[i - 1] == '\r') {
                    http_status_end_position = i;
                    return std::string(header_buf, 0, i - 1);
                }
            }
            return "";
        }

        void parse_http_header() {
            if (http_status_end_position > 0) {
                int pre_header_item_end_pos = http_status_end_position;
                for (int i = http_status_end_position + 1; i < header_len; i ++) {
                    char c = header_buf[i];
                    if ('\r' == c && '\n' == header_buf[i + 1]){
                        int key_begin, key_end, value_begin, value_end;
                        if (parse_key_value(pre_header_item_end_pos + 1, i - 1, &key_begin, &key_end, &value_begin, &value_end)) {
                            std::string k = string_parser::trim(std::string(header_buf, key_begin, key_end - key_begin + 1));
                            std::string v = string_parser::trim(std::string(header_buf, value_begin, value_end - value_begin + 1));
                            headers->add(k, v);
                        }

                        if ('\r' == header_buf[i + 2] && '\n' == header_buf[i + 3]) {
                            http_header_end_position = i + 3;
                            break;
                        } else {
                            pre_header_item_end_pos = i + 1;
                        }
                    }
                }
            }
        }

        void parse_http_body() {
            if (!ofstream) {
                //没有写文件
                if (is_transfer_encoding_chunked()) {
                    int data_real_index = 0;
                    int data_real_len = 0;
                    for (int i = 0; i < data_len; ++i) {
                        char c = data_buf[i];
                        if (c == '\r' && data_buf[i + 1] == '\n') {
                            data_real_index = i + 2;
                            break;
                        }
                    }
                    data_real_len = string_parser::dex_to_dec(data_buf, data_real_index - 2);
                    std::string zip = get_header_string("Content-Encoding");
                    if ("gzip" == zip) {
                        unsigned long len = 0;
                        char* new_data = zlib_wrap::ungzip(data_buf + data_real_index, data_real_len, &len);
                        if (len > 0) {
                            free(data_buf);
                            data_buf = new_data;
                            data_len = (int)len;
                            data_buf_size = (int)len;
                        }
                    } else {
                        char* new_data = (char*) malloc(data_real_len);
                        memcpy(new_data, data_buf + data_real_index, data_real_len);
                        free(data_buf);
                        data_buf = new_data;
                        data_len = data_real_len;
                    }
                }
            }
        }

        bool parse_key_value(int begin, int end, int*key_begin, int* key_end, int* value_begin, int* value_end) {
            *key_begin = begin;
            *value_end = end;
            for (int i = begin; i <= end; ++i) {
                if (':' == header_buf[i]) {
                    *key_end = i - 1;
                    *value_begin = i + 1;
                    return true;
                }
            }
            return false;
        }

        long get_len() {
            return total_len;
        }

        long get_content_length() {
            if (content_length <= 0) {
                content_length = get_header<long>("Content-Length");
            }
            return content_length;
        }

        bool is_transfer_encoding_chunked() {
            if (transfer_encoding_chunked == tri_undefined) {
                std::string v = get_header_string("Transfer-Encoding");
                if (string_parser::to_lower(v) == "chunked") {
                    transfer_encoding_chunked = tri_true;
                } else {
                    transfer_encoding_chunked = tri_false;
                }
                return transfer_encoding_chunked == tri_true;
            } else {
                return transfer_encoding_chunked == tri_true;
            }
        }

        int get_status() {
            return status;
        }

        long get_body_len() {
            return total_len - header_len;
        }

        long get_header_len() {
            return header_len;
        }

        template <typename T>
        T get_header(std::string key) {
            std::string ret = string_parser::trim(get_header_string(key));
            std::stringstream ss(ret);
            T t;
            ss >> t;
            return t;
        }

        std::string get_header_string(std::string key) {
            bool find;
            std::string ret = headers->get(key, &find);
            if (find) {
                return ret;
            }
            return "";
        }

        std::shared_ptr<std::map<std::string, std::string>> get_headers() {
            return headers->get();
        };
        std::string get_body_string() {
            return std::string(data_buf, data_len);
        }

        std::string to_string() {
            if (ofstream) {
                return std::string(header_buf, header_len);
            } else {
                std::stringstream ss;
                ss.write(header_buf, header_len);
                ss.write(data_buf, data_len);
                return ss.str();
            }
        }

    private:
        long total_len;
        char* header_buf;
        int header_buf_size;
        int header_len;
        char* data_buf;
        int data_buf_size;
        int data_len;
        int block_num;
        std::string http_version;
        int status;
        int http_status_end_position;
        int http_header_end_position;
        std::shared_ptr<case_insensitive_map> headers;
        std::string file;
        std::shared_ptr<std::ofstream> ofstream;
        long content_length;
        tri_bool transfer_encoding_chunked;
    };

    ahttp_response::ahttp_response() : impl(new ahttp_response_impl) {

    }

    template <typename T>
    T ahttp_response::get_header(std::string key) {
        return impl->get_header<T>(key);
    }

    std::string ahttp_response::get_header(std::string key) {
        return impl->get_header_string(key);
    }

    std::shared_ptr<std::map<std::string, std::string>> ahttp_response::get_headers() {
        return impl->get_headers();
    }

    bool ahttp_response::append_response_data(std::shared_ptr<char> data, int len) {
        return impl->append_response_data(data, len);
    }

    void ahttp_response::set_response_data_file(std::string file) {
        impl->set_response_file(file);
    }

    long ahttp_response::get_response_data_length() {
        return impl->get_body_len();
    }

    long ahttp_response::get_response_header_length() {
        return impl->get_header_len();
    }

    long ahttp_response::get_response_length() {
        return impl->get_len();
    }

    long ahttp_response::get_content_length() {
        return impl->get_content_length();
    }

    std::string ahttp_response::to_string() {
        return impl->to_string();
    }

    std::string ahttp_response::get_body_string() {
        return impl->get_body_string();
    }

    class ahttp::ahttp_impl {
    public:

        ahttp_impl() : timer_id(-1), read_begin(false),
                       dns_resolve_callback(std::bind(&uv_wrapper::resolve, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)),
                        validate_domain(false), validate_cert(false) {

        }

        ~ahttp_impl() {
            cancel();
        }

        static void exec_reused_connect(int tcp_id) {
            if (tcp_http_map.find(tcp_id) != tcp_http_map.end()) {
                auto list = tcp_http_map[tcp_id];
                if (list->size() > 0) {
                    auto http = list->at(0);

                    std::shared_ptr<common_callback> ccb(new common_callback);
                    http->send_dns_event(ccb);

                    std::shared_ptr<common_callback> ccb1(new common_callback);
                    http->send_connected_event(ccb1);

                    if (http->request->is_use_ssl()) {
                        std::shared_ptr<common_callback> ccb2(new common_callback);
                        http->send_ssl_connected_event(ccb2);
                    }

                    std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>> list_disconnected;
                    if (tcp_http_disconnected_map.find(tcp_id) != tcp_http_disconnected_map.end()) {
                        list_disconnected = tcp_http_disconnected_map[tcp_id];
                    } else {
                        list_disconnected.reset(new std::vector<std::shared_ptr<ahttp_impl>>);
                        tcp_http_disconnected_map[tcp_id] = list_disconnected;
                    }
                    list_disconnected->push_back(http);

                    http->request->get_http_data([=](std::shared_ptr<char> data, int len, int sent, int total){
                        uv_wrapper::write(tcp_id, data, len, [=](std::shared_ptr<common_callback> write_callback){
                            http->send_send_event(write_callback, sent + len, total);
                        });
                    });
                }
            }
        }

        static std::string get_unique_domain(std::string domain, int port) {
            std::stringstream ss;
            ss << domain;
            ss << port;
            return ss.str();
        }

        static void exec_new_connect(std::shared_ptr<ahttp::ahttp_impl> http, std::string domain, std::string ip, int port) {
            auto connected_callback = [=](std::shared_ptr<common_callback> ccb, int tcp_id) {
                if (ccb->success) {
                    mutex.lock();
                    if (http->request) {
                        url_tcp_map[get_unique_domain(http->request->get_domain(), http->request->get_port())] = tcp_id;
                    }

                    mutex.unlock();

                    std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>> list;
                    if (tcp_http_map.find(tcp_id) != tcp_http_map.end()) {
                        list = tcp_http_map[tcp_id];
                    } else {
                        list.reset(new std::vector<std::shared_ptr<ahttp_impl>>);
                        mutex.lock();
                        tcp_http_map[tcp_id] = list;
                        mutex.unlock();
                    }
                    mutex.lock();
                    list->push_back(http);
                    mutex.unlock();

                    http->request->get_http_data([=](std::shared_ptr<char> data, int len, int sent, int total){
                        uv_wrapper::write(tcp_id, data, len, [=](std::shared_ptr<common_callback> write_callback){
                            http->send_send_event(write_callback, sent + len, total);
                        });
                    });
                } else {
                    uv_wrapper::close(tcp_id);
                }
            };
            uv_wrapper::connect(ip, port, http->request->is_use_ssl(), domain, [=](std::shared_ptr<common_callback> ccb, int tcp_id){
                //tcp connected
                std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>> list_disconnected;
                if (tcp_http_disconnected_map.find(tcp_id) != tcp_http_disconnected_map.end()) {
                    list_disconnected = tcp_http_disconnected_map[tcp_id];
                } else {
                    list_disconnected.reset(new std::vector<std::shared_ptr<ahttp_impl>>);
                    tcp_http_disconnected_map[tcp_id] = list_disconnected;
                }
                list_disconnected->push_back(http);
                http->send_connected_event(ccb);
                if (http->request->is_use_ssl()) {

                } else {
                    connected_callback(ccb, tcp_id);
                }
                auto ssl = uv_wrapper::get_ssl_impl_by_tcp_id(tcp_id);
                if (ssl) {
                    ssl->validate_domain(http->validate_domain);
                    ssl->validate_cert(http->validate_cert);
                }
            }, [=](std::shared_ptr<common_callback> ccb, int tcp_id) {
                //ssl connected
                http->send_ssl_connected_event(ccb);
                if (http->request->is_use_ssl()) {
                    connected_callback(ccb, tcp_id);
                }
            }, [=](int tcp_id, std::shared_ptr<char>data, int len) {
                if (tcp_http_map.find(tcp_id) != tcp_http_map.end()) {
                    auto http_list = tcp_http_map[tcp_id];
                    if (http_list->size() > 0) {
                        auto h = http_list->at(0);
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        h->send_read_begin_event(ccb);
                        if (h->append(data, len)) {
                            mutex.lock();
                            http_list->erase(http_list->begin());
                            uv_wrapper::cancel_timer(h->timer_id);
                            mutex.unlock();
                            if (h->callback != nullptr) {
                                std::shared_ptr<common_callback> ccb(new common_callback);
                                h->callback(ccb, h->request, h->response);
                            }
                            if (http_list->size() > 0) {
                                exec_reused_connect(tcp_id);
                            }
                        }
                    }
                }
            }, [=](std::shared_ptr<common_callback> disconnect_ccb, int tcp_id) {
                mutex.lock();
                std::map<std::string, int>::const_iterator it = url_tcp_map.begin();
                while (it != url_tcp_map.end()) {
                    if (it->second == tcp_id) {
                        break;
                    }
                    it++;
                }
                if (it != url_tcp_map.end()) {
                    url_tcp_map.erase(it);
                }
                mutex.unlock();

                if (tcp_http_disconnected_map.find(tcp_id) != tcp_http_disconnected_map.end()) {
                    auto http_list = tcp_http_disconnected_map[tcp_id];
                    tcp_http_disconnected_map.erase(tcp_id);
                    std::vector<std::shared_ptr<ahttp_impl>>::const_iterator itt = http_list->begin();
                    while (itt != http_list->end()) {
                        auto ahttp_i = *itt;
                        if (ahttp_i) {
                            ahttp_i->send_disconnected_event(disconnect_ccb);
                        }
                        itt ++;
                    }
                }

                tcp_http_map.erase(tcp_id);
            });
        }

        static void exec(std::shared_ptr<ahttp::ahttp_impl> http) {
            if (http && http->request != nullptr && http->callback != nullptr) {
                bool reused_connect = false;
                std::string uni_domain = get_unique_domain(http->request->get_domain(), http->request->get_port());
                if (http->request->is_reused_tcp() && url_tcp_map.find(uni_domain) != url_tcp_map.end()) {
                    //重用tcp
                    int tcp_id = url_tcp_map[uni_domain];
                    std::shared_ptr<std::vector<std::shared_ptr<ahttp::ahttp_impl>>> list;
                    if (tcp_http_map.find(tcp_id) != tcp_http_map.end()) {
                        list = tcp_http_map[tcp_id];
                    } else {
                        list.reset(new std::vector<std::shared_ptr<ahttp::ahttp_impl>>);
                        mutex.lock();
                        tcp_http_map[tcp_id] = list;
                        mutex.unlock();
                    }
                    mutex.lock();
                    list->push_back(http);
                    mutex.unlock();
                    if (list->size() == 1) {
                        if (uv_wrapper::tcp_alive(tcp_id)) {
                            exec_reused_connect(tcp_id);
                            reused_connect = true;
                        } else {
                            reused_connect = false;
                        }
                    } else {
                        reused_connect = true;
                    }
                }
                if (!reused_connect) {
                    if (http->request->is_ip_format(http->request->get_domain())) {
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        http->send_dns_event(ccb);
                        exec_new_connect(http, http->request->get_domain(), http->request->get_domain(), http->request->get_port());
                    } else {
                        http->dns_resolve_callback(http->request->get_domain(), http->request->get_port(), [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<std::vector<std::string>> ips){
                            http->send_dns_event(ccb);
                            if (ccb->success) {
                                if (ips->size() > 0) {
                                    std::string ip = (*ips)[0];
                                    exec_new_connect(http, http->request->get_domain(), ip, http->request->get_port());
                                }
                            }
                        });
                    }
                }
            }
        }
        void exec2(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            std::shared_ptr<ahttp_impl> self;
            //TODO 可能存在内存泄露
            self.reset(this);
            request = model;
            this->callback = callback;
            if (model->get_timeout() > 0) {
                timer_id = uv_wrapper::post_timer([=](){
                    std::map<int, std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>>>::const_iterator it = tcp_http_map.begin();
                    bool find = false;
                    while (it != tcp_http_map.end()) {
                        std::vector<std::shared_ptr<ahttp_impl>>::iterator itt = it->second->begin();
                        while (itt != it->second->end()) {
                            if (*itt == self) {
                                find = true;
                                it->second->erase(itt);
                                break;
                            }
                            itt ++;
                        }
                        if (find) {
                            break;
                        }
                        it++;
                    }
                    if (find && self->callback) {
                        std::shared_ptr<common_callback> ccb(new common_callback(false, -1, "timeout"));
                        if (!self->response) {
                            self->response.reset(new ahttp_response);
                        }
                        self->callback(ccb, self->request, self->response);
                    }
                }, model->get_timeout() * 1000, 0);
            }
            ahttp_impl::exec(self);
        }

        void cancel() {
            mutex.lock();
            std::map<int, std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>>>::const_iterator it = tcp_http_map.begin();
            bool find = false;
            while (it != tcp_http_map.end()) {
                std::vector<std::shared_ptr<ahttp_impl>>::iterator itt = it->second->begin();
                while (itt != it->second->end()) {
                    if ((*itt).get() == this) {
                        find = true;
                        it->second->erase(itt);
                        break;
                    }
                    itt ++;
                }
                if (find) {
                    break;
                }
                it++;
            }

            it = tcp_http_disconnected_map.begin();
            find = false;
            while (it != tcp_http_disconnected_map.end()) {
                std::vector<std::shared_ptr<ahttp_impl>>::iterator itt = it->second->begin();
                while (itt != it->second->end()) {
                    if ((*itt).get() == this) {
                        find = true;
                        it->second->erase(itt);
                        break;
                    }
                    itt ++;
                }
                if (find) {
                    break;
                }
                it++;
            }
            mutex.unlock();
        }

        void is_validate_domain(bool validate) {
            validate_domain = validate;
        }

        void is_validate_cert(bool validate) {
            validate_cert = validate;
        }

        void set_dns_resolve(std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> callback) {
            this->dns_resolve_callback = callback;
        }

        void set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            dns_callback = callback;
        }
        void set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            connect_callback = callback;
        }
        void set_ssl_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            ssl_connect_callback = callback;
        }
        void set_read_event_callback(std::function<void(std::shared_ptr<common_callback>, long size)> callback) {
            read_callback = callback;
        }
        void set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, long sent, long total)> callback) {
            send_callback = callback;
        }
        void set_read_begin_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            read_begin_callback = callback;
        }
        void set_read_end_event_callback(std::function<void(std::shared_ptr<common_callback>, long bytes)> callback) {
            read_end_callback = callback;
        }
        void set_disconnected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            disconnect_callback = callback;
        }

        void get(std::string url, int timeout, std::shared_ptr<std::map<std::string, std::string>>header, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            std::shared_ptr<ahttp_request> request(new ahttp_request);
            request->set_method("GET");
            request->set_url(url);
            request->append_header(header);
            request->set_timeout(timeout);
            exec2(request, callback);
        }

        void post(std::string url, int timeout, std::shared_ptr<std::map<std::string, std::string>>header, std::shared_ptr<std::map<std::string, std::string>> data, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            std::shared_ptr<ahttp_request> request(new ahttp_request);
            request->set_method("POST");
            request->set_url(url);
            request->append_header(header);
            request->append_body_data(data);
            request->set_timeout(timeout);
            exec2(request, callback);
        }


        void download(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            std::shared_ptr<ahttp_request> request(new ahttp_request);
            request->set_method("GET");
            request->set_url(url);
            request->append_header(header);
            request->set_timeout(0);
            this->response.reset(new ahttp_response);
            this->response->set_response_data_file(file);
            if (process_callback) {
                this->set_read_event_callback([=](std::shared_ptr<common_callback> ccb, int size){
                    long total = response->get_content_length();
                    process_callback(response->get_response_data_length(), total);
                });
            }
            exec2(request, callback);
        }

        void upload(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            std::shared_ptr<ahttp_request> request(new ahttp_request);
            request->set_method("POST");
            request->set_url(url);
            request->append_header(header);
            request->set_timeout(0);
            request->append_body_data_from_file("file", file);
            this->response.reset(new ahttp_response);
            if (process_callback) {
                this->set_read_event_callback([=](std::shared_ptr<common_callback> ccb, int size){
                    long total = response->get_content_length();
                    process_callback(response->get_response_data_length(), total);
                });
            }
            exec2(request, callback);
        }

    private:
        void send_dns_event(std::shared_ptr<common_callback> callback) {
            if (dns_callback) {
                dns_callback(callback);
            }
        }
        void send_connected_event(std::shared_ptr<common_callback> callback) {
            if (connect_callback) {
                connect_callback(callback);
            }
        }
        void send_ssl_connected_event(std::shared_ptr<common_callback> callback) {
            if (ssl_connect_callback) {
                ssl_connect_callback(callback);
            }
        }
        void send_send_event(std::shared_ptr<common_callback> callback, long bytes, long total) {
            if (send_callback) {
                send_callback(callback, bytes, total);
            }
        }
        void send_read_event(std::shared_ptr<common_callback> callback, int bytes) {
            if (read_callback) {
                read_callback(callback, bytes);
            }
        }
        void send_read_begin_event(std::shared_ptr<common_callback> callback) {
            if (!read_begin) {
                if (read_begin_callback) {
                    read_begin_callback(callback);
                }
                read_begin = true;
            }
        }
        void send_read_end_event(std::shared_ptr<common_callback> callback, long bytes) {
            if (read_end_callback) {
                read_end_callback(callback, bytes);
            }
        }
        void send_disconnected_event(std::shared_ptr<common_callback> callback) {
            if (disconnect_callback) {
                disconnect_callback(callback);
            }
        }

        bool append(std::shared_ptr<char> data, int len) {
            if (!response) {
                response.reset(new ahttp_response);
            }
            bool isEnd = response->append_response_data(data, len);
            std::shared_ptr<common_callback> ccb(new common_callback);
            send_read_event(ccb, len);
            if (isEnd) {
                send_read_end_event(nullptr, response->get_response_length());
            }
            return isEnd;
        }


        static std::map<std::string, int> url_tcp_map;
        static std::map<int, std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>>> tcp_http_map;
        static std::map<int, std::shared_ptr<std::vector<std::shared_ptr<ahttp_impl>>>> tcp_http_disconnected_map;
        static mutex_wrap mutex;
        std::shared_ptr<ahttp_response> response;
        std::shared_ptr<ahttp_request> request;
        std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback;
        std::function<void(std::shared_ptr<common_callback>)> dns_callback;
        std::function<void(std::shared_ptr<common_callback>)> connect_callback;
        std::function<void(std::shared_ptr<common_callback>)> ssl_connect_callback;
        std::function<void(std::shared_ptr<common_callback>, long, long)> send_callback;
        std::function<void(std::shared_ptr<common_callback>, long)> read_callback;
        std::function<void(std::shared_ptr<common_callback>)> read_begin_callback;
        std::function<void(std::shared_ptr<common_callback>, long)> read_end_callback;
        std::function<void(std::shared_ptr<common_callback>)> disconnect_callback;
        std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> dns_resolve_callback;
        int timer_id;
        bool read_begin;
        bool validate_domain;
        bool validate_cert;
    };

    std::map<std::string, int> ahttp::ahttp_impl::url_tcp_map;
    std::map<int, std::shared_ptr<std::vector<std::shared_ptr<ahttp::ahttp_impl>>>> ahttp::ahttp_impl::tcp_http_map;
    std::map<int, std::shared_ptr<std::vector<std::shared_ptr<ahttp::ahttp_impl>>>> ahttp::ahttp_impl::tcp_http_disconnected_map;
    mutex_wrap ahttp::ahttp_impl::mutex;

    ahttp::ahttp() : impl(new ahttp_impl) {

    }

    ahttp::~ahttp() {
        cancel();
    }

    void ahttp::is_validate_domain(bool validate) {
        impl->is_validate_domain(validate);
    }

    void ahttp::is_validate_cert(bool validate) {
        impl->is_validate_cert(validate);
    }

    void ahttp::cancel() {
        impl->cancel();
    }

    void ahttp::exec(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->exec2(model, callback);
    }

    void ahttp::set_dns_resolve(std::function<void(std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)>)> callback) {
        impl->set_dns_resolve(callback);
    }

    void ahttp::set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_dns_event_callback(callback);
    }
    void ahttp::set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_connected_event_callback(callback);
    }

    void ahttp::set_ssl_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_ssl_connected_event_callback(callback);
    }

    void ahttp::set_read_event_callback(std::function<void(std::shared_ptr<common_callback>, long size)> callback) {
        impl->set_read_event_callback(callback);
    }

    void ahttp::set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, long, long)> callback) {
        impl->set_send_event_callback(callback);
    }

    void ahttp::set_read_begin_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_read_begin_event_callback(callback);
    }

    void ahttp::set_read_end_event_callback(std::function<void(std::shared_ptr<common_callback>, long)> callback) {
        impl->set_read_end_event_callback(callback);
    }

    void ahttp::set_disconnected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_disconnected_event_callback(callback);
    }

    void ahttp::get(std::string url, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->get(url, ahttp_request::get_default_timeout(), header, callback);
    }

    void ahttp::get(std::string url, int timeout, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->get(url, timeout, header, callback);
    }

    void ahttp::post(std::string url, std::shared_ptr<std::map<std::string, std::string>> header, std::shared_ptr<std::map<std::string, std::string>> data, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->post(url, ahttp_request::get_default_timeout(), header, data, callback);
    }

    void ahttp::post(std::string url, int timeout, std::shared_ptr<std::map<std::string, std::string>> header, std::shared_ptr<std::map<std::string, std::string>> data, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->post(url, timeout, header, data, callback);
    }

    void ahttp::download(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->download(url, file, header, process_callback, callback);
    }

    void ahttp::upload(std::string url, std::string file, std::shared_ptr<std::map<std::string, std::string>> header, std::function<void(long current, long total)> process_callback, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->upload(url, file, header, process_callback, callback);
    }

}
