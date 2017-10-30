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
#include "string_parser.hpp"

namespace plan9 {

    class ahttp_request::ahttp_request_impl {
    public:
        ahttp_request_impl() : header(new std::vector<std::string>), method("GET"), version("1.1"), port(80), path("/") {
        }
        void append_header(std::string key, std::string value) {
            header->push_back(key + ": " + value);
        }
        void set_mothod(std::string method) {
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
            std::stringstream ss;
            ss << domain;
            ss << ":";
            ss << port;
            append_header("Host", ss.str());
        }

        std::string get_http_method_string() {
            std::stringstream ss;
            ss << method;
            ss << " ";
            ss << path;
            ss << " ";
            ss << "HTTP/";
            ss << version;
            return ss.str();
        }

        std::string get_http_header_string() {
            std::stringstream ss;
            if (header != nullptr) {
                for (int i = 0; i < header->size(); ++i) {
                    std::string h = header->at(i);
                    ss << h;
                    ss << "\r\n";
                }
            }
            return ss.str();
        }

        std::string get_domain() {
            return domain;
        }

        int get_port() {
            return port;
        }

        std::string get_http_string() {
            std::stringstream ss;
            ss << get_http_method_string();
            ss << "\r\n";
            ss << get_http_header_string();
            ss << "\r\n";
            return ss.str();
        }

    private:
        std::shared_ptr<std::vector<std::string>> header;
        std::string method;
        std::string version;
        std::string url;
        std::string protocol;
        std::string domain;
        std::string path;
        int port;

    };

    ahttp_request::ahttp_request() : impl(new ahttp_request_impl) {

    }

    void ahttp_request::append_header(std::string key, std::string value) {
        impl->append_header(key, value);
    }

    void ahttp_request::set_mothod(std::string method) {
        impl->set_mothod(method);
    }

    void ahttp_request::set_http_version(std::string version) {
        impl->set_http_version(version);
    }

    void ahttp_request::set_url(std::string url) {
        impl->set_url(url);
    }

    std::string ahttp_request::get_http_method_string() {
        return impl->get_http_method_string();
    }

    std::string ahttp_request::get_http_header_string() {
        return impl->get_http_header_string();
    }

    std::string ahttp_request::get_http_string() {
        return impl->get_http_string();
    }

    std::string ahttp_request::to_string() {
        return impl->get_http_string();
    }
    std::string ahttp_request::get_domain() {
        return impl->get_domain();
    }

    int ahttp_request::get_port() {
        return impl->get_port();
    }


    class ahttp_response::ahttp_response_impl {
    public:

        ahttp_response_impl() : buf((char*)malloc(65536)), buf_size(65536), len(0), block_num(0), status(-1),
            http_status_end_position(0), headers(new std::map<std::string, std::string>) {
        }

        ~ahttp_response_impl() {
            if (buf != nullptr) {
                free(buf);
                buf = nullptr;
            }
        }

        bool append_response_data(char* data, int len) {
            block_num ++;
            if (buf_size - this->len > len) {
                //有足够空间
            } else {
                buf = (char*)realloc(buf, len * 2);
                buf_size += len * 2;
            }
            memcpy(buf + this->len, data, len);
            this->len += len;
            bool over = is_over();
            if (over) {
                parse();
            }
            return over;
        }

        bool is_over() {
            if (len >= 6 && buf[len - 5] == '0' && buf[len - 4] == '\r' && buf[len - 3] == '\n' && buf[len - 2] == '\r' && buf[len - 1] == '\n') {
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
            for (int i = 5; i < buf_size; i += 2) {
                char c = buf[i];
                if (c == '\r' && buf[i + 1] == '\n') {
                    http_status_end_position = i + 1;
                    return std::string(buf, 0, i);
                } else if (c == '\n' && buf[i - 1] == '\r') {
                    http_status_end_position = i;
                    return std::string(buf, 0, i - 1);
                }
            }
            return "";
        }

        void parse_http_header() {
            int pre_header_item_end_pos = http_status_end_position;
            for (int i = http_status_end_position + 1; i < buf_size; i ++) {
                char c = buf[i];
                if ('\r' == c && '\n' == buf[i + 1]){
                    int key_begin, key_end, value_begin, value_end;
                    if (parse_key_value(pre_header_item_end_pos + 1, i - 1, &key_begin, &key_end, &value_begin, &value_end)) {
                        std::string k = string_parser::trim(std::string(buf, key_begin, key_end - key_begin + 1));
                        std::string v = string_parser::trim(std::string(buf, value_begin, value_end - value_begin + 1));
                        (*headers)[k] = v;
                    }

                    if ('\r' == buf[i + 2] && '\n' == buf[i + 3]) {
                        http_header_end_position = i + 3;
                        break;
                    } else {
                        pre_header_item_end_pos = i + 1;
                    }
                }
            }
        }

        bool parse_key_value(int begin, int end, int*key_begin, int* key_end, int* value_begin, int* value_end) {
            *key_begin = begin;
            *value_end = end;
            for (int i = begin; i <= end; ++i) {
                if (':' == buf[i]) {
                    *key_end = i - 1;
                    *value_begin = i + 1;
                    return true;
                }
            }
            return false;
        }

        int get_len() {
            return len;
        }

        int get_status() {
            return status;
        }

        std::string getHeader(std::string key) {
            if (headers->find(key) != headers->end()) {
                return (*headers)[key];
            }
            return "";
        }

        std::shared_ptr<std::map<std::string, std::string>> get_headers() {
            return headers;
        };

        std::string to_string() {
            return std::string(buf, len);
        }

    private:
        char* buf;
        int buf_size;
        int len;
        int block_num;
        std::string http_version;
        int status;
        int http_status_end_position;
        int http_header_end_position;
        std::shared_ptr<std::map<std::string, std::string>> headers;
    };

    ahttp_response::ahttp_response() : impl(new ahttp_response_impl) {

    }

    bool ahttp_response::append_response_data(char *data, int len) {
        return impl->append_response_data(data, len);
    }

    int ahttp_response::get_response_data_length() {
        return impl->get_len();
    }

    std::string ahttp_response::to_string() {
        return impl->to_string();
    }

    class ahttp::ahttp_impl {
    public:

        static void exec(std::shared_ptr<ahttp::ahttp_impl> http, std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            if (model != nullptr && "" != model->get_domain()) {
                uv_wrapper::resolve(model->get_domain(), model->get_port(), [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<std::vector<std::string>> ips){
                    http->send_dns_event(ccb);
                    if (ccb->success) {
                        if (ips->size() > 0) {
                            std::string ip = (*ips)[0];
                            bool need_new_connect = true;
                            if (ahttp_impl::ip_tcp_map.find(ip) != ahttp_impl::ip_tcp_map.end()) {
                                int tcp_id = ahttp_impl::ip_tcp_map[ip];
                                if (uv_wrapper::tcp_alive(tcp_id)) {
                                    tcp_http_map[tcp_id] = http;
                                    need_new_connect = false;
                                    std::string str = model->get_http_string();
                                    uv_wrapper::write(tcp_id, (char*)str.c_str(), (int)str.size(), [=](std::shared_ptr<common_callback> write_callback) {
                                        http->send_send_event(write_callback, (int)str.size());
                                    });
                                }
                            }
                            if (need_new_connect) {
                                uv_wrapper::connect(ip, model->get_port(), [=](std::shared_ptr<common_callback> ccb1, int tcp_id){
                                    ip_tcp_map[ip] = tcp_id;
                                    http->send_connected_event(ccb1);
                                    if (ccb->success) {
                                        std::string str = model->get_http_string();
                                        uv_wrapper::write(tcp_id, (char*)str.c_str(), (int)str.size(), [=](std::shared_ptr<common_callback> write_callback) {
                                            http->send_send_event(write_callback, (int)str.size());
                                        });
                                    } else {
                                        uv_wrapper::close(tcp_id);
                                    }
                                }, [=](int tcp_id, char* data, int len){
                                    if (tcp_http_map.find(tcp_id) != tcp_http_map.end()) {
                                        auto http_ = tcp_http_map[tcp_id];
                                        if (http_->append(data, len)) {
                                            tcp_http_map.erase(tcp_id);
                                            if (callback != nullptr) {
                                                callback(model, http_->response);
                                            }
                                        }
                                    }
                                    delete (data);
                                }, [=](std::shared_ptr<common_callback> disconnect_ccb, int tcp_id){
                                    std::map<std::string, int>::const_iterator it = ip_tcp_map.begin();
                                    while (it != ip_tcp_map.end()) {
                                        if (it->second == tcp_id) {
                                            break;
                                        }
                                        it ++;
                                    }
                                    if (it != ip_tcp_map.end()) {
                                        ip_tcp_map.erase(it);
                                    }
                                    if (tcp_http_map.find(tcp_id) != tcp_http_map.end()) {
                                        auto http_ = tcp_http_map[tcp_id];
                                        http_->send_disconnected_event(disconnect_ccb);
                                    }
                                });
                            }
                        }
                    }
                });
            }
        }

        void exec2(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            std::shared_ptr<ahttp_impl> self(this);
            ahttp_impl::exec(self, model, callback);
        }

        void exec(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
            if (model != nullptr && "" != model->get_domain()) {
                uv_wrapper::resolve(model->get_domain(), model->get_port(), [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<std::vector<std::string>> ips){
                    send_dns_event(ccb);
                    if (ccb->success) {
                        if (ips->size() > 0) {
                            std::string ip = (*ips)[0];
                            uv_wrapper::connect(ip, model->get_port(), [=](std::shared_ptr<common_callback> ccb1, int tcp_id) {
                                send_connected_event(ccb1);
                                if (ccb->success) {
                                    std::string str = model->get_http_string();
                                    uv_wrapper::write(tcp_id, (char *) str.c_str(), (int) str.size(), [=](std::shared_ptr<common_callback> write_callback) {
                                        send_send_event(write_callback, (int) str.size());
                                    });
                                } else {
                                    uv_wrapper::close(tcp_id);
                                }
                            }, [=](int tcp_id, char *data, int len) {
                                if (append(data, len)) {
                                    if (callback != nullptr) {
                                        callback(model, response);
                                    }
                                }
                                delete (data);
                            }, [=](std::shared_ptr<common_callback> disconnect_ccb, int tcp_id) {
                                send_disconnected_event(disconnect_ccb);
                            });
                        }
                    }
                });
            }
        }

        void set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            dns_callback = callback;
        }
        void set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            connect_callback = callback;
        }
        void set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, int bytes)> callback) {
            send_callback = callback;
        }
        void set_read_begin_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            read_begin_callback = callback;
        }
        void set_read_end_event_callback(std::function<void(std::shared_ptr<common_callback>, int bytes)> callback) {
            read_end_callback = callback;
        }
        void set_disconnected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
            disconnect_callback = callback;
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
        void send_send_event(std::shared_ptr<common_callback> callback, int bytes) {
            if (send_callback) {
                send_callback(callback, bytes);
            }
        }
        void send_read_begin_event(std::shared_ptr<common_callback> callback) {
            if (read_begin_callback) {
                read_begin_callback(callback);
            }
        }
        void send_read_end_event(std::shared_ptr<common_callback> callback, int bytes) {
            if (read_end_callback) {
                read_end_callback(callback, bytes);
            }
        }
        void send_disconnected_event(std::shared_ptr<common_callback> callback) {
            if (disconnect_callback) {
                disconnect_callback(callback);
            }
        }
        bool append(char* data, int len) {
            if (!response) {
                response.reset(new ahttp_response);
                send_read_begin_event(nullptr);
            }
            bool isEnd = response->append_response_data(data, len);
            if (isEnd) {
                send_read_end_event(nullptr, response->get_response_data_length());
            }
            return isEnd;
        }

        static std::map<std::string, int> ip_tcp_map;
        static std::map<int, std::shared_ptr<ahttp_impl>> tcp_http_map;
        std::shared_ptr<ahttp_response> response;
        std::function<void(std::shared_ptr<common_callback>)> dns_callback;
        std::function<void(std::shared_ptr<common_callback>)> connect_callback;
        std::function<void(std::shared_ptr<common_callback>, int)> send_callback;
        std::function<void(std::shared_ptr<common_callback>)> read_begin_callback;
        std::function<void(std::shared_ptr<common_callback>, int)> read_end_callback;
        std::function<void(std::shared_ptr<common_callback>)> disconnect_callback;
    };

    std::map<std::string, int> ahttp::ahttp_impl::ip_tcp_map;
    std::map<int, std::shared_ptr<ahttp::ahttp_impl>> ahttp::ahttp_impl::tcp_http_map;

    ahttp::ahttp() : impl(new ahttp_impl) {

    }

    void ahttp::exec(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->exec(model, callback);
    }

    void ahttp::exec2(std::shared_ptr<ahttp_request> model, std::function<void(std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback) {
        impl->exec2(model, callback);
    }

    void ahttp::set_dns_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_dns_event_callback(callback);
    }
    void ahttp::set_connected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_connected_event_callback(callback);
    }
    void ahttp::set_send_event_callback(std::function<void(std::shared_ptr<common_callback>, int)> callback) {
        impl->set_send_event_callback(callback);
    }

    void ahttp::set_read_begin_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_read_begin_event_callback(callback);
    }

    void ahttp::set_read_end_event_callback(std::function<void(std::shared_ptr<common_callback>, int)> callback) {
        impl->set_read_end_event_callback(callback);
    }

    void ahttp::set_disconnected_event_callback(std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->set_disconnected_event_callback(callback);
    }
}
