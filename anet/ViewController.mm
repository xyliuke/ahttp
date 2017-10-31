//
//  ViewController.m
//  anet
//
//  Created by ke liu on 18/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#import <memory>
#import "ViewController.h"
#import "atcp.hpp"
#include "uv_wrapper.hpp"
#include <vector>
#include <iostream>
#import <sstream>
#include "common_callback.hpp"
#import "ahttp.hpp"
#import "string_parser.hpp"
#include <chrono>


@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    plan9::uv_wrapper::init(nullptr);
    // Do any additional setup after loading the view.
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}
- (IBAction)click_dns:(id)sender {
    plan9::uv_wrapper::resolve("localhost"/*"www.baidu.com"*/, 443, [=](std::shared_ptr<plan9::common_callback> ccb, std::shared_ptr<std::vector<std::string>> data){
        if (ccb->success) {
            std::cout << "www.baidu.com" << ":" << 443 << "  resolve ip:\n";
            for (int i = 0; i < data->size(); i ++) {
                std::cout << (*data)[i] << "\t";
            }
            
        }
    });
}
- (IBAction)click_connect:(id)sender {
    plan9::uv_wrapper::connect("127.0.0.1", 8800, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
        std::cout << tcp_id << " connected\n";
//        plan9::uv_thread_wrap::close(tcp_id);
        plan9::uv_wrapper::write(tcp_id, "hello world", 11, [=](std::shared_ptr<plan9::common_callback> ccb){
            std::cout << "write " << ccb->success << std::endl;
        });
    }, [=](int tcp_id, char* data, int len) {
        std::cout << "read : " << std::string(data, len) << std::endl;
    }, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
        std::cout << tcp_id << " disconnected\n";
    });
}
- (IBAction)click_ssl:(id)sender {
//    plan9::ahttp_request model;
//    model.set_url("https://api.chesupai.cn/a?b=1");
//    std::string rep = "HTTP/1.1 200 OK\r\nServer: openresty\r\nDate: Mon, 23 Oct 2017 10:20:26 GMT\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PUT\r\nAccess-Control-Allow-Headers: Content-Type,PAI-TOKEN\r\n\r\n33\r\n{\"code\":-1,\"message\":\"uri match failed.\",\"data\":[]}\r\n0\r\n\r\n";
//    plan9::ahttp_response response;
//    response.set_response_string(rep);
    std::string string = "Server: openresty";
    auto ret = plan9::string_parser::split(string, ":");
    for (int i = 0; i < ret->size(); ++i) {
        std::cout << ret->at(i) << "\t";
    }
}
- (IBAction)click_send:(id)sender {

//    std::string http = plan9::ahttp::http("GET", "/", "HTTP/1.1");
//    std::shared_ptr<std::map<std::string, std::string>> h(new std::map<std::string, std::string>);
//    (*h)["Host"] = "api.chesupai.cn";
//    (*h)["Connection"] = "keep-aliver";
//    (*h)["Accept"] = "*/*";
//    (*h)["Accept-Encoding"] = "gzip, deflate, br";
//    (*h)["Accept-Language"] = "en-Us,en;q=0.9";
//    std::string header = plan9::ahttp::header(h);
//    std::stringstream ss;
//    ss << http;
//    ss << header;
//    ss << "\r\n";
//
//    std::string http_str = ss.str();

//    plan9::uv_wrapper::resolve("api.chesupai.cn", 80, [=](std::shared_ptr<plan9::common_callback> ccb, std::shared_ptr<std::vector<std::string>> data){
//        if (ccb->success && data->size() > 0) {
//            std::string ip = (*data)[0];
//            plan9::uv_wrapper::connect(ip, 80, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
//                plan9::uv_wrapper::write(tcp_id, (char*)http_str.c_str(), http_str.size(), [=](std::shared_ptr<plan9::common_callback> ccb){
//                    std::cout << "write " << ccb->success << std::endl;
//                });
//            }, [=](char* data, int len) {
//                std::cout << "read : " << std::string(data, len) << std::endl;
//            }, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
//                std::cout << tcp_id << " disconnected\n";
//            });
//        }
//    });

    auto tp = std::chrono::system_clock::now();
    std::cout << "http " << tp.time_since_epoch().count() / 1000 << std::endl;
    using namespace plan9;
    std::shared_ptr<ahttp_request> req(new ahttp_request);
    req->set_url("http://api.chesupai.cn");
//    req->set_url("http://cn.bing.com/az/hprichbg/rb/Forest_ZH-CN16430313748_1920x1080.jpg");
//    req->set_url("http://localhost:4567/hello?a=b");
//    req->set_mothod("GET");
    req->append_header("Connection", "keep-alive");
    req->append_header("Accept", "*/*");
    req->append_header("Accept-Encoding", "gzip, deflate");
    req->append_header("Accept-Language", "en-Us,en;q=0.9");
    for (int i = 0; i < 5; ++i) {
        static std::vector<std::shared_ptr<ahttp>> list;
        std::shared_ptr<ahttp> ah;
        ah.reset(new ahttp);

        list.push_back(ah);

        ah->set_dns_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " dns " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_connected_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " connected " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_send_event_callback([=](std::shared_ptr<common_callback>, int bytes) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " send " << tp.time_since_epoch().count() / 1000 << "\tsize : " << bytes << std::endl;
        });
        ah->set_read_begin_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " read begin " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_read_end_event_callback([=](std::shared_ptr<common_callback>, int bytes) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " read end " << tp.time_since_epoch().count() / 1000 << "\tsize : " << bytes << std::endl;
        });
        ah->set_disconnected_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << "disconnected " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->exec2(req, [=](std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response) {
//            std::cout << request->to_string() << std::endl;
//            std::cout << response->to_string() << std::endl;
        });
        if (i == 0) {
            sleep(3);
        }
    }
}


@end
