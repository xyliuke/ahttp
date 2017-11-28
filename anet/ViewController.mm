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
#import "zlib_wrap.hpp"
#include <chrono>
#import <fstream>
#include "case_insensitive_map.h"
#import "char_array.h"

std::shared_ptr<plan9::ahttp> ah;

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

    using namespace plan9;
//    case_insensitive_map map;
//    map.add("a", "b");
//    map.add("A", "bb");
//    bool find;
//    std::string ret = map.get("a", &find);
//    ret = map.get("A", &find);

    char_array array(10);
    array.append("hello world", 11);
    std::cout << array.to_string() << std::endl;
    array.append("abcdefg", 7);
    std::cout << array.to_string() << std::endl;
    array.insert("123", 3, 5);
    std::cout << array.to_string() << std::endl;
    array.erase(2, 4);
    std::cout << array.to_string() << std::endl;

//    plan9::uv_wrapper::connect("127.0.0.1", 8800, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
//        std::cout << tcp_id << " connected\n";
//        plan9::uv_wrapper::write(tcp_id, "hello world", 11, [=](std::shared_ptr<plan9::common_callback> ccb){
//            std::cout << "write " << ccb->success << std::endl;
//        });
//    }, [=](int tcp_id, char* data, int len) {
//        std::cout << "read : " << std::string(data, len) << std::endl;
//    }, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
//        std::cout << tcp_id << " disconnected\n";
//    });
}
- (IBAction)click_ssl:(id)sender {
//    plan9::ahttp_request model;
//    model.set_url("https://api.chesupai.cn/a?b=1");
//    std::string rep = "HTTP/1.1 200 OK\r\nServer: openresty\r\nDate: Mon, 23 Oct 2017 10:20:26 GMT\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS, DELETE, PUT\r\nAccess-Control-Allow-Headers: Content-Type,PAI-TOKEN\r\n\r\n33\r\n{\"code\":-1,\"message\":\"uri match failed.\",\"data\":[]}\r\n0\r\n\r\n";
//    plan9::ahttp_response response;
//    response.set_response_string(rep);
//    std::string string = "Server: openresty";
//    auto ret = plan9::string_parser::split(string, ":");
//    for (int i = 0; i < ret->size(); ++i) {
//        std::cout << ret->at(i) << "\t";
//    }
//    plan9::ahttp_request request;
//    std::shared_ptr<std::map<std::string, std::string>> data(new std::map<std::string, std::string>);
//    (*data)["a"] = "b";
//    (*data)["c"] = "d";
//    request.append_body_data(data);
//    std::string d = request.get_http_string();

//    auto tp = std::chrono::system_clock::now();
//    std::cout << " timer " << tp.time_since_epoch().count() / 1000 << std::endl;
//    plan9::uv_wrapper::post_timer([=](){
//        auto tp = std::chrono::system_clock::now();
//        std::cout << " timer " << tp.time_since_epoch().count() / 1000 << std::endl;
//    }, 5000, 0);
//    int d = plan9::string_parser::dex_to_dec("12", 2);
//    d = plan9::string_parser::dex_to_dec("1A", 2);
//    d = plan9::string_parser::dex_to_dec("DA", 2);
    std::string data = "aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccc";
//    data = "hello";
    char *buf = (char*)malloc(100);
    unsigned long ret = plan9::zlib_wrap::gzip((char*)data.c_str(), data.length(), buf, 100);
    char buf1[100];
    unsigned long r = plan9::zlib_wrap::ungzip(buf, ret, buf1, 100);
    unsigned long len = 0;
    char* rr = plan9::zlib_wrap::ungzip(buf, ret, &len);
}
- (IBAction)click_send:(id)sender {

    std::cout << "click send \n";

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
//    req->set_url("http://api.chesupai.cn");
    req->set_url("http://cn.bing.com/az/hprichbg/rb/Forest_ZH-CN16430313748_1920x1080.jpg");
//    req->set_url("http://localhost:4567/hello?a=b");
//    req->set_method("POST");
    req->append_header("Connection", "keep-alive");
    req->append_header("Accept", "*/*");
    req->append_header("Accept-Encoding", "gzip, deflate");
    req->append_header("Accept-Language", "en-Us,en;q=0.9");
//    req->append_body_data("a", "b");
//    std::ofstream ofstream;
//    ofstream.open("/Users/keliu/Downloads/a.txt", std::ios::app | std::ios::in);
//    ofstream.write("123", 3);
//    ofstream.flush();
//    ofstream.close();
//    req->set_timeout(5);
    int i = 0;
//    for (int i = 0; i < 1; ++i) {
//        static std::vector<std::shared_ptr<ahttp>> list;
//        std::shared_ptr<ahttp> ah;
        ah.reset(new ahttp);

//    ah.reset();
//        list.push_back(ah);

        ah->set_dns_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " dns " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_connected_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " connected " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_send_event_callback([=](std::shared_ptr<common_callback>, int bytes, long total) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " send " << tp.time_since_epoch().count() / 1000 << "\tsize : " << bytes << std::endl;
        });
        ah->set_read_event_callback([=](std::shared_ptr<common_callback>, long bytes) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " read " << tp.time_since_epoch().count() / 1000 << "\tsize : " << bytes << std::endl;
        });
        ah->set_read_begin_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " read begin " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_read_end_event_callback([=](std::shared_ptr<common_callback>, long bytes) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " read end " << tp.time_since_epoch().count() / 1000 << "\tsize : " << bytes << std::endl;
        });
        ah->set_disconnected_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << "disconnected " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
//        ah->exec(req, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response) {
//            std::cout << request->to_string() << std::endl;
//            std::cout << response->to_string() << std::endl;
//        });
        
        std::shared_ptr<std::map<std::string, std::string>> h(new std::map<std::string, std::string>);
        (*h)["Accept-Encoding"] = "gzip, deflate";
        std::string url = "http://api.chesupai.cn";
//        std::string url = "http://api.chesupai.cn/customer/detail/info?id=1429449&idfa=11BFBC7A-98EF-4B37-A216-E8DAF0ABAB8B&osv=iOS8.1&net=wifi&screenWH=750%252C1334&deviceId=3200A4C2-C469-469D-A42A-920B1A5A0216&deviceModel=iPhoneSimulator&platform=1&dpi=326&versionId=2.7.3&model=x86_64&pushTYpe=0&sign=9102c932d5e96cd5129b1c35f9baee28";
        ah->get(url, h, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response) {
            std::cout << response->get_response_length() << std::endl;
            std::cout << response->get_body_string() << std::endl;
        });
//        ah->download("http://cn.bing.com/az/hprichbg/rb/Forest_ZH-CN16430313748_1920x1080.jpg", "/Users/keliu/Downloads/a.jpg", nullptr, [=](long current, long total){
//            std::cout << current << "/" << total << std::endl;
//        }, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response){
//            std::cout << response->to_string() << std::endl;
//        });
//        if (i == 0) {
//            sleep(3);
//        }
//    }
}


@end
