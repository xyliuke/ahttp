//
//  ViewController.m
//  anet
//
//  Created by ke liu on 18/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#import <memory>
#import "ViewController.h"
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
//#include "cpprest/http_client.h"
#include "cpprest/http_client.h"
#import "ssl_shake.h"
#import "log.h"
#include <cpprest/filestream.h>
#include <openssl/ssl.h>

std::shared_ptr<plan9::ahttp> ah;
pplx::task<void> task;
@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    plan9::uv_wrapper::init(nullptr);
    plan9::uv_wrapper::set_ssl_impl([=] () -> std::shared_ptr<plan9::ssl_interface> {
        std::shared_ptr<plan9::ssl_interface> ret = std::make_shared<plan9::ssl_shake>();
        return ret;
    });
    // Do any additional setup after loading the view.
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}
- (IBAction)click_dns:(id)sender {
    using namespace web::http::client;
    using namespace web;                        // Common features like URIs.
    using namespace web::http;
    using namespace concurrency::streams;
    using namespace utility;
//    http_client client(U("http://www.baidu.com"));
//    client.request(methods::GET);
    http_client client(U("https://api.chesupai.cn"));
    task = client.request(methods::GET).then([](http_response response){
        std::cout << response.status_code();
//    Concurrency::streams::streambuf<char> buf;
        Concurrency::streams::stringstreambuf sbuffer;
        response.body().read_to_end(sbuffer);
        std::cout << sbuffer.collection();
    });
    
    task.wait();
    
    
//    pplx::task<<#typename _Type#>>

//    auto fileStream = std::make_shared<ostream>();
//    // Open stream to output file.
//    pplx::task<void> requestTask = fstream::open_ostream(U("/Users/keliu/Downloads/results.html"))
//    .then([=](ostream outFile){
//         *fileStream = outFile;
//
//         // Create http_client to send the request.
//         http_client client(U("http://www.baidu.com"));
//
//        // Build request URI and start the request.
////      uri_builder builder(U("/search"));
////      builder.append_query(U("q"), U("cpprestsdk github"));
//        return client.request(methods::GET);
//    })
//
//    // Handle response headers arriving.
//    .then([=](http_response response){
//          printf("Received response status code:%u\n", response.status_code());
//          std::cout << fileStream->streambuf().size() << std::endl;
//          // Write response body into the file.
//          return response.body().read_to_end(fileStream->streambuf());
//    })
//
//    // Close the file stream.
//    .then([=](size_t) {
//        return fileStream->close();
//    });
//
//    // Wait for all the outstanding I/O to complete and handle any exceptions
//    printf("begin\n");
//    try
//    {
//
//        requestTask.wait();
//    }
//    catch (const std::exception &e)
//    {
//        printf("Error exception:%s\n", e.what());
//    }
//    printf("end");

//    plan9::uv_wrapper::resolve("localhost"/*"www.baidu.com"*/, 443, [=](std::shared_ptr<plan9::common_callback> ccb, std::shared_ptr<std::vector<std::string>> data){
//        if (ccb->success) {
//            std::cout << "www.baidu.com" << ":" << 443 << "  resolve ip:\n";
//            for (int i = 0; i < data->size(); i ++) {
//                std::cout << (*data)[i] << "\t";
//            }
//
//        }
//    });
}

static int getNum() {
    return 4 + 5;
}

- (IBAction)click_connect:(id)sender {

    /*
    plan9::uv_wrapper::connect("10.16.8.115", 443, true, [](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
        std::cout << "connected\n";
    }, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
        std::cout << "ssl connected\n";
    }, [=](int tcp_id, std::shared_ptr<char> data, int len) {
        std::cout << "read\n";
    }, [=](std::shared_ptr<plan9::common_callback> ccb, int tcp_id){
        std::cout << "close\n";
    });
     */
    
//    std::shared_ptr<char> c(new char[1024 * 1024 * 100]{});
//    plan9::log::instance().debug(getNum());
//    plan9::log::instance().debug(std::bind(getNum));
//    plan9::log::instance().debug(std::bind([]() -> int {
//        return 5 + 4;
//    }));

    plan9::uv_wrapper::is_ip4("192.168.1.1");
    plan9::uv_wrapper::is_ip4("1.1.1.1");
    plan9::uv_wrapper::is_ip4("a.b.c.e");
    plan9::uv_wrapper::is_ip4("abce");

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

        ah->set_dns_event_callback([=](std::shared_ptr<common_callback> ccbo) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " dns " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_connected_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " connected " << tp.time_since_epoch().count() / 1000 << std::endl;
        });
        ah->set_ssl_connected_event_callback([=](std::shared_ptr<common_callback>) {
            auto tp = std::chrono::system_clock::now();
            std::cout << i << " ssl connected " << tp.time_since_epoch().count() / 1000 << std::endl;
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
//        ah->set_disconnected_event_callback([=](std::shared_ptr<common_callback>) {
//            auto tp = std::chrono::system_clock::now();
//            std::cout << i << "disconnected " << tp.time_since_epoch().count() / 1000 << std::endl;
//        });
//        ah->exec(req, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response) {
//            std::cout << request->to_string() << std::endl;
//            std::cout << response->to_string() << std::endl;
//        });
        
        std::shared_ptr<std::map<std::string, std::string>> h(new std::map<std::string, std::string>);
    (*h)["host"] = "api.chesupai.cn";
//        (*h)["Accept-Encoding"] = "gzip, deflate";
//        std::string url = "https://124.250.45.37";
    std::string url = "https://api.chesupai.cn";
//        ah->set_dns_resolve([=](std::string url, int port, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<std::vector<std::string>>)> callback) {
//            if (callback) {
//                std::shared_ptr<common_callback> ccb(new common_callback);
//                std::shared_ptr<std::vector<std::string>> list(new std::vector<std::string>);
//                list->push_back("10.16.8.115");
//                callback(ccb, list);
//            }
//        });
//        std::string url = "http://api.chesupai.cn/customer/detail/info?id=1429449&idfa=11BFBC7A-98EF-4B37-A216-E8DAF0ABAB8B&osv=iOS8.1&net=wifi&screenWH=750%252C1334&deviceId=3200A4C2-C469-469D-A42A-920B1A5A0216&deviceModel=iPhoneSimulator&platform=1&dpi=326&versionId=2.7.3&model=x86_64&pushTYpe=0&sign=9102c932d5e96cd5129b1c35f9baee28";

        ah->is_validate_domain(true);
        ah->is_validate_cert(true);
        ah->get(url, h, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response) {
//            std::cout << response->get_response_length() << std::endl;
            std::cout << response->get_body_string() << std::endl;
            std::map<std::string, std::string>::iterator it = ah->get_debug_info()->begin();
            while (it != ah->get_debug_info()->end()) {
                std::cout << it->first << ":" << it->second << std::endl;
                it ++;
            }

        });
//        ah->download("http://cn.bing.com/az/hprichbg/rb/Forest_ZH-CN16430313748_1920x1080.jpg", "/Users/keliu/Downloads/a.jpg", nullptr, [=](long current, long total){
//            std::cout << current << "/" << total << std::endl;
//        }, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response){
//            std::cout << response->to_string() << std::endl;
//        });
//    ah->upload("http://api.chesupai.cn", "/Users/keliu/Downloads/1.JPG", nullptr, nullptr, [=](std::shared_ptr<common_callback> ccb, std::shared_ptr<ahttp_request> request, std::shared_ptr<ahttp_response> response) {
//
//    });

//        if (i == 0) {
//            sleep(3);
//        }
//    }
//    ssl_shake ssl;
//    ssl.do_shake(0, nullptr);
}



- (void) ssl_connect_direct {
    int sockfd = -1;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    struct sockaddr_in dest;
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(443);
    if (inet_aton("10.16.8.115", (struct in_addr *) &dest.sin_addr.s_addr) == 0)
    {
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n\n");
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    int ret = SSL_connect(ssl);
    if (ret == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    }
}


@end
