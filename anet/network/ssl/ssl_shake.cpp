//
// Created by ke liu on 16/12/2017.
// Copyright (c) 2017 ke liu. All rights reserved.
//

#include "ssl_shake.h"
#include <openssl/ssl.h>
#include <assert.h>
#include <iostream>
#include <openssl/err.h>

namespace plan9
{
#define WHERE_INFO(ssl, w, flag, msg) { \
    if(w & flag) { \
      printf("\t"); \
      printf(msg); \
      printf(" - %s ", SSL_state_string(ssl)); \
      printf(" - %s ", SSL_state_string_long(ssl)); \
      printf("\n"); \
    }\
 }

    static void dummy_ssl_info_callback(const SSL* ssl, int where, int ret) {
        if(ret == 0) {
            printf("dummy_ssl_info_callback, error occured.\n");
            return;
        }
        WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
        WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
        WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
        WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
        WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
        WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
    }

    static void dummy_ssl_msg_callback(int writep ,int version ,int contentType ,const void* buf
            ,size_t len ,SSL* ssl ,void *arg ) {
        printf("\tMessage callback with length: %zu   write %d version %d contentType %d \n", len, writep, version, contentType);
//        std::cout << "\tMessage callback " << std::string((char*)buf, len);
    }

    //TODO 需要解决内存泄露问题，将各个接口传递char*的方面进行修改
    class ssl_shake::ssl_shake_impl {
    public:
        ssl_shake_impl() : buf((char*)malloc(buf_len)) {
            ssl = SSL_new(get_ssl_ctx());
            read_bio = BIO_new(BIO_s_mem());
            write_bio = BIO_new(BIO_s_mem());
            SSL_set_bio(ssl, read_bio, write_bio);
        }

        ~ssl_shake_impl() {
            if (buf != nullptr) {
                delete buf;
                buf = nullptr;
            }
            if (ssl != nullptr) {
                SSL_free(ssl);
                ssl = nullptr;
            }
        }

        void write(char *data, long len, std::function<void(std::shared_ptr<common_callback>, char *data, long len)> callback) {
            if (callback) {
                if (ssl && write_bio) {
                    int ret = SSL_write(ssl, data, len);
                    if (ret > 0) {
                        int bytes_read = 0;
                        while((bytes_read = BIO_read(write_bio, buf, buf_len)) > 0) {
                            std::shared_ptr<common_callback> ccb(new common_callback);
                            callback(ccb, buf, bytes_read);
                        }
                        return;
                    }
                }
                std::shared_ptr<common_callback> ccb(new common_callback(false, -1, "ssl write error"));
                callback(ccb, nullptr, -1);
            }
        }

        void on_connect(int tcp_id, std::function<void(std::shared_ptr<common_callback>)> callback) {
            SSL_set_connect_state(ssl);     // 这是个客户端连接
            SSL_do_handshake(ssl);
            bool finish = do_shake_finish(tcp_id);
            if (finish) {
                if (callback) {
                    std::shared_ptr<common_callback> ccb(new common_callback);
                    callback(ccb);
                }
            }
        }

        void on_read(int tcp_id, char* data, long len, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<char>, long)> callback) {
            if (SSL_is_init_finished(ssl)) {
                if (callback) {
                    int ret = BIO_write(read_bio, data, len);
                    if (ret >= 0) {
                        static int num = 10240;
                        std::shared_ptr<char> buf((char*) malloc(num));
                        ret = SSL_read(ssl, buf.get(), num);
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        if (ret < 0) {
                            ccb->success = false;
                            ccb->error_code = -1;
                            ccb->reason = "ssl read error";
                        } else if (ret == 0){
                            ccb->success = false;
                            ccb->error_code = -2;
                            ccb->reason = "ssl close";
                        }
                        callback(ccb, buf, ret);
                    }
                }
            } else {
//                char *buf =  (char*)malloc(len);
//                memcpy(buf, data, len);
                int written = BIO_write(read_bio, data, len);

                if (written > 0 && do_shake_finish(tcp_id)) {
                    if (callback) {
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        callback(ccb, nullptr, -1);
                    }
                }
            }
        }

        void validate_domain(std::function<bool()> callback) {
            validate_domain_cb = callback;
        }

        void allow_invalid_cert(std::function<bool()> callback) {
            allow_invalid_cert_cb = callback;
        }


    private:
        bool do_shake_finish(int tcp_id) {
            if (!SSL_is_init_finished(ssl)) {
                int ret = SSL_connect(ssl);     // 开始握手。这个
                write(tcp_id);
                if (ret != 1) {
                    int err = SSL_get_error(ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        write(tcp_id);
                    } else if (err == SSL_ERROR_WANT_WRITE) {
                    }
                } else {
                    return true;
                }
                return false;
            }
            return true;
        }

        void write(int tcp_id) {
            int bytes_read = 0;
            while((bytes_read = BIO_read(write_bio, buf, buf_len)) > 0) {
                uv_wrapper::write_uv(tcp_id, buf, bytes_read, nullptr);
            }
        };

        static SSL_CTX* get_ssl_ctx() {
            static SSL_CTX* ctx = nullptr;
            if (!ctx) {
                SSL_library_init();
                OpenSSL_add_all_algorithms();
                SSL_load_error_strings();
                ERR_load_BIO_strings();
                ctx = SSL_CTX_new(SSLv23_client_method());
                SSL_CTX_set_info_callback(ctx, dummy_ssl_info_callback);
                SSL_CTX_set_msg_callback(ctx, dummy_ssl_msg_callback);
//                SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
//                SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
                assert(ctx);
            }
            return ctx;
        }
    private:
        SSL* ssl;
        BIO* read_bio;
        BIO* write_bio;
        char* buf;
        static int buf_len;
        std::function<bool()> validate_domain_cb;
        std::function<bool()> allow_invalid_cert_cb;
    };
    int ssl_shake::ssl_shake_impl::buf_len = 10240;

    ssl_shake::ssl_shake( ) : impl(new ssl_shake_impl) {

    }

    void ssl_shake::write(char *data, long len, std::function<void(std::shared_ptr<common_callback>, char *data, long len)> callback) {
        impl->write(data, len, callback);
    }

    void ssl_shake::on_connect(int tcp_id, std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->on_connect(tcp_id, callback);
    }

    void ssl_shake::on_read(int tcp_id, char* data, long len, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<char>, long)> callback) {
        impl->on_read(tcp_id, data, len, callback);
    }

    void ssl_shake::validate_domain(std::function<bool()> callback) {
        impl->validate_domain(callback);
    }

    void ssl_shake::allow_invalid_cert(std::function<bool()> callback) {
        impl->allow_invalid_cert(callback);
    }
}
