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

    class ssl_shake::ssl_shake_impl {
    public:
        ssl_shake_impl() {
            ssl = SSL_new(get_ssl_ctx());
            read_bio = BIO_new(BIO_s_mem());
            write_bio = BIO_new(BIO_s_mem());
            SSL_set_bio(ssl, read_bio, write_bio);
        }

        void do_shake(int fd, std::function<void(std::shared_ptr<ssl_shake>)> callback) {
            ssl = SSL_new(get_ssl_ctx());
//            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
//            SSL_set_connect_state(ssl);
//            read_bio = BIO_new(BIO_s_mem());
//            write_bio = BIO_new(BIO_s_mem());
//            SSL_set_bio(ssl, read_bio, write_bio);
            SSL_set_fd(ssl, fd);
//            int ret = SSL_do_handshake(ssl);
            int ret = SSL_connect(ssl);
//            SSL_do_handshake(ssl);
            int error = SSL_get_error(ssl, ret);
//
//            char buf[100];
//            ERR_error_string(error, buf);
            const char* e = ERR_reason_error_string(error);
//            std::string ee = std::string(e, 1000);
            std::cout << "do handshake " << e << std::endl;

//            BIO* bio = BIO_new_ssl_connect(get_ssl_ctx());
//            BIO* bio = BIO_new_socket(fd, BIO_NOCLOSE);
//            BIO* bio = BIO_new_fd(fd, BIO_NOCLOSE);
//            BIO_set_ssl(bio, ssl, )
//            BIO_get_ssl(bio, &ssl);
//            BIO_set_ssl(bio, ssl, BIO_NOCLOSE);
//            BIO_set_conn_hostname(bio, "api.chesupai.cn:443");
//            long ret = BIO_do_handshake(bio);
//            if(ret <= 0) {
                /* Handle failed connection */
//                int error = SSL_get_error(ssl, ret);
//                std::cout << "do handshake " << ERR_reason_error_string(error) << std::endl;
//            }
        }

        void read(char *data, long len, std::function<void(char *data, long len)> callback) {

        }

        void write(char *data, long len, std::function<void(char *data, long len)> callback) {

        }

        void on_connect(int tcp_id, std::function<void(std::shared_ptr<common_callback>)> callback) {
            this->tcp_id = tcp_id;
            SSL_set_connect_state(ssl);     // 这是个客户端连接
            SSL_do_handshake(ssl);
            bool finish = do_shake_finish(tcp_id);
            if (finish) {
                if (callback) {
                    std::shared_ptr<common_callback> ccb(new common_callback);
                    callback(ccb);
                }
            }
//            on_event();
        }

        void on_read(int tcp_id, char* data, long len, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<char>, long)> callback) {
            char *buf =  (char*)malloc(len);
            memcpy(buf, data, len);
            if (SSL_is_init_finished(ssl)) {

            } else {
                int written = BIO_write(read_bio, buf, len);
                if (do_shake_finish(tcp_id)) {
                    if (callback) {
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        callback(ccb, nullptr, -1);
                    }
                }
            }
        }

    private:

        void on_event() { // is called after each socket event
            char buf[1024 * 10];
            int bytes_read = 0;

            if(!SSL_is_init_finished(ssl)) {
                int r = SSL_connect(ssl);
                if(r < 0) {
                    handle_error(r);
                }
                check_outgoing_application_data();
            }
            else {
                // connect, check if there is encrypted data, or we need to send app data
                int r = SSL_read(ssl, buf, sizeof(buf));
                if(r < 0) {
                    handle_error(r);
                }
                else if(r > 0) {
//                    std::copy(buf, buf+r, std::back_inserter(c->buffer_in));
//                    std::copy(c->buffer_in.begin(), c->buffer_in.end(), std::ostream_iterator<char>(std::cout));
//                    c->buffer_in.clear();
                }
                check_outgoing_application_data();
            }
        }

        void check_outgoing_application_data() {
//            if(SSL_is_init_finished(ssl)) {
//                if(c->buffer_out.size() > 0) {
//                    std::copy(c->buffer_out.begin(), c->buffer_out.end(), std::ostream_iterator<char>(std::cout,""));
//                    int r = SSL_write(c->ssl, &c->buffer_out[0], c->buffer_out.size());
//                    c->buffer_out.clear();
//                    handle_error(c, r);
//                    flush_read_bio(c);
//                }
//            }
        }

        void handle_error(int result) {
            int error = SSL_get_error(ssl, result);
            if(error == SSL_ERROR_WANT_READ) { // wants to read from bio
                flush_read_bio();
            }
        }

        void flush_read_bio() {
            char buf[1024*16];
            int bytes_read = 0;
            while((bytes_read = BIO_read(write_bio, buf, sizeof(buf))) > 0) {
                write_to_socket(buf, bytes_read);
            }
        }

        void write_to_socket(char* buf, size_t len) {
            if(len <= 0) {
                return;
            }
            uv_wrapper::write(tcp_id, buf, len, nullptr);
//            uv_buf_t uvbuf;
//            uvbuf.base = buf;
//            uvbuf.len = len;
//            int r = uv_write(&c->write_req, (uv_stream_t*)&c->socket, &uvbuf, 1, on_written_callback);
//            if(r < 0) {
//                printf("ERROR: write_to_socket error: %s\n", uv_err_name(uv_last_error(c->socket.loop)));
//            }
        }


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
//                    char*
//                    int ret = SSL_write(ssl, , data_len);   // data中存放了要发送的数据

                    return true;
                }
                return false;
            }
            return true;
        }

        void write(int tcp_id) {
            static int buf_len = 10240;
            char* buf = (char*)malloc(buf_len);
            int bytes_read = 0;
            while((bytes_read = BIO_read(write_bio, buf, buf_len)) > 0) {
                uv_wrapper::write(tcp_id, buf, bytes_read, nullptr);
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
        int tcp_id;
    };

    ssl_shake::ssl_shake( ) : impl(new ssl_shake_impl) {

    }

    void ssl_shake::do_shake(int fd, std::function<void(std::shared_ptr<ssl_shake>)> callback) {
        impl->do_shake(fd, callback);
    }

    void ssl_shake::read(char *data, long len, std::function<void(char *data, long len)> callback) {
        impl->read(data, len, callback);
    }

    void ssl_shake::write(char *data, long len, std::function<void(char *data, long len)> callback) {
        impl->write(data, len, callback);
    }

    void ssl_shake::on_connect(int tcp_id, std::function<void(std::shared_ptr<common_callback>)> callback) {
        impl->on_connect(tcp_id, callback);
    }

    void ssl_shake::on_read(int tcp_id, char* data, long len, std::function<void(std::shared_ptr<common_callback>, std::shared_ptr<char>, long)> callback) {
        impl->on_read(tcp_id, data, len, callback);
    }
}
