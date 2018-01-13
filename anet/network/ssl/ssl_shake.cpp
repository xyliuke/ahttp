//
// Created by ke liu on 16/12/2017.
// Copyright (c) 2017 ke liu. All rights reserved.
//

#include "ssl_shake.h"
#include <openssl/ssl.h>
#include <assert.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <map>


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
//    static std::map<ssl_shak


//    static int verify_callback(int ok, X509_STORE_CTX* ctx) {
////        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
////        int cert_err = X509_verify_cert(ctx);
////        const char* area = X509_get_default_cert_area();
////        const char* dir = X509_get_default_cert_dir();
////        const char* dir_env = X509_get_default_cert_dir_env();
////        const char* file = X509_get_default_cert_file();
////        const char* file_env = X509_get_default_cert_file_env();
////        const char* pri_dir = X509_get_default_private_dir();
//
//        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
//        BIO* bio = BIO_new(BIO_s_mem());
//        X509_print(bio, cert);
//        char buf[10240];
//        int ret = BIO_read(bio, buf, 10240);
//        printf("%s", buf);
////        X509_NAME* name = X509_get_subject_name(cert);
////        ASN1_BIT_STRING *bit_string = X509_get0_pubkey_bitstr(cert);
////        X509_get0_signature(&bit_string, 0, cert);
////        int count = X509_get_ext_count(cert);
////        for (int i = 0; i < count; ++i) {
////            X509_EXTENSION* extension = X509_get_ext(cert, i);
////            printf("extentsion %s\n", extension->value->data);
////        }
////        X509_NAME* issuer = X509_get_issuer_name(cert);
////        X509_NAME* sub = X509_get_subject_name(cert);
////        ASN1_INTEGER* sn = X509_get_serialNumber(cert);
////        EVP_PKEY* pub_key = X509_get_pubkey(cert);
////        int nid = X509_get_signature_nid(cert);
//
//        SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
////        if (ssl_shake::ssl_shake_impl::ssl_impl_map.find(ssl) != ssl_shake::ssl_shake_impl::ssl_impl_map::end()) {
////
////        }
////        SSL_ex_data
//
//        int  err = X509_STORE_CTX_get_error(ctx);
//        if (err == X509_V_ERR_HOSTNAME_MISMATCH) {
//            return 0;
//        }
////        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
//        return 1;
//
////        char data[256];
////            fprintf(stderr, "verify_callback\n{\n");
////            X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
////            int  depth = X509_STORE_CTX_get_error_depth(ctx);
////            int  err = X509_STORE_CTX_get_error(ctx);
////
//////        X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) cert), -1);
////
////        X509_NAME* name = X509_get_subject_name(cert);
////        fprintf(stderr, "certificate at depth: %i\n", depth);
////            memset(data, 0, sizeof(data));
////            X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
////            fprintf(stderr, "issuer = %s\n", data);
////            X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
////            fprintf(stderr, "subject = %s\n", data);
////            fprintf(stderr, "error status:  %i:%s\n}\n", err, X509_verify_cert_error_string(err));
////        return 1;
//
////        char    buf[256];
////        X509   *err_cert;
////        int     err, depth;
////        SSL    *ssl;
//////        mydata_t *mydata;
////
////
////        err_cert = X509_STORE_CTX_get_current_cert(ctx);
////        auto name = X509_get_subject_name(err_cert);
////        X509_VERIFY_PARAM_get0_peername(<#X509_VERIFY_PARAM*#>)
////        err = X509_STORE_CTX_get_error(ctx);
////        depth = X509_STORE_CTX_get_error_depth(ctx);
////
////        /*
////         * Retrieve the pointer to the SSL of the connection currently treated
////         * and the application specific data stored into the SSL object.
////         */
////        ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
//////        mydata = SSL_get_ex_data(ssl, mydata_index);
////
////        X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
////
////        /*
////         * Catch a too long certificate chain. The depth limit set using
////         * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
////         * that whenever the "depth>verify_depth" condition is met, we
////         * have violated the limit and want to log this error condition.
////         * We must do it here, because the CHAIN_TOO_LONG error would not
////         * be found explicitly; only errors introduced by cutting off the
////         * additional certificates would be logged.
////         */
//////        if (depth > mydata->verify_depth) {
//////            preverify_ok = 0;
//////            err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
//////            X509_STORE_CTX_set_error(ctx, err);
//////        }
//////        if (!preverify_ok) {
//////            printf("verify error:num=%d:%s:depth=%d:%s\n", err,
//////                    X509_verify_cert_error_string(err), depth, buf);
//////        } else if (mydata->verbose_mode) {
//////            printf("depth=%d:%s\n", depth, buf);
//////        }
////
////        /*
////         * At this point, err contains the last verification error. We can use
////         * it for something special
////         */
//////        if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
//////            X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
//////            printf("issuer= %s\n", buf);
//////        }
//////
//////        if (mydata->always_continue)
//////            return 1;
//////        else
////            return preverify_ok;
//    }
//    static int verify_cert_callback(X509_STORE_CTX* ctx, void* args) {
////        auto list = SSL_get_client_CA_list((SSL*)args);
////        auto tree = X509_STORE_CTX_get0_policy_tree(ctx);
////        X509_
////        auto chain = X509_STORE_CTX_get1_chain(ctx);
////        X509* x509 = SSL_get_peer_certificate((SSL*)args);
//
////        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
////        BIO* bio = BIO_new(BIO_s_mem());
////        X509_print(bio, cert);
////        char buf[10240];
////        int ret = BIO_read(bio, buf, 10240);
////        printf("%s", buf);
////        X509_NAME* name = X509_get_subject_name(cert);
////        ASN1_BIT_STRING *bit_string = X509_get0_pubkey_bitstr(cert);
////        X509_get0_signature(&bit_string, 0, cert);
////        int count = X509_get_ext_count(cert);
////        for (int i = 0; i < count; ++i) {
////            X509_EXTENSION* extension = X509_get_ext(cert, i);
////            printf("extentsion %s\n", extension->value->data);
////        }
////        X509_NAME* issuer = X509_get_issuer_name(cert);
////        X509_NAME* sub = X509_get_subject_name(cert);
////        ASN1_INTEGER* sn = X509_get_serialNumber(cert);
////        EVP_PKEY* pub_key = X509_get_pubkey(cert);
////        int nid = X509_get_signature_nid(cert);
//
//
//        int  err = X509_STORE_CTX_get_error(ctx);
//        if (err == X509_V_ERR_HOSTNAME_MISMATCH) {
//            return 0;
//        }
////        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
//        return 1;
//    }


    class ssl_shake::ssl_shake_impl {
    public:

        static std::map<SSL*, ssl_shake_impl*> ssl_impl_map;

        static int verify_callback(int ok, X509_STORE_CTX* ctx) {
//        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
//        BIO* bio = BIO_new(BIO_s_mem());
//        X509_print(bio, cert);
//        char buf[10240];
//        int ret = BIO_read(bio, buf, 10240);
//        printf("%s", buf);

            bool validate_domain = false;
            bool validate_cert = false;
            SSL* ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
            if (ssl_impl_map.find(ssl) != ssl_impl_map.end()) {
                ssl_shake_impl* impl = ssl_impl_map[ssl];
                if (impl->validate_domain_bool) {
                    validate_domain = true;
                }
            }

            int  err = X509_STORE_CTX_get_error(ctx);
            if (err == X509_V_ERR_HOSTNAME_MISMATCH && validate_domain) {
                return 0;
            }
            return 1;
        }

        ssl_shake_impl() : buf((char*)malloc(buf_len)), ctx(nullptr), validate_cert_bool(false), validate_domain_bool(false) {
            ssl = SSL_new(get_ssl_ctx());
            read_bio = BIO_new(BIO_s_mem());
            write_bio = BIO_new(BIO_s_mem());
            SSL_set_bio(ssl, read_bio, write_bio);
            SSL_set_verify_depth(ssl, 2);
            ssl_impl_map[ssl] = this;
//            SSL_CTX_set_cert_verify_callback(get_ssl_ctx(), verify_cert_callback, this);
        }

        ~ssl_shake_impl() {
            if (ssl_impl_map.find(ssl) != ssl_impl_map.end()) {
                ssl_impl_map.erase(ssl);
            }
            if (buf != nullptr) {
                delete buf;
                buf = nullptr;
            }
            if (ssl != nullptr) {
                SSL_free(ssl);
                ssl = nullptr;
            }
        }
        void set_host(std::string host) {
            SSL_set_tlsext_host_name(ssl, host.c_str());
            X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0);
//            X509_VERIFY_PARAM_set1_host(param, "guazi.com", 0);
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
                int written = BIO_write(read_bio, data, len);
                if (written > 0 && do_shake_finish(tcp_id)) {
                    if (callback) {
                        std::shared_ptr<common_callback> ccb(new common_callback);
                        callback(ccb, nullptr, -1);
                    }
                }
            }
        }

        void validate_domain(bool validate) {
            validate_domain_bool = validate;
        }

        void validate_cert(bool validate) {
            validate_cert_bool = validate;
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

        SSL_CTX* get_ssl_ctx() {
            if (!ctx) {
                SSL_library_init();
                OpenSSL_add_all_algorithms();
                SSL_load_error_strings();
                ERR_load_BIO_strings();
                ctx = SSL_CTX_new(SSLv23_client_method());
                SSL_CTX_set_info_callback(ctx, dummy_ssl_info_callback);
                SSL_CTX_set_msg_callback(ctx, dummy_ssl_msg_callback);
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
                X509_STORE* store = SSL_CTX_get_cert_store(ctx);
                int count = X509_PURPOSE_get_count();
                int vp_count = X509_VERIFY_PARAM_get_count();
                assert(ctx);
            }
            return ctx;
        }
//    private:
        SSL_CTX* ctx;
        SSL* ssl;
        BIO* read_bio;
        BIO* write_bio;
        char* buf;
        static int buf_len;
        bool validate_domain_bool;
        bool validate_cert_bool;
    };

    int ssl_shake::ssl_shake_impl::buf_len = 10240;
    std::map<SSL*, ssl_shake::ssl_shake_impl*> ssl_shake::ssl_shake_impl::ssl_impl_map;

    ssl_shake::ssl_shake( ) : impl(new ssl_shake_impl) {

    }

    void ssl_shake::set_host(std::string host) {
        impl->set_host(host);
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

    void ssl_shake::validate_domain(bool validate) {
        impl->validate_domain(validate);
    }

    void ssl_shake::validate_cert(bool validate) {
        impl->validate_cert(validate);
    }
}
