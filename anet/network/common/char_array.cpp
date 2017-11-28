//
// Created by ke liu on 28/11/2017.
// Copyright (c) 2017 ke liu. All rights reserved.
//

#include <cstdlib>
#include <cstring>
#include "char_array.h"

namespace plan9
{
    char_array::char_array() : len(0), cap(1024) {
    }
    char_array::char_array(int size) :len(0), cap(size){
    }
    char_array::~char_array() {
        len = 0;
        cap = 0;
    }
    void char_array::append(char *data, int len) {
        re_data();
        memcpy(this->data.get() + this->len, data, len);
        this->len += len;
    }
    void char_array::insert(char *data, int len, int pos) {
        re_data();
        memmove(this->data.get() + pos + len, this->data.get() + pos, this->len - pos);
        memcpy(this->data.get() + pos, data, len);
        this->len += len;
    }
    void char_array::erase(int pos, int len) {
        memcpy(this->data.get() + pos, this->data.get() + pos + len, this->len - pos - len);
        this->len -= len;
    }
    char* char_array::get_data() {
        return data.get();
    }
    int char_array::get_len() {
        return len;
    }

    std::string char_array::to_string() {
        return std::string(data.get(), len);
    }

    void char_array::re_data() {
        if (data == nullptr) {
            data.reset((char*) malloc(cap));
        }
        if (cap - this->len < len) {
            cap += (len << 1);
            char* nd = (char*)realloc(this->data.get(), cap);
            this->data.reset(nd);
        }
    }

}