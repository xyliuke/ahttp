//
// Created by ke liu on 28/11/2017.
// Copyright (c) 2017 ke liu. All rights reserved.
//

#include <cstdlib>
#include <cstring>
#include "char_array.h"

namespace plan9
{
    char_array::char_array() : len(0), cap(1024), data((char*) malloc(cap)){
    }
    char_array::char_array(int size) :len(0), cap(size), data((char*) malloc(cap)){
    }
    char_array::~char_array() {
        delete data;
        data = nullptr;
        len = 0;
        cap = 0;
    }
    void char_array::append(char *data, int len) {
        if (cap - this->len < len) {
            cap += (len << 1);
            this->data = (char*)realloc(this->data, cap);
        }
        memcpy(this->data + this->len, data, len);
        this->len += len;
    }
    void char_array::insert(char *data, int len, int pos) {
        if (cap - this->len < len) {
            cap += (len << 1);
            this->data = (char*)realloc(this->data, cap);
        }
        memmove(this->data + pos + len, this->data + pos, this->len - pos);
        memcpy(this->data + pos, data, len);
        this->len += len;
    }
    void char_array::erase(int pos, int len) {
        memcpy(this->data + pos, this->data + pos + len, this->len - pos - len);
        this->len -= len;
    }
    char* char_array::get_data() {
        return data;
    }
    int char_array::get_len() {
        return len;
    }

    std::string char_array::to_string() {
        return std::string(data, len);
    }


}