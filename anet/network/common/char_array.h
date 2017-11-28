//
// Created by ke liu on 28/11/2017.
// Copyright (c) 2017 ke liu. All rights reserved.
//

#ifndef ANET_CHAR_ARRAY_H
#define ANET_CHAR_ARRAY_H

#include <string>

namespace plan9 {

    class char_array {
    public:
        char_array();
        char_array(int size);
        ~char_array();
        void append(char *data, int len);
        void insert(char* data, int len, int pos);
        void erase(int pos, int len);
        int get_len();
        char* get_data();
        std::string to_string();
    private:
        char* data;
        int len;
        int cap;
    };

}


#endif //ANET_CHAR_ARRAY_H
