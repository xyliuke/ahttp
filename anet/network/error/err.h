//
// Created by ke liu on 27/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_ERR_H
#define ANET_ERR_H

#include <string>
#include "uv.h"

namespace plan9
{
#define ERR_TABLE  \
    X(E_TIME_OUT, "time out")   \
    X(E_DNS_RESOLVE, "dns resolve error")

    typedef enum {
        E_SUCCESS,
#define X(a, b) a,
    ERR_TABLE
#undef X
        NUM_ERR
    } err_no;

    std::string get_err_msg(err_no e);
}


#endif //ANET_ERR_H
