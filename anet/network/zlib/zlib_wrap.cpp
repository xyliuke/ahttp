//
//  zlib_wrap.cpp
//  anet
//
//  Created by ke liu on 08/11/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#include "zlib_wrap.hpp"
#include "zlib.h"

namespace plan9 {
    unsigned long zlib_wrap::zip(char *data, unsigned long len, char *dst_data) {
        unsigned long ret = 0;
        int result = compress2((unsigned char *)ret, &ret, (unsigned char*)data, len, Z_BEST_COMPRESSION);
        if (result == Z_OK) {
            return ret;
        }
        return 0;
    }
    
    unsigned long zlib_wrap::unzip(char *data, unsigned long len, char *dst_data) {
        unsigned long ret = 0;
        int result = uncompress((unsigned char*)dst_data, &ret, (unsigned char*)data, len);
        if (result == Z_OK) {
            return ret;
        }
        return -1;
    }
}
