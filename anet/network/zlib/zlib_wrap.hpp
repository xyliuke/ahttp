//
//  zlib_wrap.hpp
//  anet
//
//  Created by ke liu on 08/11/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#ifndef zlib_wrap_hpp
#define zlib_wrap_hpp

#include <stdio.h>
#include <memory>

namespace plan9 {
    class zlib_wrap {
        static unsigned long zip(char* data, unsigned long len, char* dst_data);
        static unsigned long unzip(char* data, unsigned long len, char* dst_data);
//    private:
//        class zlib_wrap_impl;
//        std::shared_ptr<zlib_wrap_impl> impl_;
    };
}

#endif /* zlib_wrap_hpp */
