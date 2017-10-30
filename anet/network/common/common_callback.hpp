//
//  common_callback.hpp
//  anet
//
//  Created by ke liu on 19/10/2017.
//  Copyright © 2017 ke liu. All rights reserved.
//

#ifndef common_callback_hpp
#define common_callback_hpp

#include <stdio.h>
#include <string>

namespace plan9
{
    
class common_callback {
public:
    common_callback(bool success_, int error_code_, std::string reason_) : success(success_), error_code(error_code_), reason(reason_) {
    }

    common_callback() : success(true), error_code(0), reason("success"){
    }

    bool success;
    int error_code;
    std::string reason;
};
    
}

#endif /* common_callback_hpp */
