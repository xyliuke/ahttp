//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_AHTTP1_H
#define ANET_AHTTP1_H

#include <memory>
#include "ahttp.hpp"

namespace plan9
{
    class ahttp1 {

    public:
        ahttp1();
        void exec(std::shared_ptr<ahttp_request> request, std::function<void(std::shared_ptr<common_callback>ccb, std::shared_ptr<ahttp_request>, std::shared_ptr<ahttp_response>)> callback);
    private:
        class ahttp_impl;
        std::shared_ptr<ahttp_impl> impl;
    };
}


#endif //ANET_AHTTP1_H
