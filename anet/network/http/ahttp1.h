//
// Created by ke liu on 30/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_AHTTP1_H
#define ANET_AHTTP1_H

#include <memory>

namespace plan9
{
    class ahttp1 {

    public:
        ahttp1();

    private:
        class ahttp_impl;
        std::shared_ptr<ahttp_impl> impl;
    };
}


#endif //ANET_AHTTP1_H
