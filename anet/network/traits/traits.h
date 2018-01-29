//
// Created by ke liu on 29/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_TRAITS_H
#define ANET_TRAITS_H

namespace plan9
{
    template <typename I>
    class traits {
    public:
        typedef typename I::value_type value_type;
        typedef typename I::pointer pointer;
        typedef typename I::reference reference;
    };
    template <typename T>
    class traits<T*> {
    public:
        typedef T value_type;
    };
}


#endif //ANET_TRAITS_H
