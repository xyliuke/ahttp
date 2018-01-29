//
// Created by ke liu on 27/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_STATE_MACHINE_H
#define ANET_STATE_MACHINE_H

#include <functional>

namespace plan9 {
    //TODO 实现简单的状态机
    class state_machine;
    class state;


    class event {
    public:

    };

    class state {
    public:
        void on_entry(event event, state_machine fsm);
        void on_exit(event event, state_machine fsm);
    };

    class transition_row {
        transition_row(std::shared_ptr<state> begin, std::shared_ptr<event> event, std::shared_ptr<state> end, std::function<bool(state_machine&)> action);
    };

    class transition_table {
    public:

    };


    class state_machine {
    public:

    };
}


#endif //ANET_STATE_MACHINE_H
