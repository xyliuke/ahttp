//
// Created by ke liu on 27/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include "state_machine.h"

namespace plan9
{
    std::map<size_t, std::shared_ptr<state>> transition_row::map_;

    void state_machine::process_event(int event) {
        std::shared_ptr<state> c_state;
        bool exist = false;
        for (int i = 0; i < rows.size(); ++i) {
            auto row = rows[i];
            if (row->is_match(event, current)) {
                exist = true;
                if (row->exec_action(*this)) {
                    auto c = transition_row::get(current);
                    if (c) {
                        c->on_exit(event, *this);
                    }

                    current = row->get_end();
                    c_state = transition_row::get(current);
                    if (c_state) {
                        c_state->on_entry(event, *this);
                    }
                }
                break;
            }
        }
        if (!exist) {
            no_transition(c_state, event);
        }
    }

    void state_machine::no_transition(std::shared_ptr<state> begin, int event) {
    }
}