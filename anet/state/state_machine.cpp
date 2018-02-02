//
// Created by ke liu on 27/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include <sstream>
#include "state_machine.h"

namespace plan9
{
    std::map<state_machine*, std::shared_ptr<std::map<size_t, std::shared_ptr<state>>>> transition_row::map_;

    state::state() {
    }

    const std::type_info& state::get_type() {
        return typeid(this);
    }

    void transition_row::set_trace(const std::type_info &t1, const std::type_info &t2) {
        std::stringstream ss;
        ss << t1.name();
        ss <<  " -> ";
        ss << event_;
        ss << " -> ";
        ss <<  t2.name();
        trace = ss.str();
    }

    state_machine::state_machine() : current(0), rows(std::make_shared<std::vector<std::shared_ptr<transition_row>>>()),
                                     trace(std::make_shared<std::vector<std::shared_ptr<transition_row>>>()){

    }

    state_machine::~state_machine() {
        transition_row::remove(this);
    }

    void state_machine::start() {
        if (current > 0) {
            auto c = transition_row::get(this, current);
            if (c) {
                c->on_entry("no_event", this);
            }
        }
    }

    void state_machine::process_event(std::string event) {
        bool exist = false;
        for (int i = 0; i < rows->size(); ++i) {
            auto row = (*rows)[i];
            if (row->is_match(event, current)) {
                exist = true;
                if (row->exec_action(this)) {
                    trace->push_back(row);
                    auto c_state = transition_row::get(this, current);
                    if (c_state) {
                        c_state->on_exit(event, this);
                    }

                    current = row->get_end();
                    auto n_state = transition_row::get(this, current);
                    if (n_state) {
                        n_state->on_entry(event, this);
                    }
                    break;
                }
            }
        }
        if (!exist) {
            no_transition(transition_row::get(this, current), event);
        }
    }

    void state_machine::no_transition(std::shared_ptr<state> begin, std::string event) {
    }

    std::string state_machine::get_trace() {
        std::stringstream ss;
        auto it = trace->begin();
        while (it != trace->end()) {
            ss << (*it)->to_string();
            ss << "\n";
            it ++;
        }
        return ss.str();
    }
}