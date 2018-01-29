//
// Created by ke liu on 27/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#ifndef ANET_STATE_MACHINE_H
#define ANET_STATE_MACHINE_H

#include <functional>
#include <vector>
#include <map>
#include <string>

namespace plan9 {
    //TODO 实现简单的状态机
    //TODO 并能跨语言调用
    class state_machine;
    class state;


    class state {
    public:
        virtual void on_entry(int event, state_machine& fsm) {}
        virtual void on_exit(int event, state_machine& fsm) {}
    };

#define T_ROW(begin, event, end, action) transition_row::get<begin, end>(event, action)


    class transition_row {
    private:

    public:

        template <typename B, typename E>
        static std::shared_ptr<transition_row> get(int event, std::function<bool(state_machine&)> action) {
            std::shared_ptr<transition_row> ret = std::make_shared<transition_row>(event, action);
            ret->set_state<B, E>();
            return ret;
        }

        /**
         * 定义一个迁移的事件
         * @param event 迁移的事件
         * @param action 迁移的动作，返回true表示同意迁移，返回false表示不同意迁移
         */
        transition_row(const int event, std::function<bool(state_machine&)> action)
                : event_(event), action_(action) {
        }
        /**
         * 设置移动的起始和终止状态
         * @tparam B 一条迁移的起始状态类型
         * @tparam E 一条迁移的终止起始状态
         */
        template <typename B, typename E>
        void set_state() {
            b_hash_code = typeid(B).hash_code();
            e_hash_code = typeid(E).hash_code();
            if (map_.find(b_hash_code) == map_.end()) {
                map_[b_hash_code] = std::make_shared<B>();
            }
            if (map_.find(e_hash_code) == map_.end()) {
                map_[e_hash_code] = std::make_shared<E>();
            }
        }

        bool is_match(int event, size_t begin) {
            return event_ == event && begin == b_hash_code;
        }

        bool exec_action(state_machine& fsm) {
            if (action_) {
                return action_(fsm);
            }
            return true;
        }

        size_t get_end() {
            return e_hash_code;
        }

        static std::shared_ptr<state> get(size_t hash_code) {
            std::shared_ptr<state> ret;
            if (map_.find(hash_code) != map_.end()) {
                return map_[hash_code];
            }
            return ret;
        }

    private:
        size_t b_hash_code;
        size_t e_hash_code;
        const int event_;
        const std::function<bool(state_machine&)> action_;
        static std::map<size_t, std::shared_ptr<state>> map_;
    };

    class state_machine {
    public:
        std::vector<std::shared_ptr<transition_row>> rows;
        template <typename T>
        void set_init_state() {
            current = typeid(T).hash_code();
        }
        void process_event(int event);
        virtual void no_transition(std::shared_ptr<state> begin, int event);
    private:
        size_t current;
    };
}


#endif //ANET_STATE_MACHINE_H
