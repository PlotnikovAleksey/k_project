// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include "emitter.hpp"

void Emitter::emit_info_signal(int type, std::string str) {
    emit info_signal(type, str);
}

void Emitter::emit_full(std::string data) {
    emit full_signal(data);
}

void Emitter::emit_hex(std::string data) {
    emit hex_signal(data);
}

void Emitter::emit_ascii(std::string data) {
    emit ascii_signal(data);
}

void Emitter::emit_users_signal(std::string users){
    emit users_signal(users);
}
