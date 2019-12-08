// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#ifndef EMITTER_HPP
#define EMITTER_HPP

#include <QObject>
#include <string>
#include <vector>

class Emitter : public QObject {
    Q_OBJECT
public:
    void emit_info_signal(int type, std::string str);

    void emit_full(std::string data);

    void emit_hex(std::string data);

    void emit_ascii(std::string data);

    void emit_users_signal(std::string users);

signals:
    void info_signal(int, std::string);

    void packets_signal(std::string);

    void full_signal(std::string);

    void hex_signal(std::string);

    void ascii_signal(std::string);

    void users_signal(std::string);
};

#endif // EMITTER_HPP
