// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include <QApplication>
#include "mainwindow.hpp"
#include <QMetaType>
#include <QtDebug>
Q_DECLARE_METATYPE(std::string)

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    qRegisterMetaType<std::string>("std::string");
    MainWindow w;
    w.show();
    std::thread accept(accept_thread, &w);
    std::thread handle(handle_clients_thread);
    accept.detach();
    handle.detach();
    return a.exec();
}
