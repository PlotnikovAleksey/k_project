// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <boost/thread/recursive_mutex.hpp>
#include <QString>
#include <QFileDialog>
#include <QDebug>

boost::recursive_mutex rm;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("WireSharkie");
    ui->lineEdit->setPlaceholderText("enter command");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::messages(int type, std::string name){
    if (type == 1) {
        name+="\'s socket is closed";
        QMessageBox::information(this, "Good buy", name.c_str());
    } else if (type == 2) {
        std::string mes = "invalid message from " + name;
        QMessageBox::critical(this, "How dare you?!", mes.c_str());
    } else if (type == 3) {
        std::string mes = "new client accepted: " + name;
        QMessageBox::information(this, "You are mine!", mes.c_str());
        QString q_name = QString::fromUtf8(name.c_str());
        ui->textEdit->append(q_name);
    } else if (type == 4) {
        std::string mes = "Error while shiffing " + name;
        QMessageBox::warning(this, "Something went wrong...", mes.c_str());
    } else if (type == 5) {
        std::string mes = "Unable to compile the filter used for " + name;
        QMessageBox::warning(this, "Hey, your filter is not correct!", mes.c_str());
    } else if (type == 6) {
        std::string mes = "Error while opening file " + name;
        QMessageBox::warning(this, "Something went wrong...", mes.c_str());
    } else if (type == 7) {
        std::string mes = "What\'s wrong with you, " + name;
        QMessageBox::critical(this, "Unknow error 0_o...", mes.c_str());
    } else if (type == 8) {
        std::string mes = "Packets are captured from " + name;
        QMessageBox::information(this, "Delicious...", mes.c_str());
    }
}

void MainWindow::show_users(std::string users){
    if (users.size() != 0){
        QString q_names = QString::fromUtf8(users.c_str());
        ui->textEdit->setText(q_names);
    } else {
        ui->textEdit->clear();
    }
}

std::mutex mut;

void MainWindow::accept_full(std::string full_data) {
    QString q_full_info = QString::fromUtf8(full_data.c_str());
    mut.lock();
    ui->textEdit_2->setText(q_full_info);
    mut.unlock();
}

void MainWindow::accept_hex(std::string hex_data) {
    QString q_hex = QString::fromUtf8(hex_data.c_str());
    mut.lock();
    ui->textEdit_4->setText(q_hex);
    mut.unlock();
}

void MainWindow::accept_ascii(std::string ascii_data) {
    QString q_ascii = QString::fromUtf8(ascii_data.c_str());
    mut.lock();
    ui->textEdit_3->setText(q_ascii);
    mut.unlock();
}


void MainWindow::on_lineEdit_returnPressed() {
    QString Qcommand = ui->lineEdit->text();
    std::string mes = Qcommand.toStdString();
    boost::recursive_mutex::scoped_lock lk(rm);
    if (mes.size() == 0) {
        QMessageBox::information(this, "Stop touching it for no reason -_-","      Enter command, please                ");
    } else {
        delete_back_whitespaces(mes);
        delete_front_whitespaces(mes);
        auto command = mes.substr(0, mes.find(' '));
        mes.erase(0, command.size());
        delete_front_whitespaces(mes);
        // Commands using clients
        if (command == "shutdown" || command == "capture") {
            if (talk_to_client::clients_list.size() == 0) {
                QMessageBox::warning(this, "Find someone finally!!!","   There is no clients        ");
            } else {
                if (command == "capture") {
                    auto num_str = mes.substr(0, mes.find(' '));
                    if (!(isdigit(mes[0])) || static_cast<int>(mes.find(' ')) == -1) {
                        QMessageBox::warning(this, "Don\'t forget!","Missing amount of packets");
                    } else {
                        command += " " + num_str;
                        mes.erase(0, num_str.size());
                        delete_front_whitespaces(mes);
                        auto filter = mes.substr(0, mes.find(' '));
                        if (filter == "set_filter") {
                            command += " \'";
                            mes.erase(0, filter.size());
                            delete_front_whitespaces(mes);
                            if (mes[0] != '\'') {
                                QMessageBox::warning(this, "Nope","Wrong syntaxis");
                            } else {
                                mes.erase(0, 1);
                                if (static_cast<int>(mes.find('\'')) == -1) {
                                    QMessageBox::warning(this, "Nope","Wrong syntaxis");
                                } else {
                                    filter = mes.substr(0, mes.find('\''));
                                    command += filter + "\'";
                                    mes.erase(0, mes.find('\'') + 1);
                                    delete_front_whitespaces(mes);
                                }
                            }
                        }
                    }
                }
                auto name = mes.substr(0, mes.find(' '));
                for (auto current = talk_to_client::clients_list.begin(), end = talk_to_client::clients_list.end();; ++current) {
                    if ((*current)->username() == name) {
                        try {
                            (*current)->write(command);
                            if (command == "shutdown")
                                (*current)->sock().close();
                            ui->lineEdit->clear();
                            break;
                        } catch (...) {
                            (*current)->sock().close();
                            break;
                        }
                    }
                    if (current + 1 == end) {
                        QMessageBox::warning(this, "Open your eyes!","Incorrect name     ");
                        break;
                    }
                }
            }
        }
        // Commands not using clients analyze
        else if (command == "analyze") {
            if (!(File_Exists(mes))) {
                QMessageBox::warning(this, "Ooooops","File doesn\'t exist");
            }
            else if (mes.size() < 5) {
                QMessageBox::warning(this, "Nope","Wrong file");
            } else if (mes.substr(mes.size() - 4, 4) != ".ydp") {
                QMessageBox::warning(this, "Nope","Wrong file");
            } else {
                char *path = new char[mes.size() + 1];
                strcpy(path, mes.c_str());
                processing(path, this);
                delete[] path;
                ui->lineEdit->clear();
            }
        }
        // Wrong commands
        else {
            QMessageBox::warning(this, "Nope","Wrong syntaxis");
        }
    }
}

void MainWindow::on_actionOpen_triggered() {
    QString path = QFileDialog::getOpenFileName(0,QObject::tr("Укажите файл"),QDir::homePath(), QObject::tr("Файл (*.ydp);;Все файлы (*.*)"));
    QByteArray ba = path.toLocal8Bit();
    const char *char_path = ba.data();
    processing(char_path, this);
}
