// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include <QString>
#include "server.hpp"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

    ~MainWindow();

public slots:

    void on_lineEdit_returnPressed();

    void messages(int type, std::string name);

    void show_users(std::string users);

    void accept_full(std::string full_data);

    void accept_hex(std::string hex_data);

    void accept_ascii(std::string ascii_data);
private slots:
    void on_actionOpen_triggered();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_HPP
