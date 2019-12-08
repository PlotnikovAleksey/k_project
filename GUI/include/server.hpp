// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#ifndef INCLUDE_SERVER_HPP_
#define INCLUDE_SERVER_HPP_
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/bind.hpp>
#include <string>
#include <thread>
#include <mutex>
#include <fstream>
#include "kp_analysis_from_dump.hpp"

bool File_Exists(std::string filePath);

void delete_front_whitespaces(std::string& s);

void delete_back_whitespaces(std::string& s);

struct talk_to_client : boost::enable_shared_from_this<talk_to_client> {
private:
    boost::asio::ip::tcp::socket sock_;
    size_t already_read_;
    char buff_[2048];
    std::string username_;
    unsigned long file_size;

public:
    typedef boost::shared_ptr<talk_to_client> client_ptr;
    typedef std::vector<client_ptr> array;
    static array clients_list;

    talk_to_client();

    std::string& username();

    void answer_to_request();

    boost::asio::ip::tcp::socket& sock();

    bool timed_out() const;

    void stop();

    void read_request();

    void process_request();

    void on_login();

    void on_error(const std::string & msg);

    void on_capture(std::string & msg);

    void send_precol();

    void write(const std::string & msg);

};

typedef boost::shared_ptr<talk_to_client> client_ptr;
typedef std::vector<client_ptr> array;

void accept_thread(QMainWindow* main_w);

void handle_clients_thread();

#endif // INCLUDE_SERVER_HPP_
