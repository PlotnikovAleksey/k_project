// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include "server.hpp"

bool File_Exists(std::string filePath) {
    std::ifstream fin(filePath.c_str());
    if (fin.is_open()) {
        fin.close();
        return true;
    }
    else {
        return false;
    }
}

void delete_front_whitespaces(std::string& s) {
    while (s.find(' ') == 0) {
        s.erase(0, 1);
    }
}

void delete_back_whitespaces(std::string& s) {
    while (s.back() == ' ')
        s.erase(s.size() - 1, 1);
}

boost::recursive_mutex cs;
boost::asio::io_service service;
Emitter server_emitter;

//initialization of vector of clients
array talk_to_client::clients_list(0);

talk_to_client::talk_to_client() : sock_(service), already_read_(0), username_("unknown_user") {}

std::string& talk_to_client::username() {
    return username_;
}

void talk_to_client::answer_to_request() {
    try {
        read_request();
        process_request();
    }
    catch (...) {
        stop();
    }
}

boost::asio::ip::tcp::socket& talk_to_client::sock() { return sock_; }

bool talk_to_client::timed_out() const {
    return !(sock_.is_open());
}

void talk_to_client::stop() {
    boost::system::error_code err;
    sock_.close(err);
    server_emitter.emit_info_signal(1, username_);
}

void talk_to_client::read_request() {
    if (sock_.available())
        already_read_ += sock_.read_some(
            boost::asio::buffer(buff_ + already_read_, 2048 - already_read_));
}

void talk_to_client::process_request() {
    bool found_enter = std::find(buff_, buff_ + already_read_, '\n') < buff_ + already_read_;
    if (!found_enter) {
        return;
    }
    size_t pos = std::find(buff_, buff_ + already_read_, '\n') - buff_;
    std::string msg(buff_, pos);
    if (msg.find("captured") == 0) {
        on_capture(msg);
    }
    else {
        std::copy(buff_ + already_read_, buff_ + 2048, buff_);
        already_read_ -= pos + 1;
        if (msg.find("login") == 0) on_login();
        else if (msg.find("error") == 0) on_error(msg);
        else
            server_emitter.emit_info_signal(2, username_);
    }
}

void talk_to_client::on_login() {
    username_ = sock_.remote_endpoint().address().to_string();
    server_emitter.emit_info_signal(3, username_);
    write("login ok");
}

void talk_to_client::on_error(const std::string & msg) {
    if (msg.find("error1") == 0)
        server_emitter.emit_info_signal(4, username_);
    else if (msg.find("error2") == 0)
        server_emitter.emit_info_signal(5, username_);
    else if (msg.find("error3") == 0)
        server_emitter.emit_info_signal(6, username_);
    else
        server_emitter.emit_info_signal(7, username_);
}

void talk_to_client::on_capture(std::string & msg) {
    msg.erase(0, 9);
    file_size = stoul(msg);
    unsigned long file_read = 0;
    std::string filename = "dumps\\" + username_;
    unsigned long name_size = static_cast<unsigned long>(filename.size());
    int ind = 0;
    while (File_Exists(filename + ".ydp")) {
        filename.resize(name_size);
        ind++;
        filename += "(" + std::to_string(ind) + ")";
    }
    std::ofstream myFile(filename + ".ydp", std::ios::binary | std::ios::app);
    file_read = static_cast<unsigned long>(already_read_ - 10 - msg.size());
    myFile.write(buff_ + 10 + msg.size(), file_read);
    for (size_t i = 0; i < already_read_; i++)
        buff_[i] = 'H';
    already_read_ = 0;
    char fileBuf[1024];
    while (file_read < file_size) {
        if (sock_.available()) {
            auto this_read = sock_.read_some(
                boost::asio::buffer(fileBuf, 1024));
            myFile.write(fileBuf, this_read);
            file_read += static_cast<unsigned long>(this_read);
        }
    }
    server_emitter.emit_info_signal(8, username_);
}

void talk_to_client::write(const std::string & msg) {
    sock_.write_some(boost::asio::buffer(msg + "\n"));
}

void accept_thread(QMainWindow* main_w) {
    QObject::connect(&server_emitter, SIGNAL(info_signal(int, std::string)), main_w, SLOT(messages(int, std::string)));
    QObject::connect(&server_emitter, SIGNAL(users_signal(std::string)), main_w, SLOT(show_users(std::string)));
    boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 32222));
    while (true) {
        client_ptr new_request(new talk_to_client);
        acceptor.accept(new_request->sock());
        boost::recursive_mutex::scoped_lock lk(cs);
        talk_to_client::clients_list.push_back(new_request);
    }
}

void handle_clients_thread() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        boost::recursive_mutex::scoped_lock lk(cs);
        for (auto current = talk_to_client::clients_list.begin(), end = talk_to_client::clients_list.end(); current != end; ++current)
            (*current)->answer_to_request();
        size_t before = talk_to_client::clients_list.size();
        talk_to_client::clients_list.erase(std::remove_if(talk_to_client::clients_list.begin(), talk_to_client::clients_list.end(),
            boost::bind(&talk_to_client::timed_out, _1)), talk_to_client::clients_list.end());
        size_t after = talk_to_client::clients_list.size();
        if (after != before) {
            std::string names;
            for (auto it: talk_to_client::clients_list)
                names+=it->username() + "\n";
            server_emitter.emit_users_signal(names);
        }
    }
}
