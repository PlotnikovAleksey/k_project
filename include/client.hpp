// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#ifndef INCLUDE_CLIENT_HPP_
#define INCLUDE_CLIENT_HPP_
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <boost/asio.hpp>
#include <string>
#include <thread>
#include <chrono>
#include <fstream>
#include "kp_sniffer_stable.hpp"

class Client {
private:
	boost::asio::ip::tcp::socket sock_;
	char buff_[1024];
	bool started_;
	size_t already_read_;

public:
	Client();

	void connect(boost::asio::ip::tcp::endpoint ep);

	void login();

	void processing();

	void read_message();

	bool process_message();

	void on_shutdown();

	void on_capture(std::string & msg);

	void send_file();

	void write(const std::string & msg);

};

void run_client();

int virtual_main();

#endif // INCLUDE_CLIENT_HPP_
