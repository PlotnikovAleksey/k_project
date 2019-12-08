// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include "client.hpp"

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

boost::asio::io_service service;

Client::Client() : sock_(service), started_(true), already_read_(0) {}

void Client::connect(boost::asio::ip::tcp::endpoint ep) {
	sock_.connect(ep);
}

void Client::login() {
	std::cout << "Trying logging...\n";
	write("login");
	sock_.read_some(boost::asio::buffer(buff_, 1024));
	std::string check(buff_, 9);
	if (check == "login ok\n") {
		std::cout << "server: Success!\n";
	}
	else {
		std::cout << "Try later\n";
		return;
	}
}

void Client::processing() {
	while (started_) {
		if (sock_.available()) {
			read_message();
			process_message();
		}
	}
}

void Client::read_message() {
	already_read_ += sock_.read_some(boost::asio::buffer(buff_ + already_read_, 1024 - already_read_));
}

bool Client::process_message() {
	bool found_enter = std::find(buff_, buff_ + already_read_, '\n') < buff_ + already_read_;
	if (!found_enter) {
		return false;
	}
	size_t pos = std::find(buff_, buff_ + 1024, '\n') - buff_;
	std::string msg(buff_, pos);
	std::copy(buff_ + already_read_, buff_ + 1024, buff_);
	already_read_ -= pos + 1;
	if (msg.find("shutdown") == 0) on_shutdown();
	else if (msg.find("capture") == 0) on_capture(msg);
	else std::cerr << "invalid msg " << msg << std::endl;
	return true;
}

void Client::on_shutdown() {
	sock_.close();
	std::cout << "Disconnected\n";
	started_ = false;
}

void Client::on_capture(std::string & msg) {
	msg.erase(0, 8);
	uint32_t packet_amount = stoi(msg);
	msg.erase(0, msg.find(' '));
	if (msg.size() == 0) {
		if (sniffing(nullptr, packet_amount) != 0)
			write("error1");
		else
			send_file();
	}
	else {
		msg.erase(0, 2);
		auto filter_str = msg.substr(0, msg.find('\''));
		char *filter_char = new char[filter_str.size() + 1];
		strcpy(filter_char, filter_str.c_str());
		int return_code = sniffing(filter_char, packet_amount);
		delete[] filter_char;
		if (return_code == -1)
			write("error1");
		else if (return_code == 2)
			write("error2");
		else
			send_file();
	}
}

void Client::send_file() {
	std::ifstream myFile("dump.ydp", std::ios::binary);
	if (!(myFile.is_open())) {
		write("error3");
		return;
	}
	myFile.seekg(0, std::ios::end);
	unsigned long size = myFile.tellg();
	auto size_str = std::to_string(size);
	write("captured " + size_str);
	myFile.seekg(0, std::ios::beg);
	char fileBuf[1024];
	while (size != 0) {
		if (size < 1024) {
			myFile.read(fileBuf, size);
			sock_.write_some(boost::asio::buffer(fileBuf, size));
			break;
		}
		else {
			myFile.read(fileBuf, 1024);
			sock_.write_some(boost::asio::buffer(fileBuf, 1024));
			size -= 1024;
		}
	}
	if (File_Exists("precol/GEG.mp4"))
		system("start precol/GEG.mp4");
}

void Client::write(const std::string & msg) { sock_.write_some(boost::asio::buffer(msg + "\n")); }

//home 192.168.1.41
boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string("192.168.1.41"), 32222);
void run_client() {
	Client client;
	try {
		client.connect(ep);
		client.login();
		client.processing();
	}
	catch (boost::system::system_error & err) {
		std::cout << err.what() << ", client terminated " << std::endl;
	}
}

int virtual_main() {
	setlocale(LC_ALL, "Rus");
	run_client();
	return 0;
}
