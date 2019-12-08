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
	std::cout << username_ << "\'s socket is closed\n";
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
		if (msg.find("login") == 0) on_login(msg);
		else if (msg.find("error") == 0) on_error(msg);
		else
			std::cout << "invalid message " << msg << " from " << username_ << std::endl;
	}
}

void talk_to_client::on_login(const std::string & msg) {
	username_ = sock_.remote_endpoint().address().to_string();
	std::cout << "New client " << username_ << " is accepted, " << "amount of clients: " << clients_list.size() << std::endl;
	write("login ok");
}

void talk_to_client::on_error(const std::string & msg) {
	if (msg.find("error1") == 0)
		std::cout << "Error while shiffing\n";
	else if (msg.find("error2") == 0)
		std::cout << "Unable to compile the filter\n";
	else if (msg.find("error3") == 0)
		std::cout << "Error while opening file\n";
	else
		std::cout << "Unknow error 0_o\n";
}

void talk_to_client::on_capture(std::string & msg) {
	msg.erase(0, 9);
	file_size = stoul(msg);
	unsigned long file_read = 0;
	std::string filename = "dumps/" + username_;
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
	std::cout << "Packets are captured from " << username_ << std::endl;
}

void talk_to_client::write(const std::string & msg) {
	sock_.write_some(boost::asio::buffer(msg + "\n"));
}

void accept_thread() {
	boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 32222));
	while (true) {
		client_ptr new_request(new talk_to_client);
		acceptor.accept(new_request->sock());
		boost::recursive_mutex::scoped_lock lk(cs);
		std::cout << "New client accepted\n";
		talk_to_client::clients_list.push_back(new_request);
	}
}

void handle_clients_thread() {
	while (true) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		boost::recursive_mutex::scoped_lock lk(cs);
		for (auto current = talk_to_client::clients_list.begin(), end = talk_to_client::clients_list.end(); current != end; ++current)
			(*current)->answer_to_request();
		talk_to_client::clients_list.erase(std::remove_if(talk_to_client::clients_list.begin(), talk_to_client::clients_list.end(),
			boost::bind(&talk_to_client::timed_out, _1)), talk_to_client::clients_list.end());
	}
}

void command_input() {
	while (true) {
		std::string mes;
		std::getline(std::cin, mes);
		boost::recursive_mutex::scoped_lock lk(cs);
		if (mes.size() == 0) {
			std::cout << "Empty input\n";
			continue;
		}
		delete_back_whitespaces(mes);
		delete_front_whitespaces(mes);
		auto command = mes.substr(0, mes.find(' '));
		mes.erase(0, command.size());
		delete_front_whitespaces(mes);
		// Commands using clients
		if (command == "shutdown" || command == "capture") {
			if (talk_to_client::clients_list.size() == 0) {
				std::cout << "No clients\n";
				continue;
			}
			if (command == "capture") {
				auto num_str = mes.substr(0, mes.find(' '));
				try {
					stoi(num_str);
				}
				catch (const std::exception&) {
					std::cout << "Missing amount of packets";
					continue;
				}
				command += " " + num_str;
				mes.erase(0, num_str.size());
				delete_front_whitespaces(mes);
				auto filter = mes.substr(0, mes.find(' '));
				if (filter == "set_filter") {
					command += " \'";
					mes.erase(0, filter.size());
					delete_front_whitespaces(mes);
					if (mes[0] != '\'') {
						std::cout << "Wrong syntaxis\n";
						continue;
					}
					mes.erase(0, 1);
					if (static_cast<int>(mes.find('\'')) == -1) {
						std::cout << "Wrong syntaxis\n";
						continue;
					}
					filter = mes.substr(0, mes.find('\''));
					command += filter + "\'";
					mes.erase(0, mes.find('\'') + 1);
					delete_front_whitespaces(mes);
				}
			}
			auto name = mes.substr(0, mes.find(' '));
			for (auto current = talk_to_client::clients_list.begin(), end = talk_to_client::clients_list.end();; ++current) {
				if ((*current)->username() == name) {
					(*current)->write(command);
					if (command == "shutdown")
						(*current)->sock().close();
					break;
				}
				if (current + 1 == end) {
					std::cout << "Incorrect name\n";
					break;
				}
			}
		}
		// Commands not using clients analyze
		else if (command == "analyze") {
			char *path = new char[mes.size() + 1];
			strcpy(path, mes.c_str());
			processing(path);
			delete[] path;
		}
		// Wrong commands
		else {
			std::cout << "Wrong syntaxis\n";
		}
	}
}

int virtual_main() {
	std::cout << "Server was activated\n";
	std::thread accept(accept_thread);
	std::thread handle(handle_clients_thread);
	std::thread input(command_input);
	accept.join();
	handle.join();
	input.join();
	return 0;
}
