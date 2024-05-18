#include <chrono>
#include <string>

#include "connection.h"

using namespace std;

Connection::Connection() {}

Connection::Connection(string i, int p, int d) : ip(i), port(p), id(d) {
	/*
	Constructor function to create Connection class
	*/
	asio::io_context::work idleWork(context);
	context_thread = thread([&]() {context.run();});

	socket = make_shared<asio::ip::udp::socket>(context);
	socket->open(asio::ip::udp::v4());
	asio::ip::udp::endpoint local_endpoint = asio::ip::udp::endpoint(asio::ip::udp::v4(), 0); // lan
	socket->bind(local_endpoint);

	asio::ip::udp::endpoint e = asio::ip::udp::endpoint(asio::ip::make_address(ip), port);
	connect(e);
}

Connection::Connection(string i, int p, int d, shared_ptr<RSA> dk) : Connection(i, p, d) {
	/*
	Constructor functino to create Connection class
	takes decryption key
	*/
	decryption_key = dk;
}

Connection::~Connection() {
	/*
	Destructor function to properly stop a connection
	*/
	context.stop();
	context_thread.join();

	if (socket->is_open()) socket->close();
	socket.reset();
}

bool Connection::checkNodeProtocol(string data) {
	/*
	Check if data is of type Node protocol, meaning pnp, rpnp, or cpnp
	Cases where it isn't: syn, ack, keepalive
	*/
	return (data.find("pnp") == 0 || data.find("rpnp") == 0 || data.find("cpnp") == 0);
}

bool Connection::checkConnectionProtocol(string data) {
	/*
	Check if data is not of type Node protocol, meaning syn, ack, keepalive
	Cases where it isn't: pnp, rpnp, cpnp
	*/
	return (data.find("keepalive") == 0 || data.find("syn") == 0 || data.find("ack") == 0);
}

void Connection::handleConnectionMessage(string data) {
	/*
	Handle a connection message
	if the message is keepalive, update the last time keepalive was recieved to now
	if the message is syn, return ack
	if the message is ack, realize the connection
	*/
	if (data == "keepalive") {
		keepalive = chrono::high_resolution_clock::now();
	}
	else if (data == "syn") {
		connected = true;
		writeProtocolless("ack");
	}
	else if (data == "ack") {
		connected = true;
	}
}

void Connection::asyncReadData() {
	/*
	Asynchronous function to read an incoming message
	if the message is of type Node protocol, it is put into the queue of incoming messages
	if not, it is handled with handleConnectionMessage
	*/
	fill(read_buffer.begin(), read_buffer.end(), 0);

	socket->async_receive_from(asio::buffer(read_buffer.data(), read_buffer.size()), endpoint,
		[&](error_code ec, size_t length) {
			if (!ec) {
				vector<char>::iterator end_of_data = find(read_buffer.begin(), read_buffer.end(), '\0');
				string data(read_buffer.begin(), end_of_data);

				if (data.substr(0, 6) == "epnpa\n") {
					end_of_data = find_end(read_buffer.begin(), read_buffer.end(), "\nepnpa", "\nepnpa" + 6);
					data = string(read_buffer.begin(), end_of_data);
					data = data.substr(6, data.length() - 6);

					data = Encryption::decryptAES(data, AES_MASTER_KEY);
				}

				if (data.substr(0, 6) == "epnpr\n") {
					fill(read_buffer.begin(), read_buffer.end(), 0);
					copy(data.begin(), data.end(), read_buffer.begin());

					end_of_data = find_end(read_buffer.begin(), read_buffer.end(), "\nepnpr", "\nepnpr" + 6);
					data = string(read_buffer.begin(), end_of_data);
					data = data.substr(6, data.length() - 6);

					data = Encryption::decrypt(data, decryption_key);
				}
				
				if (checkConnectionProtocol(data)) handleConnectionMessage(data);
				else if (checkNodeProtocol(data)) incoming_messages.push(data);
			}

			asyncReadData();
		}
	);
}

void Connection::writeData(string data) {
	/*
	Write data to the socket
	add an rsa encryption layer, then continue to writePlain
	*/
	string payload = data;

	if (encryption_key && !checkConnectionProtocol(data)) {
		payload = "epnpr\n" + Encryption::encrypt(data, encryption_key) + "\nepnpr";
	}

	writePlain(payload);
}

void Connection::writePlain(string data) {
	/*
	Write data to the socket
	add an aes encryption layer, then continue to writeProtocolless
	*/
	data = "epnpa\n" + Encryption::encryptAES(data, AES_MASTER_KEY) + "\nepnpa";

	writeProtocolless(data);
}

void Connection::writeProtocolless(string data) {
	/*
	Write data as it's inputed to the socket without encrypting it
	used directly for packets without Node protocol
	*/
	socket->send_to(asio::buffer(data.data(), data.size()), endpoint);
}

void Connection::handshake() {
	/*
	Handshake with another node to connect to it
	*/
	time_point start = chrono::high_resolution_clock::now();
	time_point now;
	int time_passed = 0;

	while (!connected && time_passed < HANDSHAKE_TIME) {
		writeProtocolless("syn");

		this_thread::sleep_for(chrono::milliseconds(HANDSHAKE_FREQUENCY));

		now = chrono::high_resolution_clock::now();
		time_passed = chrono::duration_cast<chrono::seconds>(now - start).count();
	}
}

void Connection::connect(asio::ip::udp::endpoint e) {
	/*
	Connect to a different node with endpoint e
	*/
	connected = false;
	socket->cancel();

	endpoint = e;

	error_code ec;
	socket->connect(endpoint, ec);
	
	asyncReadData();
	handshake();

	if (connected) {
		keepalive = chrono::high_resolution_clock::now();
	}
}

void Connection::change(string i, int p, int d, shared_ptr<RSA> dk) {
	/*
	Change the endpoint and node the socket is connected to
	used for holepunching
	*/
	ip = i;
	port = p;
	id = d;
	decryption_key = dk;

	asio::ip::udp::endpoint e = asio::ip::udp::endpoint(asio::ip::make_address(ip), port);
	connect(e);
}

void Connection::releaseChess() {
	/*
	Release the board associated with the Connection
	*/
	chess_connection = false;
	board.reset();
}

RootConnection::RootConnection(string i, int p, int d, int my_port) {
	/*
	Constructor function for RootConnection
	RootConnect is a connection of the RootNode, meaning it needs a bound port
	*/
	ip = i;
	port = p;
	id = d;

	asio::io_context::work idleWork(context);
	context_thread = thread([&]() {context.run();});

	socket = make_shared<asio::ip::udp::socket>(context);
	socket->open(asio::ip::udp::v4());
	asio::ip::udp::endpoint local_endpoint = asio::ip::udp::endpoint(asio::ip::udp::v4(), my_port); // lan
	socket->bind(local_endpoint);

	connect();
}

RootConnection::RootConnection(string i, int p, int d, int my_port, shared_ptr<RSA> dk) : RootConnection(i, p, d, my_port) {
	/*
	Constructor function for RootConnection
	initializes with decryption key
	*/
	decryption_key = dk;
}

void RootConnection::connect() {
	/*
	Connect to a different node with endpoint e
	*/
	asyncReadData();
	
	time_point start = chrono::high_resolution_clock::now();
	time_point now;
	int time_passed = 0;

	while (!connected && time_passed < HANDSHAKE_TIME) {
		this_thread::sleep_for(chrono::milliseconds(HANDSHAKE_FREQUENCY));

		now = chrono::high_resolution_clock::now();
		time_passed = chrono::duration_cast<chrono::seconds>(now - start).count();
	}

	if (connected) {
		keepalive = chrono::high_resolution_clock::now();
	}
}

OpenConnection::OpenConnection() {
	/*
	Constructor function for OpenConnection
	OpenConnection is the root connection with port forwarding, meaning it is the connection
	that welcomes new user and that is used for hole punching as the rendezvous server
	*/
	asio::io_context::work idleWork(context);
	context_thread = thread([&]() {context.run();});

	local_endpoint = asio::ip::udp::endpoint(asio::ip::udp::v4(), ROOT_PORT);
	socket = make_shared<asio::ip::udp::socket>(context, local_endpoint);

	asyncReceive();
}

void OpenConnection::writeData(asio::ip::udp::endpoint endpoint, string data) {
	/*
	Write data to the socket
	add an aes encryption layer, the continue to writeProtocolless
	*/
	data = "epnpa\n" + Encryption::encryptAES(data, AES_MASTER_KEY) + "\nepnpa";

	writeProtocolless(endpoint, data);
}

void OpenConnection::writeProtocolless(asio::ip::udp::endpoint endpoint, string data) {
	/*
	Write data as it's inputed to the socket without encrypting it
	used directly for packets without Node protocol
	*/
	socket->send_to(asio::buffer(data.data(), data.size()), endpoint);
}

bool OpenConnection::checkNodeProtocol(string data) {
	/*
	Check if data is of type Node protocol, meaning pnp, rpnp, or apnp
	Cases where it isn't: syn, ack, keepalive
	*/
	return data.find("rpnp") == 0;
}

void OpenConnection::handleConnectionMessage(Message data) {
	/*
	Handle data with no protocol
	if data is syn, return ack
	*/
	if (data.message == "syn") {
		writeProtocolless(data.endpoint, "ack");
	}
}

void OpenConnection::asyncReceive() {
	/*
	Asynchornous function to read data into the buffer and handle it
	if it is of type Node Protocol, put it in the incoming message queue
	if not, handle it
	*/
	fill(read_buffer.begin(), read_buffer.end(), 0);

	socket->async_receive_from(asio::buffer(read_buffer.data(), read_buffer.size()), receiving_endpoint,
		[&](error_code ec, size_t length) {
			if (!ec) {
				Message message;
				message.endpoint = receiving_endpoint;

				vector<char>::iterator end_of_data = find(read_buffer.begin(), read_buffer.end(), '\0');
				string data(read_buffer.begin(), end_of_data);
				
				if (data.substr(0, 6) == "epnpa\n") {
					end_of_data = find_end(read_buffer.begin(), read_buffer.end(), "\nepnpa", "\nepnpa" + 6);
					data = string(read_buffer.begin(), end_of_data);
					data = data.substr(6, data.length() - 6);

					data = Encryption::decryptAES(data, AES_MASTER_KEY);
				}

				message.message = data;

				if (checkNodeProtocol(message.message)) incoming_messages.push(message);
				else handleConnectionMessage(message);
			}

			asyncReceive();
		});
}