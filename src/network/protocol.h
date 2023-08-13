#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <variant>
#include <vector>

namespace erebos {

using std::mutex;
using std::unique_ptr;
using std::variant;
using std::vector;

class NetworkProtocol
{
public:
	NetworkProtocol();
	explicit NetworkProtocol(int sock);
	NetworkProtocol(const NetworkProtocol &) = delete;
	NetworkProtocol(NetworkProtocol &&);
	NetworkProtocol & operator=(const NetworkProtocol &) = delete;
	NetworkProtocol & operator=(NetworkProtocol &&);
	~NetworkProtocol();

	class Connection;

	struct NewConnection;
	struct ConnectionReadReady;
	struct ProtocolClosed {};

	using PollResult = variant<
		NewConnection,
		ConnectionReadReady,
		ProtocolClosed>;

	PollResult poll();

	Connection connect(sockaddr_in6 addr);

	bool recvfrom(vector<uint8_t> & buffer, sockaddr_in6 & addr);
	void sendto(const vector<uint8_t> & buffer, sockaddr_in addr);
	void sendto(const vector<uint8_t> & buffer, sockaddr_in6 addr);

	void shutdown();

private:
	int sock;

	mutex protocolMutex;
	vector<uint8_t> buffer;

	struct ConnectionPriv;
	vector<ConnectionPriv *> connections;
};

class NetworkProtocol::Connection
{
	friend class NetworkProtocol;
	Connection(unique_ptr<ConnectionPriv> p);
public:
	Connection(const Connection &) = delete;
	Connection(Connection &&);
	Connection & operator=(const Connection &) = delete;
	Connection & operator=(Connection &&);
	~Connection();

	using Id = uintptr_t;
	Id id() const;

	const sockaddr_in6 & peerAddress() const;

	bool receive(vector<uint8_t> & buffer);
	bool send(const vector<uint8_t> & buffer);

	void close();

private:
	unique_ptr<ConnectionPriv> p;
};

struct NetworkProtocol::NewConnection { Connection conn; };
struct NetworkProtocol::ConnectionReadReady { Connection::Id id; };

}
