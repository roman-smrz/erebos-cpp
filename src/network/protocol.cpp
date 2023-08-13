#include "protocol.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <system_error>

using std::move;
using std::scoped_lock;

namespace erebos {

struct NetworkProtocol::ConnectionPriv
{
	Connection::Id id() const;

	NetworkProtocol * protocol;
	const sockaddr_in6 peerAddress;

	mutex cmutex {};
	vector<uint8_t> buffer {};
};


NetworkProtocol::NetworkProtocol():
	sock(-1)
{}

NetworkProtocol::NetworkProtocol(int s):
	sock(s)
{}

NetworkProtocol::NetworkProtocol(NetworkProtocol && other):
	sock(other.sock)
{
	other.sock = -1;
}

NetworkProtocol & NetworkProtocol::operator=(NetworkProtocol && other)
{
	sock = other.sock;
	other.sock = -1;
	return *this;
}

NetworkProtocol::~NetworkProtocol()
{
	if (sock >= 0)
		close(sock);

	for (auto & c : connections)
		c->protocol = nullptr;
}

NetworkProtocol::PollResult NetworkProtocol::poll()
{
	sockaddr_in6 addr;
	if (!recvfrom(buffer, addr))
		return ProtocolClosed {};

	scoped_lock lock(protocolMutex);
	for (const auto & c : connections) {
		if (memcmp(&c->peerAddress, &addr, sizeof addr) == 0) {
			scoped_lock clock(c->cmutex);
			buffer.swap(c->buffer);
			return ConnectionReadReady { c->id() };
		}
	}

	auto conn = unique_ptr<ConnectionPriv>(new ConnectionPriv {
		.protocol = this,
		.peerAddress = addr,
	});

	connections.push_back(conn.get());
	buffer.swap(conn->buffer);
	return NewConnection { Connection(move(conn)) };
}

NetworkProtocol::Connection NetworkProtocol::connect(sockaddr_in6 addr)
{
	auto conn = unique_ptr<ConnectionPriv>(new ConnectionPriv {
		.protocol = this,
		.peerAddress = addr,
	});
	connections.push_back(conn.get());
	return Connection(move(conn));
}

bool NetworkProtocol::recvfrom(vector<uint8_t> & buffer, sockaddr_in6 & addr)
{
	socklen_t addrlen = sizeof(addr);
	buffer.resize(4096);
	ssize_t ret = ::recvfrom(sock, buffer.data(), buffer.size(), 0,
			(sockaddr *) &addr, &addrlen);
	if (ret < 0)
		throw std::system_error(errno, std::generic_category());
	if (ret == 0)
		return false;

	buffer.resize(ret);
	return true;
}

void NetworkProtocol::sendto(const vector<uint8_t> & buffer, sockaddr_in addr)
{
	::sendto(sock, buffer.data(), buffer.size(), 0,
			(sockaddr *) &addr, sizeof(addr));
}

void NetworkProtocol::sendto(const vector<uint8_t> & buffer, sockaddr_in6 addr)
{
	::sendto(sock, buffer.data(), buffer.size(), 0,
			(sockaddr *) &addr, sizeof(addr));
}

void NetworkProtocol::shutdown()
{
	::shutdown(sock, SHUT_RDWR);
}


NetworkProtocol::Connection::Id NetworkProtocol::ConnectionPriv::id() const
{
	return reinterpret_cast<uintptr_t>(this);
}

NetworkProtocol::Connection::Connection(unique_ptr<ConnectionPriv> p_):
	p(move(p_))
{
}

NetworkProtocol::Connection::Connection(Connection && other):
	p(move(other.p))
{
}

NetworkProtocol::Connection & NetworkProtocol::Connection::operator=(Connection && other)
{
	close();
	p = move(other.p);
	return *this;
}

NetworkProtocol::Connection::~Connection()
{
	close();
}

NetworkProtocol::Connection::Id NetworkProtocol::Connection::id() const
{
	return p->id();
}

const sockaddr_in6 & NetworkProtocol::Connection::peerAddress() const
{
	return p->peerAddress;
}

bool NetworkProtocol::Connection::receive(vector<uint8_t> & buffer)
{
	scoped_lock lock(p->cmutex);
	if (p->buffer.empty())
		return false;

	buffer.swap(p->buffer);
	p->buffer.clear();
	return true;
}

bool NetworkProtocol::Connection::send(const vector<uint8_t> & buffer)
{
	p->protocol->sendto(buffer, p->peerAddress);
	return true;
}

void NetworkProtocol::Connection::close()
{
	if (not p)
		return;

	if (p->protocol) {
		scoped_lock lock(p->protocol->protocolMutex);
		for (auto it = p->protocol->connections.begin();
				it != p->protocol->connections.end(); it++) {
			if ((*it) == p.get()) {
				p->protocol->connections.erase(it);
				break;
			}
		}
	}

	p = nullptr;
}

}
