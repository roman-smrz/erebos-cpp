#include "protocol.h"

#include <sys/socket.h>
#include <unistd.h>

#include <system_error>

namespace erebos {

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

}
