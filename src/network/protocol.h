#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <vector>

namespace erebos {

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

	bool recvfrom(vector<uint8_t> & buffer, sockaddr_in6 & addr);
	void sendto(const vector<uint8_t> & buffer, sockaddr_in addr);
	void sendto(const vector<uint8_t> & buffer, sockaddr_in6 addr);

	void shutdown();

private:
	int sock;
};

}
