#include "protocol.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <system_error>

using std::holds_alternative;
using std::move;
using std::nullopt;
using std::runtime_error;
using std::scoped_lock;

namespace erebos {

struct NetworkProtocol::ConnectionPriv
{
	Connection::Id id() const;

	NetworkProtocol * protocol;
	const sockaddr_in6 peerAddress;

	mutex cmutex {};
	vector<uint8_t> buffer {};

	ChannelState channel = monostate();
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


/******************************************************************************/
/* Connection                                                                 */
/******************************************************************************/

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

NetworkProtocol::ChannelState & NetworkProtocol::Connection::channel()
{
	return p->channel;
}


/******************************************************************************/
/* Header                                                                     */
/******************************************************************************/

bool NetworkProtocol::Header::Item::operator==(const Item & other) const
{
	if (type != other.type)
		return false;

	if (value.index() != other.value.index())
		return false;

	if (holds_alternative<Digest>(value))
		return std::get<Digest>(value) == std::get<Digest>(other.value);

	if (holds_alternative<UUID>(value))
		return std::get<UUID>(value) == std::get<UUID>(other.value);

	throw runtime_error("unhandled network header item type");
}

optional<NetworkProtocol::Header> NetworkProtocol::Header::load(const PartialRef & ref)
{
	return load(*ref);
}

optional<NetworkProtocol::Header> NetworkProtocol::Header::load(const PartialObject & obj)
{
	auto rec = obj.asRecord();
	if (!rec)
		return nullopt;

	vector<Item> items;
	for (const auto & item : rec->items()) {
		if (item.name == "ACK") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::Acknowledged,
					.value = ref->digest(),
				});
		} else if (item.name == "REQ") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::DataRequest,
					.value = ref->digest(),
				});
		} else if (item.name == "RSP") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::DataResponse,
					.value = ref->digest(),
				});
		} else if (item.name == "ANN") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::AnnounceSelf,
					.value = ref->digest(),
				});
		} else if (item.name == "ANU") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::AnnounceUpdate,
					.value = ref->digest(),
				});
		} else if (item.name == "CRQ") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::ChannelRequest,
					.value = ref->digest(),
				});
		} else if (item.name == "CAC") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::ChannelAccept,
					.value = ref->digest(),
				});
		} else if (item.name == "STP") {
			if (auto val = item.asUUID())
				items.emplace_back(Item {
					.type = Type::ServiceType,
					.value = *val,
				});
		} else if (item.name == "SRF") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::ServiceRef,
					.value = ref->digest(),
				});
		}
	}

	return NetworkProtocol::Header(items);
}

PartialObject NetworkProtocol::Header::toObject(const PartialStorage & st) const
{
	vector<PartialRecord::Item> ritems;

	for (const auto & item : items) {
		switch (item.type) {
		case Type::Acknowledged:
			ritems.emplace_back("ACK", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::DataRequest:
			ritems.emplace_back("REQ", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::DataResponse:
			ritems.emplace_back("RSP", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::AnnounceSelf:
			ritems.emplace_back("ANN", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::AnnounceUpdate:
			ritems.emplace_back("ANU", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::ChannelRequest:
			ritems.emplace_back("CRQ", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::ChannelAccept:
			ritems.emplace_back("CAC", st.ref(std::get<Digest>(item.value)));
			break;

		case Type::ServiceType:
			ritems.emplace_back("STP", std::get<UUID>(item.value));
			break;

		case Type::ServiceRef:
			ritems.emplace_back("SRF", st.ref(std::get<Digest>(item.value)));
			break;
		}
	}

	return PartialObject(PartialRecord(std::move(ritems)));
}

}
