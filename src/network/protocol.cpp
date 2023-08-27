#include "protocol.h"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <mutex>
#include <system_error>

using std::get_if;
using std::holds_alternative;
using std::move;
using std::nullopt;
using std::runtime_error;
using std::scoped_lock;
using std::visit;

namespace erebos {

struct NetworkProtocol::ConnectionPriv
{
	Connection::Id id() const;

	bool send(const PartialStorage &, const Header &,
			const vector<Object> &, bool secure);

	NetworkProtocol * protocol;
	const sockaddr_in6 peerAddress;

	mutex cmutex {};
	vector<uint8_t> buffer {};

	ChannelState channel = monostate();
	vector<vector<uint8_t>> secureOutQueue {};
};


NetworkProtocol::NetworkProtocol():
	sock(-1)
{}

NetworkProtocol::NetworkProtocol(int s, Identity id):
	sock(s),
	self(move(id))
{}

NetworkProtocol::NetworkProtocol(NetworkProtocol && other):
	sock(other.sock),
	self(move(other.self))
{
	other.sock = -1;
}

NetworkProtocol & NetworkProtocol::operator=(NetworkProtocol && other)
{
	sock = other.sock;
	other.sock = -1;
	self = move(other.self);
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

	{
		scoped_lock lock(protocolMutex);
		connections.push_back(conn.get());

		vector<Header::Item> header {
			Header::AnnounceSelf { self->ref()->digest() },
			Header::Version { defaultVersion },
		};
		conn->send(self->ref()->storage(), header, {}, false);
	}

	return Connection(move(conn));
}

void NetworkProtocol::updateIdentity(Identity id)
{
	scoped_lock lock(protocolMutex);
	self = move(id);

	vector<Header::Item> hitems;
	for (const auto & r : self->refs())
		hitems.push_back(Header::AnnounceUpdate { r.digest() });
	for (const auto & r : self->updates())
		hitems.push_back(Header::AnnounceUpdate { r.digest() });

	Header header(hitems);

	for (const auto & conn : connections)
		conn->send(self->ref()->storage(), header, { **self->ref() }, false);
}

void NetworkProtocol::announceTo(variant<sockaddr_in, sockaddr_in6> addr)
{
	vector<uint8_t> bytes;
	{
		scoped_lock lock(protocolMutex);

		if (!self)
			throw runtime_error("NetworkProtocol::announceTo without self identity");

		bytes = Header({
			Header::AnnounceSelf { self->ref()->digest() },
			Header::Version { defaultVersion },
		}).toObject(self->ref()->storage()).encode();
	}

	sendto(bytes, addr);
}

void NetworkProtocol::shutdown()
{
	::shutdown(sock, SHUT_RDWR);
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

void NetworkProtocol::sendto(const vector<uint8_t> & buffer, variant<sockaddr_in, sockaddr_in6> vaddr)
{
	visit([&](auto && addr) {
		::sendto(sock, buffer.data(), buffer.size(), 0,
				(sockaddr *) &addr, sizeof(addr));
	}, vaddr);
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

optional<NetworkProtocol::Header> NetworkProtocol::Connection::receive(const PartialStorage & partStorage)
{
	vector<uint8_t> buf, decrypted;
	auto plainBegin = buf.cbegin();
	auto plainEnd = buf.cbegin();

	{
		scoped_lock lock(p->cmutex);

		if (p->buffer.empty())
			return nullopt;

		buf.swap(p->buffer);

		if ((buf[0] & 0xE0) == 0x80) {
			Channel * channel = nullptr;
			unique_ptr<Channel> channelPtr;

			if (holds_alternative<unique_ptr<Channel>>(p->channel)) {
				channel = std::get<unique_ptr<Channel>>(p->channel).get();
			} else if (holds_alternative<Stored<ChannelAccept>>(p->channel)) {
				channelPtr = std::get<Stored<ChannelAccept>>(p->channel)->data->channel();
				channel = channelPtr.get();
			}

			if (not channel) {
				std::cerr << "unexpected encrypted packet\n";
				return nullopt;
			}

			if (auto dec = channel->decrypt(buf.begin() + 1, buf.end(), decrypted, 0)) {
				if (decrypted.empty()) {
					std::cerr << "empty decrypted content\n";
				}
				else if (decrypted[0] == 0x00) {
					plainBegin = decrypted.begin() + 1;
					plainEnd = decrypted.end();
				}
				else {
					std::cerr << "streams not implemented\n";
					return nullopt;
				}
			}
		}
		else if ((buf[0] & 0xE0) == 0x60) {
			plainBegin = buf.begin();
			plainEnd = buf.end();
		}
	}

	if (auto dec = PartialObject::decodePrefix(partStorage, plainBegin, plainEnd)) {
		if (auto header = Header::load(std::get<PartialObject>(*dec))) {
			auto pos = std::get<1>(*dec);
			while (auto cdec = PartialObject::decodePrefix(partStorage, pos, plainEnd)) {
				partStorage.storeObject(std::get<PartialObject>(*cdec));
				pos = std::get<1>(*cdec);
			}

			return header;
		}
	}

	std::cerr << "invalid packet\n";
	return nullopt;
}

bool NetworkProtocol::Connection::send(const PartialStorage & partStorage,
		const Header & header,
		const vector<Object> & objs, bool secure)
{
	return p->send(partStorage, header, objs, secure);
}

bool NetworkProtocol::ConnectionPriv::send(const PartialStorage & partStorage,
		const Header & header,
		const vector<Object> & objs, bool secure)
{
	vector<uint8_t> data, part, out;

	{
		scoped_lock clock(cmutex);

		Channel * channel = nullptr;
		if (auto uptr = get_if<unique_ptr<Channel>>(&this->channel))
			channel = uptr->get();

		if (channel || secure)
			data.push_back(0x00);

		part = header.toObject(partStorage).encode();
		data.insert(data.end(), part.begin(), part.end());
		for (const auto & obj : objs) {
			part = obj.encode();
			data.insert(data.end(), part.begin(), part.end());
		}

		if (channel) {
			out.push_back(0x80);
			channel->encrypt(data.begin(), data.end(), out, 1);
		} else if (secure) {
			secureOutQueue.emplace_back(move(data));
		} else {
			out = std::move(data);
		}
	}

	if (not out.empty())
		protocol->sendto(out, peerAddress);

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

void NetworkProtocol::Connection::trySendOutQueue()
{
	decltype(p->secureOutQueue) queue;
	{
		scoped_lock clock(p->cmutex);

		if (p->secureOutQueue.empty())
			return;

		if (not holds_alternative<unique_ptr<Channel>>(p->channel))
			return;

		queue.swap(p->secureOutQueue);
	}

	vector<uint8_t> out { 0x80 };
	for (const auto & data : queue) {
		std::get<unique_ptr<Channel>>(p->channel)->encrypt(data.begin(), data.end(), out, 1);
		p->protocol->sendto(out, p->peerAddress);
	}
}


/******************************************************************************/
/* Header                                                                     */
/******************************************************************************/

bool operator==(const NetworkProtocol::Header::Item & left,
		const NetworkProtocol::Header::Item & right)
{
	if (left.index() != right.index())
		return false;

	return visit([&](auto && arg) {
            using T = std::decay_t<decltype(arg)>;
	    return arg.value == std::get<T>(right).value;
	}, left);
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
				items.emplace_back(Acknowledged { ref->digest() });
		} else if (item.name == "VER") {
			if (auto ver = item.asText())
				items.emplace_back(Version { *ver });
		} else if (item.name == "REQ") {
			if (auto ref = item.asRef())
				items.emplace_back(DataRequest { ref->digest() });
		} else if (item.name == "RSP") {
			if (auto ref = item.asRef())
				items.emplace_back(DataResponse { ref->digest() });
		} else if (item.name == "ANN") {
			if (auto ref = item.asRef())
				items.emplace_back(AnnounceSelf { ref->digest() });
		} else if (item.name == "ANU") {
			if (auto ref = item.asRef())
				items.emplace_back(AnnounceUpdate { ref->digest() });
		} else if (item.name == "CRQ") {
			if (auto ref = item.asRef())
				items.emplace_back(ChannelRequest { ref->digest() });
		} else if (item.name == "CAC") {
			if (auto ref = item.asRef())
				items.emplace_back(ChannelAccept { ref->digest() });
		} else if (item.name == "STP") {
			if (auto val = item.asUUID())
				items.emplace_back(ServiceType { *val });
		} else if (item.name == "SRF") {
			if (auto ref = item.asRef())
				items.emplace_back(ServiceRef { ref->digest() });
		}
	}

	return NetworkProtocol::Header(items);
}

PartialObject NetworkProtocol::Header::toObject(const PartialStorage & st) const
{
	vector<PartialRecord::Item> ritems;

	for (const auto & item : items) {
		if (const auto * ptr = get_if<Acknowledged>(&item))
			ritems.emplace_back("ACK", st.ref(ptr->value));

		else if (const auto * ptr = get_if<Version>(&item))
			ritems.emplace_back("VER", ptr->value);

		else if (const auto * ptr = get_if<DataRequest>(&item))
			ritems.emplace_back("REQ", st.ref(ptr->value));

		else if (const auto * ptr = get_if<DataResponse>(&item))
			ritems.emplace_back("RSP", st.ref(ptr->value));

		else if (const auto * ptr = get_if<AnnounceSelf>(&item))
			ritems.emplace_back("ANN", st.ref(ptr->value));

		else if (const auto * ptr = get_if<AnnounceUpdate>(&item))
			ritems.emplace_back("ANU", st.ref(ptr->value));

		else if (const auto * ptr = get_if<ChannelRequest>(&item))
			ritems.emplace_back("CRQ", st.ref(ptr->value));

		else if (const auto * ptr = get_if<ChannelAccept>(&item))
			ritems.emplace_back("CAC", st.ref(ptr->value));

		else if (const auto * ptr = get_if<ServiceType>(&item))
			ritems.emplace_back("STP", ptr->value);

		else if (const auto * ptr = get_if<ServiceRef>(&item))
			ritems.emplace_back("SRF", st.ref(ptr->value));
	}

	return PartialObject(PartialRecord(std::move(ritems)));
}

}
