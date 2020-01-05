#include "network.h"

#include "identity.h"

#include <cstring>

#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>

using std::scoped_lock;
using std::unique_lock;

using namespace erebos;

Server::Server(const Identity & self):
	p(new Priv(self))
{
}

Server::~Server() = default;

Server::Priv::Priv(const Identity & self):
	self(self)
{
	struct ifaddrs * raddrs;
	if (getifaddrs(&raddrs) < 0)
		throw std::system_error(errno, std::generic_category());
	unique_ptr<ifaddrs, void(*)(ifaddrs *)> addrs(raddrs, freeifaddrs);

	for (struct ifaddrs * ifa = addrs.get(); ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
				ifa->ifa_flags & IFF_BROADCAST) {
			bcastAddresses.push_back(((sockaddr_in*)ifa->ifa_broadaddr)->sin_addr);
		}
	}
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		throw std::system_error(errno, std::generic_category());

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
				&enable, sizeof(enable)) < 0)
		throw std::system_error(errno, std::generic_category());

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				&enable, sizeof(enable)) < 0)
		throw std::system_error(errno, std::generic_category());

	sockaddr_in laddr = {};
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons(discoveryPort);
	if (bind(sock, (sockaddr *) &laddr, sizeof(laddr)) < 0)
		throw std::system_error(errno, std::generic_category());

	threadListen = thread([this] { doListen(); });
	threadAnnounce = thread([this] { doAnnounce(); });
}

Server::Priv::~Priv()
{
	{
		scoped_lock lock(dataMutex);
		finish = true;
	}

	announceCondvar.notify_all();
	threadListen.join();
	threadAnnounce.join();

	if (sock >= 0)
		close(sock);
}

void Server::Priv::doListen()
{
	vector<uint8_t> buf(4096);
	unique_lock<mutex> lock(dataMutex);

	while (!finish) {
		sockaddr_in paddr;

		lock.unlock();
		socklen_t addrlen = sizeof(paddr);
		ssize_t ret = recvfrom(sock, buf.data(), buf.size(), 0,
				(sockaddr *) &paddr, &addrlen);
		if (ret < 0)
			throw std::system_error(errno, std::generic_category());

		auto peer = getPeer(paddr);
		if (auto dec = PartialObject::decodePrefix(peer.partStorage,
				buf.begin(), buf.begin() + ret)) {
			if (auto header = TransportHeader::load(std::get<PartialObject>(*dec))) {
				scoped_lock<mutex> hlock(dataMutex);
				handlePacket(peer, *header);
			}
		}

		lock.lock();
	}
}

void Server::Priv::doAnnounce()
{
	unique_lock<mutex> lock(dataMutex);
	auto lastAnnounce = steady_clock::now() - announceInterval;

	while (!finish) {
		auto now = steady_clock::now();

		if (lastAnnounce + announceInterval < now) {
			TransportHeader header({
				{ TransportHeader::Type::AnnounceSelf, *self.ref() }
			});

			vector<uint8_t> bytes = header.toObject().encode();

			for (const auto & in : bcastAddresses) {
				sockaddr_in sin = {};
				sin.sin_family = AF_INET;
				sin.sin_addr = in;
				sin.sin_port = htons(discoveryPort);
				sendto(sock, bytes.data(), bytes.size(), 0, (sockaddr *) &sin, sizeof(sin));
			}

			lastAnnounce += announceInterval * ((now - lastAnnounce) / announceInterval);
		}

		announceCondvar.wait_until(lock, lastAnnounce + announceInterval);
	}
}

Peer & Server::Priv::getPeer(const sockaddr_in & paddr)
{
	for (auto & peer : peers)
		if (memcmp(&peer->addr, &paddr, sizeof paddr) == 0)
			return *peer;

	auto st = self.ref()->storage().deriveEphemeralStorage();
	Peer * peer = new Peer {
		.sock = sock,
		.addr = paddr,
		.tempStorage = st,
		.partStorage = st.derivePartialStorage(),
		};
	peers.emplace_back(peer);
	return *peer;
}

void Server::Priv::handlePacket(Peer & peer, const TransportHeader & header)
{
	unordered_set<Digest> plaintextRefs;
	for (const auto & obj : collectStoredObjects(*Stored<Object>::load(*self.ref())))
		plaintextRefs.insert(obj.ref.digest());

	for (auto & item : header.items) {
		switch (item.type) {
		case TransportHeader::Type::Acknowledged:
			break;

		case TransportHeader::Type::DataRequest: {
			auto pref = std::get<PartialRef>(item.value);
			if (plaintextRefs.find(pref.digest()) != plaintextRefs.end()) {
				if (auto ref = peer.tempStorage.ref(pref.digest())) {
					TransportHeader::Item hitem { TransportHeader::Type::DataResponse, *ref };
					peer.send(TransportHeader({ hitem }), { **ref });
				}
			}
			break;
		}

		case TransportHeader::Type::DataResponse:
			break;

		case TransportHeader::Type::AnnounceSelf:
			break;

		case TransportHeader::Type::AnnounceUpdate:
			break;

		case TransportHeader::Type::ChannelRequest:
			break;

		case TransportHeader::Type::ChannelAccept:
			break;

		case TransportHeader::Type::ServiceType:
			break;

		case TransportHeader::Type::ServiceRef:
			break;

		}
	}
}

void Peer::send(const TransportHeader & header, const vector<Object> & objs)
{
	vector<uint8_t> data, part;

	part = header.toObject().encode();
	data.insert(data.end(), part.begin(), part.end());
	for (const auto & obj : objs) {
		part = obj.encode();
		data.insert(data.end(), part.begin(), part.end());
	}

	sendto(sock, data.data(), data.size(), 0,
			(sockaddr *) &addr, sizeof(addr));
}

optional<TransportHeader> TransportHeader::load(const PartialRef & ref)
{
	return load(*ref);
}

optional<TransportHeader> TransportHeader::load(const PartialObject & obj)
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
					.value = *ref,
				});
		} else if (item.name == "REQ") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::DataRequest,
					.value = *ref,
				});
		} else if (item.name == "RSP") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::DataResponse,
					.value = *ref,
				});
		} else if (item.name == "ANN") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::AnnounceSelf,
					.value = *ref,
				});
		} else if (item.name == "ANU") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::AnnounceUpdate,
					.value = *ref,
				});
		} else if (item.name == "CRQ") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::ChannelRequest,
					.value = *ref,
				});
		} else if (item.name == "CAC") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::ChannelAccept,
					.value = *ref,
				});
		} else if (item.name == "STP") {
			if (auto val = item.asText())
				items.emplace_back(Item {
					.type = Type::ServiceType,
					.value = *val,
				});
		} else if (item.name == "SRF") {
			if (auto ref = item.asRef())
				items.emplace_back(Item {
					.type = Type::ServiceRef,
					.value = *ref,
				});
		}
	}

	return TransportHeader { .items = items };
}

PartialObject TransportHeader::toObject() const
{
	vector<PartialRecord::Item> ritems;

	for (const auto & item : items) {
		switch (item.type) {
		case Type::Acknowledged:
			ritems.emplace_back("ACK", std::get<PartialRef>(item.value));
			break;

		case Type::DataRequest:
			ritems.emplace_back("REQ", std::get<PartialRef>(item.value));
			break;

		case Type::DataResponse:
			ritems.emplace_back("RSP", std::get<PartialRef>(item.value));
			break;

		case Type::AnnounceSelf:
			ritems.emplace_back("ANN", std::get<PartialRef>(item.value));
			break;

		case Type::AnnounceUpdate:
			ritems.emplace_back("ANU", std::get<PartialRef>(item.value));
			break;

		case Type::ChannelRequest:
			ritems.emplace_back("CRQ", std::get<PartialRef>(item.value));
			break;

		case Type::ChannelAccept:
			ritems.emplace_back("CAC", std::get<PartialRef>(item.value));
			break;

		case Type::ServiceType:
			ritems.emplace_back("STP", std::get<string>(item.value));
			break;

		case Type::ServiceRef:
			ritems.emplace_back("SRF", std::get<PartialRef>(item.value));
			break;
		}
	}

	return PartialObject(PartialRecord(std::move(ritems)));
}
