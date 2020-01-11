#include "network.h"

#include "identity.h"

#include <algorithm>
#include <cstring>

#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>

using std::holds_alternative;
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

		auto & peer = getPeer(paddr);
		if (auto dec = PartialObject::decodePrefix(peer.partStorage,
				buf.begin(), buf.begin() + ret)) {
			if (auto header = TransportHeader::load(std::get<PartialObject>(*dec))) {
				auto pos = std::get<1>(*dec);
				while (auto cdec = PartialObject::decodePrefix(peer.partStorage,
							pos, buf.begin() + ret)) {
					peer.partStorage.storeObject(std::get<PartialObject>(*cdec));
					pos = std::get<1>(*cdec);
				}
				scoped_lock<mutex> hlock(dataMutex);
				handlePacket(peer, *header);
				peer.updateIdentity();
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
		.identity = monostate(),
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

	vector<TransportHeader::Item> replyHeaders;
	vector<Object> replyBody;

	for (auto & item : header.items) {
		switch (item.type) {
		case TransportHeader::Type::Acknowledged:
			break;

		case TransportHeader::Type::DataRequest: {
			auto pref = std::get<PartialRef>(item.value);
			if (plaintextRefs.find(pref.digest()) != plaintextRefs.end()) {
				if (auto ref = peer.tempStorage.ref(pref.digest())) {
					TransportHeader::Item hitem { TransportHeader::Type::DataResponse, *ref };
					replyHeaders.push_back({ TransportHeader::Type::DataResponse, *ref });
					replyBody.push_back(**ref);
				}
			}
			break;
		}

		case TransportHeader::Type::DataResponse:
			if (auto pref = std::get<PartialRef>(item.value)) {
				replyHeaders.push_back({ TransportHeader::Type::Acknowledged, pref });
				for (auto & pwref : waiting) {
					if (auto wref = pwref.lock()) {
						if (std::find(wref->missing.begin(), wref->missing.end(), pref.digest()) !=
								wref->missing.end()) {
							if (wref->check(&replyHeaders))
								pwref.reset();
						}
					}
				}
				waiting.erase(std::remove_if(waiting.begin(), waiting.end(),
							[](auto & wref) { return wref.expired(); }), waiting.end());
			}
			break;

		case TransportHeader::Type::AnnounceSelf: {
			auto pref = std::get<PartialRef>(item.value);
			if (pref.digest() == self.ref()->digest())
				break;

			if (holds_alternative<monostate>(peer.identity))
				replyHeaders.push_back({ TransportHeader::Type::AnnounceSelf, *self.ref()});

			shared_ptr<WaitingRef> wref(new WaitingRef {
				.storage = peer.tempStorage,
				.ref = pref,
				.peer = peer,
				.missing = {},
			});
			waiting.push_back(wref);
			peer.identity = wref;
			wref->check(&replyHeaders);
			break;
		}

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

	if (!replyHeaders.empty())
		peer.send(TransportHeader(replyHeaders), replyBody);
}

void Peer::send(const TransportHeader & header, const vector<Object> & objs) const
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

void Peer::updateIdentity()
{
	if (holds_alternative<shared_ptr<WaitingRef>>(identity))
		if (auto ref = std::get<shared_ptr<WaitingRef>>(identity)->check())
			if (auto id = Identity::load(*ref))
				identity.emplace<Identity>(*id);
}


optional<Ref> WaitingRef::check(vector<TransportHeader::Item> * request)
{
	if (auto r = storage.ref(ref.digest()))
		return *r;

	auto res = storage.copy(ref);
	if (auto r = std::get_if<Ref>(&res))
		return *r;

	missing = std::get<vector<Digest>>(res);
	if (request)
		for (const auto & d : missing)
			request->push_back({ TransportHeader::Type::DataRequest, peer.partStorage.ref(d) });

	return nullopt;
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
