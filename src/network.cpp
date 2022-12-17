#include "network.h"

#include "identity.h"
#include "service.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>

using std::get;
using std::get_if;
using std::holds_alternative;
using std::move;
using std::runtime_error;
using std::scoped_lock;
using std::to_string;
using std::unique_lock;

using namespace erebos;

Server::Server(const Head<LocalState> & head, vector<unique_ptr<Service>> && svcs):
	p(new Priv(head, *head->identity(), std::move(svcs)))
{
	for (const auto & s : p->services)
		s->serverStarted(*this);
}

Server:: Server(const std::shared_ptr<Priv> & ptr):
	p(ptr)
{
}

Server::~Server() = default;

const Head<LocalState> & Server::localHead() const
{
	return p->localHead;
}

const Bhv<LocalState> & Server::localState() const
{
	return p->localState;
}

const Identity & Server::identity() const
{
	return p->self;
}

Service & Server::svcHelper(const std::type_info & tinfo)
{
	for (auto & s : p->services) {
		auto & sobj = *s;
		if (typeid(sobj) == tinfo)
			return sobj;
	}
	throw runtime_error("service not found");
}

PeerList & Server::peerList() const
{
	return p->plist;
}


Peer::Peer(const shared_ptr<Priv> & p): p(p) {}
Peer::~Peer() = default;

Server Peer::server() const
{
	if (auto speer = p->speer.lock())
		return Server(speer->server.getptr());
	throw runtime_error("Server no longer running");
}

const Storage & Peer::tempStorage() const
{
	if (auto speer = p->speer.lock())
		return speer->tempStorage;
	throw runtime_error("Server no longer running");
}

const PartialStorage & Peer::partialStorage() const
{
	if (auto speer = p->speer.lock())
		return speer->partStorage;
	throw runtime_error("Server no longer running");
}

string Peer::name() const
{
	if (auto speer = p->speer.lock()) {
		if (holds_alternative<Identity>(speer->identity))
			if (auto name = std::get<Identity>(speer->identity).finalOwner().name())
				return *name;
		if (holds_alternative<shared_ptr<WaitingRef>>(speer->identity))
			return string(std::get<shared_ptr<WaitingRef>>(speer->identity)->ref.digest());

		char buf[16];
		if (inet_ntop(AF_INET, &speer->addr.sin_addr, buf, sizeof(buf)))
			return string(buf) + ":" + to_string(ntohs(speer->addr.sin_port));
		return "<invalid address>";
	}
	return "<server closed>";
}

optional<Identity> Peer::identity() const
{
	if (auto speer = p->speer.lock())
		if (holds_alternative<Identity>(speer->identity))
			return std::get<Identity>(speer->identity);
	return nullopt;
}

const sockaddr_in & Peer::address() const
{
	if (auto speer = p->speer.lock())
		return speer->addr;
	throw runtime_error("Server no longer running");
}

void Peer::Priv::notifyWatchers()
{
	if (auto slist = list.lock()) {
		Peer p(shared_from_this());
		for (const auto & w : slist->watchers)
			w(listIndex, &p);
	}
}

bool Peer::hasChannel() const
{
	if (auto speer = p->speer.lock())
		return holds_alternative<unique_ptr<Channel>>(speer->channel);
	return false;
}

bool Peer::send(UUID uuid, const Ref & ref) const
{
	return send(uuid, ref, *ref);
}

bool Peer::send(UUID uuid, const Object & obj) const
{
	if (auto speer = p->speer.lock()) {
		auto ref = speer->tempStorage.storeObject(obj);
		return send(uuid, ref, obj);
	}

	return false;
}

bool Peer::send(UUID uuid, const Ref & ref, const Object & obj) const
{
	if (auto speer = p->speer.lock()) {
		TransportHeader header({
			{ TransportHeader::Type::ServiceType, uuid },
				{ TransportHeader::Type::ServiceRef, ref },
		});
		speer->send(header, { obj }, true);
		return true;
	}

	return false;
}

bool Peer::operator==(const Peer & other) const { return p == other.p; }
bool Peer::operator!=(const Peer & other) const { return p != other.p; }
bool Peer::operator<(const Peer & other) const { return p < other.p; }
bool Peer::operator<=(const Peer & other) const { return p <= other.p; }
bool Peer::operator>(const Peer & other) const { return p > other.p; }
bool Peer::operator>=(const Peer & other) const { return p >= other.p; }


PeerList::PeerList(): p(new Priv) {}
PeerList::PeerList(const shared_ptr<PeerList::Priv> & p): p(p) {}
PeerList::~PeerList() = default;

void PeerList::Priv::push(const shared_ptr<Server::Peer> & speer)
{
	scoped_lock lock(dataMutex);
	size_t s = peers.size();

	speer->lpeer.reset(new Peer::Priv);
	speer->lpeer->speer = speer;
	speer->lpeer->list = shared_from_this();
	speer->lpeer->listIndex = s;

	Peer p(speer->lpeer);

	peers.push_back(speer->lpeer);
	for (const auto & w : watchers)
		w(s, &p);
}

size_t PeerList::size() const
{
	return p->peers.size();
}

Peer PeerList::at(size_t i) const
{
	return Peer(p->peers.at(i));
}

void PeerList::onUpdate(function<void(size_t, const Peer *)> w)
{
	scoped_lock lock(p->dataMutex);
	for (size_t i = 0; i < p->peers.size(); i++) {
		if (auto speer = p->peers[i]->speer.lock()) {
			Peer peer(speer->lpeer);
			w(i, &peer);
		}
	}
	p->watchers.push_back(w);
}


Server::Priv::Priv(const Head<LocalState> & local, const Identity & self,
		vector<unique_ptr<Service>> && svcs):
	self(self),
	// Watching needs to start after self is initialized
	localState(local.behavior()),
	localHead(local.watch(std::bind(&Priv::handleLocalHeadChange, this, std::placeholders::_1))),
	services(std::move(svcs))
{
	struct ifaddrs * raddrs;
	if (getifaddrs(&raddrs) < 0)
		throw std::system_error(errno, std::generic_category());
	unique_ptr<ifaddrs, void(*)(ifaddrs *)> addrs(raddrs, freeifaddrs);

	for (struct ifaddrs * ifa = addrs.get(); ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
				ifa->ifa_flags & IFF_BROADCAST) {
			localAddresses.push_back(((sockaddr_in*)ifa->ifa_addr)->sin_addr);
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
	if (::bind(sock, (sockaddr *) &laddr, sizeof(laddr)) < 0)
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

	if (sock >= 0)
		shutdown(sock, SHUT_RDWR);

	announceCondvar.notify_all();
	threadListen.join();
	threadAnnounce.join();

	if (sock >= 0)
		close(sock);
}

shared_ptr<Server::Priv> Server::Priv::getptr()
{
	// Creating temporary object, so just use null deleter
	return shared_ptr<Priv>(this, [](Priv *){});
}

void Server::Priv::doListen()
{
	vector<uint8_t> buf, decrypted, *current;
	unique_lock<mutex> lock(dataMutex);

	for (; !finish; lock.lock()) {
		sockaddr_in paddr;

		lock.unlock();
		socklen_t addrlen = sizeof(paddr);
		buf.resize(4096);
		ssize_t ret = recvfrom(sock, buf.data(), buf.size(), 0,
				(sockaddr *) &paddr, &addrlen);
		if (ret < 0)
			throw std::system_error(errno, std::generic_category());
		if (ret == 0)
			break;
		buf.resize(ret);

		if (isSelfAddress(paddr))
			continue;

		auto & peer = getPeer(paddr);

		current = &buf;
		if (holds_alternative<unique_ptr<Channel>>(peer.channel)) {
			if (auto dec = std::get<unique_ptr<Channel>>(peer.channel)->decrypt(buf)) {
				decrypted = std::move(*dec);
				current = &decrypted;
			}
		} else if (holds_alternative<Stored<ChannelAccept>>(peer.channel)) {
			if (auto dec = std::get<Stored<ChannelAccept>>(peer.channel)->
					data->channel()->decrypt(buf)) {
				decrypted = std::move(*dec);
				current = &decrypted;
			}
		}

		if (auto dec = PartialObject::decodePrefix(peer.partStorage,
				current->begin(), current->end())) {
			if (auto header = TransportHeader::load(std::get<PartialObject>(*dec))) {
				auto pos = std::get<1>(*dec);
				while (auto cdec = PartialObject::decodePrefix(peer.partStorage,
							pos, current->end())) {
					peer.partStorage.storeObject(std::get<PartialObject>(*cdec));
					pos = std::get<1>(*cdec);
				}

				ReplyBuilder reply;

				scoped_lock<mutex> hlock(dataMutex);
				handlePacket(peer, *header, reply);
				peer.updateIdentity(reply);
				peer.updateChannel(reply);
				peer.updateService(reply);

				if (!reply.header().empty())
					peer.send(TransportHeader(reply.header()), reply.body(), false);

				peer.trySendOutQueue();
			}
		} else {
			std::cerr << "invalid packet\n";
		}
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

bool Server::Priv::isSelfAddress(const sockaddr_in & paddr)
{
	for (const auto & in : localAddresses)
		if (in.s_addr == paddr.sin_addr.s_addr &&
				ntohs(paddr.sin_port) == discoveryPort)
			return true;
	return false;
}

Server::Peer & Server::Priv::getPeer(const sockaddr_in & paddr)
{
	for (auto & peer : peers)
		if (memcmp(&peer->addr, &paddr, sizeof paddr) == 0)
			return *peer;

	auto st = self.ref()->storage().deriveEphemeralStorage();
	shared_ptr<Peer> peer(new Peer {
		.server = *this,
		.addr = paddr,
		.identity = monostate(),
		.identityUpdates = {},
		.channel = monostate(),
		.tempStorage = st,
		.partStorage = st.derivePartialStorage(),
		});
	peers.push_back(peer);
	plist.p->push(peer);
	return *peer;
}

void Server::Priv::handlePacket(Server::Peer & peer, const TransportHeader & header, ReplyBuilder & reply)
{
	unordered_set<Digest> plaintextRefs;
	for (const auto & obj : collectStoredObjects(Stored<Object>::load(*self.ref())))
		plaintextRefs.insert(obj.ref().digest());

	optional<UUID> serviceType;

	for (auto & item : header.items) {
		switch (item.type) {
		case TransportHeader::Type::Acknowledged:
			if (auto pref = std::get<PartialRef>(item.value)) {
				if (holds_alternative<Stored<ChannelAccept>>(peer.channel) &&
						std::get<Stored<ChannelAccept>>(peer.channel).ref().digest() == pref.digest())
					peer.channel.emplace<unique_ptr<Channel>>
						(std::get<Stored<ChannelAccept>>(peer.channel)->data->channel());
			}
			break;

		case TransportHeader::Type::DataRequest: {
			auto pref = std::get<PartialRef>(item.value);
			if (holds_alternative<unique_ptr<Channel>>(peer.channel) ||
					plaintextRefs.find(pref.digest()) != plaintextRefs.end()) {
				if (auto ref = peer.tempStorage.ref(pref.digest())) {
					TransportHeader::Item hitem { TransportHeader::Type::DataResponse, *ref };
					reply.header({ TransportHeader::Type::DataResponse, *ref });
					reply.body(*ref);
				}
			}
			break;
		}

		case TransportHeader::Type::DataResponse:
			if (auto pref = std::get<PartialRef>(item.value)) {
				reply.header({ TransportHeader::Type::Acknowledged, pref });
				for (auto & pwref : waiting) {
					if (auto wref = pwref.lock()) {
						if (std::find(wref->missing.begin(), wref->missing.end(), pref.digest()) !=
								wref->missing.end()) {
							if (wref->check(reply))
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

			if (holds_alternative<monostate>(peer.identity)) {
				reply.header({ TransportHeader::Type::AnnounceSelf, *self.ref()});

				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = pref,
					.peer = peer,
					.missing = {},
				});
				waiting.push_back(wref);
				peer.identity = wref;
				wref->check(reply);
			}
			break;
		}

		case TransportHeader::Type::AnnounceUpdate:
			if (holds_alternative<Identity>(peer.identity)) {
				auto pref = std::get<PartialRef>(item.value);
				reply.header({ TransportHeader::Type::Acknowledged, pref });

				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = pref,
					.peer = peer,
					.missing = {},
				});
				waiting.push_back(wref);
				peer.identityUpdates.push_back(wref);
				wref->check(reply);
			}
			break;

		case TransportHeader::Type::ChannelRequest:
			if (auto pref = std::get<PartialRef>(item.value)) {
				reply.header({ TransportHeader::Type::Acknowledged, pref });

				if (holds_alternative<Stored<ChannelRequest>>(peer.channel) &&
						std::get<Stored<ChannelRequest>>(peer.channel).ref().digest() < pref.digest())
					break;

				if (holds_alternative<Stored<ChannelAccept>>(peer.channel))
					break;

				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = pref,
					.peer = peer,
					.missing = {},
				});
				waiting.push_back(wref);
				peer.channel = wref;
				wref->check(reply);
			}
			break;

		case TransportHeader::Type::ChannelAccept:
			if (auto pref = std::get<PartialRef>(item.value)) {
				if (holds_alternative<Stored<ChannelAccept>>(peer.channel) &&
						std::get<Stored<ChannelAccept>>(peer.channel).ref().digest() < pref.digest())
					break;

				auto cres = peer.tempStorage.copy(pref);
				if (auto r = std::get_if<Ref>(&cres)) {
					auto acc = ChannelAccept::load(*r);
					if (holds_alternative<Identity>(peer.identity) &&
							acc.isSignedBy(std::get<Identity>(peer.identity).keyMessage())) {
						reply.header({ TransportHeader::Type::Acknowledged, pref });
						peer.channel.emplace<unique_ptr<Channel>>(acc.data->channel());
					}
				}
			}
			break;

		case TransportHeader::Type::ServiceType:
			if (!serviceType)
				serviceType = std::get<UUID>(item.value);
			break;

		case TransportHeader::Type::ServiceRef:
			if (!serviceType)
				for (auto & item : header.items)
					if (item.type == TransportHeader::Type::ServiceType) {
						serviceType = std::get<UUID>(item.value);
						break;
					}
			if (!serviceType)
				break;

			if (auto pref = std::get<PartialRef>(item.value)) {
				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = pref,
					.peer = peer,
					.missing = {},
				});
				waiting.push_back(wref);
				peer.serviceQueue.emplace_back(*serviceType, wref);
				wref->check(reply);
			}
		}
	}
}

void Server::Priv::handleLocalHeadChange(const Head<LocalState> & head)
{
	scoped_lock lock(dataMutex);
	if (auto id = head->identity()) {
		if (*id != self) {
			self = *id;

			vector<TransportHeader::Item> hitems;
			for (const auto & r : self.refs())
				hitems.push_back(TransportHeader::Item {
					TransportHeader::Type::AnnounceUpdate, r });
			for (const auto & r : self.updates())
				hitems.push_back(TransportHeader::Item {
					TransportHeader::Type::AnnounceUpdate, r });

			TransportHeader header(hitems);

			for (const auto & peer : peers)
				peer->send(header, { **self.ref() }, false);
		}
	}
}

void Server::Peer::send(const TransportHeader & header, const vector<Object> & objs, bool secure)
{
	vector<uint8_t> data, part, out;

	part = header.toObject().encode();
	data.insert(data.end(), part.begin(), part.end());
	for (const auto & obj : objs) {
		part = obj.encode();
		data.insert(data.end(), part.begin(), part.end());
	}

	if (holds_alternative<unique_ptr<Channel>>(channel))
		out = std::get<unique_ptr<Channel>>(channel)->encrypt(data);
	else if (secure)
		secureOutQueue.emplace_back(move(data));
	else
		out = std::move(data);

	if (!out.empty())
		sendto(server.sock, out.data(), out.size(), 0,
				(sockaddr *) &addr, sizeof(addr));
}

void Server::Peer::updateIdentity(ReplyBuilder &)
{
	if (holds_alternative<shared_ptr<WaitingRef>>(identity)) {
		if (auto ref = std::get<shared_ptr<WaitingRef>>(identity)->check())
			if (auto id = Identity::load(*ref)) {
				identity.emplace<Identity>(*id);
				if (lpeer)
					lpeer->notifyWatchers();
			}
	}
	else if (holds_alternative<Identity>(identity)) {
		if (!identityUpdates.empty()) {
			decltype(identityUpdates) keep;
			vector<Stored<Signed<IdentityData>>> updates;

			for (auto wref : identityUpdates) {
				if (auto ref = wref->check())
					updates.push_back(Stored<Signed<IdentityData>>::load(*ref));
				else
					keep.push_back(move(wref));
			}

			identityUpdates = move(keep);

			if (!updates.empty()) {
				auto nid = get<Identity>(identity).update(updates);
				if (nid != get<Identity>(identity)) {
					identity = move(nid);
					if (lpeer)
						lpeer->notifyWatchers();
				}
			}
		}
	}
}

void Server::Peer::updateChannel(ReplyBuilder & reply)
{
	if (!holds_alternative<Identity>(identity))
		return;

	if (holds_alternative<monostate>(channel)) {
		auto req = Channel::generateRequest(tempStorage,
				server.self, std::get<Identity>(identity));
		channel.emplace<Stored<ChannelRequest>>(req);
		reply.header({ TransportHeader::Type::ChannelRequest, req.ref() });
		reply.body(req.ref());
		reply.body(req->data.ref());
		reply.body(req->data->key.ref());
		for (const auto & sig : req->sigs)
			reply.body(sig.ref());
	}

	if (holds_alternative<shared_ptr<WaitingRef>>(channel)) {
		if (auto ref = std::get<shared_ptr<WaitingRef>>(channel)->check(reply)) {
			auto req = Stored<ChannelRequest>::load(*ref);
			if (holds_alternative<Identity>(identity) &&
					req->isSignedBy(std::get<Identity>(identity).keyMessage())) {
				if (auto acc = Channel::acceptRequest(server.self, std::get<Identity>(identity), req)) {
					channel.emplace<Stored<ChannelAccept>>(*acc);
					reply.header({ TransportHeader::Type::ChannelAccept, acc->ref() });
					reply.body(acc->ref());
					reply.body(acc.value()->data.ref());
					reply.body(acc.value()->data->key.ref());
					for (const auto & sig : acc.value()->sigs)
						reply.body(sig.ref());
				} else {
					channel = monostate();
				}
			} else {
				channel = monostate();
			}
		}
	}
}

void Server::Peer::updateService(ReplyBuilder & reply)
{
	decltype(serviceQueue) next;
	for (auto & x : serviceQueue) {
		if (auto ref = std::get<1>(x)->check(reply)) {
			if (lpeer) {
				Service::Context ctx { nullptr };

				server.localHead.update([&] (const Stored<LocalState> & local) {
					ctx = Service::Context(new Service::Context::Priv {
						.ref = *ref,
						.peer = erebos::Peer(lpeer),
						.local = local,
					});

					for (auto & svc : server.services) {
						if (svc->uuid() == std::get<UUID>(x)) {
							svc->handle(ctx);
							break;
						}
					}

					return ctx.local();
				});

				ctx.runAfterCommitHooks();
			}
		} else {
			next.push_back(std::move(x));
		}
	}
	serviceQueue = std::move(next);
}

void Server::Peer::trySendOutQueue()
{
	if (secureOutQueue.empty())
		return;

	if (!holds_alternative<unique_ptr<Channel>>(channel))
		return;

	for (const auto & data : secureOutQueue) {
		auto out = std::get<unique_ptr<Channel>>(channel)->encrypt(data);

		sendto(server.sock, out.data(), out.size(), 0,
				(sockaddr *) &addr, sizeof(addr));
	}

	secureOutQueue.clear();
}


void ReplyBuilder::header(TransportHeader::Item && item)
{
	for (const auto & x : mheader)
		if (x.type == item.type && x.value == item.value)
			return;
	mheader.emplace_back(std::move(item));
}

void ReplyBuilder::body(const Ref & ref)
{
	for (const auto & x : mbody)
		if (x.digest() == ref.digest())
			return;
	mbody.push_back(ref);
}

vector<Object> ReplyBuilder::body() const
{
	vector<Object> res;
	res.reserve(mbody.size());
	for (const Ref & ref : mbody)
		res.push_back(*ref);
	return res;
}


optional<Ref> WaitingRef::check()
{
	if (auto r = storage.ref(ref.digest()))
		return *r;

	auto res = storage.copy(ref);
	if (auto r = get_if<Ref>(&res))
		return *r;

	missing = std::get<vector<Digest>>(res);
	return nullopt;
}

optional<Ref> WaitingRef::check(ReplyBuilder & reply)
{
	if (auto r = check())
		return r;

	for (const auto & d : missing)
		reply.header({ TransportHeader::Type::DataRequest, peer.partStorage.ref(d) });

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
			if (auto val = item.asUUID())
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

	return TransportHeader(items);
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
			ritems.emplace_back("STP", std::get<UUID>(item.value));
			break;

		case Type::ServiceRef:
			ritems.emplace_back("SRF", std::get<PartialRef>(item.value));
			break;
		}
	}

	return PartialObject(PartialRecord(std::move(ritems)));
}
