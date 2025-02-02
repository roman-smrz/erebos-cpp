#include "network.h"

#include "identity.h"
#include "network/protocol.h"
#include "service.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
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

Server::Server(const Head<LocalState> & head, ServerConfig && config):
	p(new Priv(head, *head->identity()))
{
	p->services.reserve(config.services.size());
	for (const auto & ctor : config.services)
		p->services.emplace_back(ctor(*this));

	p->startThreads();
}

Server::Server(const std::shared_ptr<Priv> & ptr):
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

Identity Server::identity() const
{
	shared_lock lock(p->selfMutex);
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

optional<Peer> Server::peer(const Identity & identity) const
{
	scoped_lock lock(p->dataMutex);

	for (auto & peer : p->peers) {
		const auto & pid = peer->identity;
		if (holds_alternative<Identity>(pid))
			if (std::get<Identity>(pid).finalOwner().sameAs(identity))
				return peer->lpeer;
	}

	return nullopt;
}

void Server::addPeer(const string & node) const
{
	return addPeer(node, to_string(Priv::discoveryPort));
}

void Server::addPeer(const string & node, const string & service) const
{
	addrinfo hints {};
	hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	addrinfo *aptr;

	int r = getaddrinfo(node.c_str(), service.c_str(), &hints, &aptr);
	if (r != 0)
		throw runtime_error(string("Server::addPeer: getaddrinfo failed: ") + gai_strerror(r));

	unique_ptr<addrinfo, void(*)(addrinfo*)> result { aptr, &freeaddrinfo };

	for (addrinfo * rp = result.get(); rp != nullptr; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET6) {
			p->getPeer(*(sockaddr_in6 *)rp->ai_addr);
			return;
		}
	}

	throw runtime_error("Server::addPeer: no suitable peer address found");
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

		return addressStr();
	}
	return "<server closed>";
}

optional<Identity> Peer::identity() const
{
	if (auto speer = p->speer.lock()) {
		scoped_lock lock(speer->server.dataMutex);
		if (holds_alternative<Identity>(speer->identity))
			return std::get<Identity>(speer->identity);
	}
	return nullopt;
}

const sockaddr_in6 & Peer::address() const
{
	if (auto speer = p->speer.lock())
		return speer->connection.peerAddress();
	throw runtime_error("Server no longer running");
}

string Peer::addressStr() const
{
	char buf[INET6_ADDRSTRLEN];
	const in6_addr & addr = address().sin6_addr;

	if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) {
		if (IN6_IS_ADDR_V4MAPPED(&addr) && strncmp(buf, "::ffff:", 7) == 0)
			return buf + 7;
		return buf;
	}

	return "<invalid address>";
}

uint16_t Peer::port() const
{
	return ntohs(address().sin6_port);
}

void Peer::Priv::notifyWatchers()
{
	vector<function<void(size_t, const Peer *)>> callbacks;

	{
		if (auto slist = list.lock()) {
			scoped_lock lock(slist->dataMutex);
			callbacks = slist->watchers;
		}
	}

	Peer p(shared_from_this());
	for (const auto & w : callbacks)
		w(listIndex, &p);
}

void Peer::Priv::runServicesHandler(Service & service, Ref ref)
{
	if (auto sptr = speer.lock()) {
		Service::Context ctx { nullptr };

		sptr->server.localHead.update([&] (const Stored<LocalState> & local) {
			ctx = Service::Context(new Service::Context::Priv {
				.ref = ref,
				.peer = erebos::Peer(shared_from_this()),
				.local = local,
			});

			service.handle(ctx);
			return ctx.local();
		});

		ctx.runAfterCommitHooks();
	}
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
		NetworkProtocol::Header header({
			NetworkProtocol::Header::ServiceType { uuid },
			NetworkProtocol::Header::ServiceRef { ref.digest() },
		});

		vector< Object > body;
		if( obj.encode().size() + 2 * NetworkProtocol::Header::itemSize
				<= speer->connection.mtu() )
			body.push_back( obj );

		speer->connection.send( speer->partStorage, move(header), body, true );
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
	vector<function<void(size_t, const Peer *)>> callbacks;
	size_t s;

	{
		scoped_lock lock(dataMutex);
		s = peers.size();

		speer->lpeer.reset(new Peer::Priv);
		speer->lpeer->speer = speer;
		speer->lpeer->list = shared_from_this();
		speer->lpeer->listIndex = s;

		peers.push_back(speer->lpeer);
		callbacks = watchers;
	}

	Peer p(speer->lpeer);
	for (const auto & w : callbacks)
		w(s, &p);
}

size_t PeerList::size() const
{
	scoped_lock lock(p->dataMutex);
	return p->peers.size();
}

Peer PeerList::at(size_t i) const
{
	scoped_lock lock(p->dataMutex);
	return Peer(p->peers.at(i));
}

void PeerList::onUpdate(function<void(size_t, const Peer *)> w)
{
	vector<Peer> peers;

	{
		scoped_lock lock(p->dataMutex);
		for (size_t i = 0; i < p->peers.size(); i++)
			if (auto speer = p->peers[i]->speer.lock())
				peers.emplace_back(speer->lpeer);
		p->watchers.push_back(w);
	}

	for (size_t i = 0; i < peers.size(); i++)
		w(i, &peers[i]);
}


Server::Priv::Priv(const Head<LocalState> & local, const Identity & self):
	self(self),
	// Watching needs to start after self is initialized
	localState(local.behavior()),
	localHead(local.watch(std::bind(&Priv::handleLocalHeadChange, this, std::placeholders::_1)))
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

	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0)
		throw std::system_error(errno, std::generic_category());

	protocol = NetworkProtocol(sock, self);

	int disable = 0;
	// Should be disabled by default, but try to make sure. On platforms
	// where the calls fails, IPv4 might not work.
	setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
				&disable, sizeof(disable));

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
				&enable, sizeof(enable)) < 0)
		throw std::system_error(errno, std::generic_category());

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				&enable, sizeof(enable)) < 0)
		throw std::system_error(errno, std::generic_category());

	sockaddr_in6 laddr = {};
	laddr.sin6_family = AF_INET6;
	laddr.sin6_port = htons(discoveryPort);
	if (::bind(sock, (sockaddr *) &laddr, sizeof(laddr)) < 0)
		throw std::system_error(errno, std::generic_category());
}

Server::Priv::~Priv()
{
	{
		scoped_lock lock(dataMutex);
		finish = true;
	}

	protocol.shutdown();

	announceCondvar.notify_all();
	threadListen.join();
	threadAnnounce.join();
}

shared_ptr<Server::Priv> Server::Priv::getptr()
{
	// Creating temporary object, so just use null deleter
	return shared_ptr<Priv>(this, [](Priv *){});
}

void Server::Priv::startThreads()
{
	threadListen = thread([this] { doListen(); });
	threadAnnounce = thread([this] { doAnnounce(); });
}

void Server::Priv::doListen()
{
	unique_lock lock(dataMutex);

	for (; !finish; lock.lock()) {
		lock.unlock();

		Peer * peer = nullptr;
		auto res = protocol.poll();

		if (holds_alternative<NetworkProtocol::ProtocolClosed>(res))
			break;

		if (const auto * ann = get_if<NetworkProtocol::ReceivedAnnounce>(&res)) {
			if (not isSelfAddress(ann->addr))
				getPeer(ann->addr);
		}

		if (holds_alternative<NetworkProtocol::NewConnection>(res)) {
			auto & conn = get<NetworkProtocol::NewConnection>(res).conn;
			if (not isSelfAddress(conn.peerAddress()))
				peer = &addPeer(move(conn));
		}

		if (holds_alternative<NetworkProtocol::ConnectionReadReady>(res)) {
			peer = findPeer(get<NetworkProtocol::ConnectionReadReady>(res).id);
		}

		if (!peer)
			continue;

		vector<shared_ptr<erebos::Peer::Priv>> notifyPeers;
		vector<tuple<shared_ptr<erebos::Peer::Priv>, Service &, Ref>> readyServices;

		{
			ReplyBuilder reply;

			scoped_lock hlock(dataMutex);
			shared_lock slock(selfMutex);

			if( auto header = peer->connection.receive( peer->partStorage )) {
				handlePacket( *peer, *header, reply );
				peer->updateIdentity( reply, notifyPeers );
				peer->updateChannel( reply );
			} else {
				peer->checkDataResponseStreams( reply );
				peer->updateIdentity( reply, notifyPeers );
			}
			peer->updateService( reply, readyServices );

			if( not reply.header().empty() ) {
				for( const auto & item : reply.header() ) {
					if( const auto * req = get_if< NetworkProtocol::Header::DataRequest >( &item )) {
						const auto & dgst = req->value;
						peer->requestedData.push_back( dgst );
					}
				}

				peer->connection.send(peer->partStorage,
						NetworkProtocol::Header( reply.header() ),
						reply.stream() ? vector< Object >{} : reply.body(), false );
				if( reply.stream() ){
					for( const auto & obj : reply.body() ) {
						auto part = obj.encode();
						reply.stream()->write( part.data(), part.size() );
					}
					reply.stream()->close();
				}
			}

			peer->connection.trySendOutQueue();
		}

		for (const auto & p : notifyPeers)
			p->notifyWatchers();
		for (const auto & [ lpeer, service, ref ] : readyServices)
			lpeer->runServicesHandler(service, ref);
	}
}

void Server::Priv::doAnnounce()
{
	auto pst = self.ref()->storage().derivePartialStorage();

	unique_lock lock(dataMutex);
	auto lastAnnounce = steady_clock::now() - announceInterval;

	while (!finish) {
		auto now = steady_clock::now();

		if (lastAnnounce + announceInterval < now) {
			shared_lock slock(selfMutex);

			for (const auto & in : bcastAddresses) {
				sockaddr_in sin = {};
				sin.sin_family = AF_INET;
				sin.sin_addr = in;
				sin.sin_port = htons(discoveryPort);
				protocol.announceTo(sin);
			}

			lastAnnounce += announceInterval * ((now - lastAnnounce) / announceInterval);
		}

		announceCondvar.wait_until(lock, lastAnnounce + announceInterval);
	}
}

bool Server::Priv::isSelfAddress(const sockaddr_in6 & paddr)
{
	if (IN6_IS_ADDR_V4MAPPED(&paddr.sin6_addr))
		for (const auto & in : localAddresses)
			if (in.s_addr == *reinterpret_cast<const in_addr_t*>(paddr.sin6_addr.s6_addr + 12) &&
					ntohs(paddr.sin6_port) == discoveryPort)
				return true;
	return false;
}

Server::Peer * Server::Priv::findPeer(NetworkProtocol::Connection::Id cid) const
{
	scoped_lock lock(dataMutex);

	for (auto & peer : peers)
		if (peer->connection.id() == cid)
			return peer.get();

	return nullptr;
}

Server::Peer & Server::Priv::getPeer(const sockaddr_in6 & paddr)
{
	shared_ptr<Peer> peer;
	shared_ptr<PeerList::Priv> sptr;

	{
		scoped_lock lock(dataMutex);

		for (auto & peer : peers)
			if (memcmp(&peer->connection.peerAddress(), &paddr, sizeof paddr) == 0)
				return *peer;

		auto st = self.ref()->storage().deriveEphemeralStorage();
		peer.reset(new Peer {
			.server = *this,
			.connection = protocol.connect(paddr),
			.identity = monostate(),
			.identityUpdates = {},
			.tempStorage = st,
			.partStorage = st.derivePartialStorage(),
			});
		peers.push_back(peer);
		sptr = plist.p;
	}

	sptr->push(peer);
	return *peer;
}

Server::Peer & Server::Priv::addPeer(NetworkProtocol::Connection conn)
{
	shared_ptr<Peer> peer;
	shared_ptr<PeerList::Priv> sptr;

	{
		scoped_lock lock(dataMutex);

		auto st = self.ref()->storage().deriveEphemeralStorage();
		peer.reset(new Peer {
			.server = *this,
			.connection = move(conn),
			.identity = monostate(),
			.identityUpdates = {},
			.tempStorage = st,
			.partStorage = st.derivePartialStorage(),
			});
		peers.push_back(peer);
		sptr = plist.p;
	}

	sptr->push(peer);
	return *peer;
}

void Server::Priv::handlePacket(Server::Peer & peer, const NetworkProtocol::Header & header, ReplyBuilder & reply)
{
	unordered_set<Digest> plaintextRefs;
	for (const auto & obj : collectStoredObjects(Stored<Object>::load(*self.ref())))
		plaintextRefs.insert(obj.ref().digest());

	optional<UUID> serviceType;
	shared_ptr< NetworkProtocol::InStream > newDataResponseStream;

	using Header = NetworkProtocol::Header;

	for (const auto & item : header.items) {
		if (const auto * ack = get_if< Header::Acknowledged >( &item )) {
			const auto & dgst = ack->value;
			if (holds_alternative<Stored<ChannelAccept>>(peer.connection.channel()) &&
					std::get<Stored<ChannelAccept>>(peer.connection.channel()).ref().digest() == dgst)
				peer.finalizeChannel(reply,
					std::get<Stored<ChannelAccept>>(peer.connection.channel())->data->channel());
		}

		else if (const auto * req = get_if< Header::DataRequest >( &item )) {
			const auto & dgst = req->value;
			if (holds_alternative<unique_ptr<Channel>>(peer.connection.channel()) ||
					plaintextRefs.find(dgst) != plaintextRefs.end()) {
				if (auto ref = peer.tempStorage.ref(dgst)) {
					reply.header({ NetworkProtocol::Header::DataResponse { ref->digest() } });
					reply.body(*ref);

					if( holds_alternative< unique_ptr< Channel >>( peer.connection.channel() ) and
							reply.size() > peer.connection.mtu() and not reply.stream() )
						reply.stream( peer.connection.openOutStream() );
				}
			}
		}

		else if (const auto * rsp = get_if< Header::DataResponse >( &item )) {
			const auto & dgst = rsp->value;
			if (not holds_alternative< unique_ptr< Channel >>( peer.connection.channel() ))
				reply.header({ Header::Acknowledged { dgst } });

			if (peer.partStorage.loadObject( dgst )) {
				peer.requestedData.erase(
						std::remove( peer.requestedData.begin(), peer.requestedData.end(), dgst ),
						peer.requestedData.end() );
				for (auto & pwref : waiting) {
					if (auto wref = pwref.lock()) {
						if (std::find(wref->missing.begin(), wref->missing.end(), dgst) !=
								wref->missing.end()) {
							if( wref->check( reply, peer.requestedData ))
								pwref.reset();
						}
					}
				}
				waiting.erase(std::remove_if(waiting.begin(), waiting.end(),
							[](auto & wref) { return wref.expired(); }), waiting.end());
			} else if (not newDataResponseStream) {
				for (const auto & item : header.items) {
					if (const auto * streamOpen = get_if< Header::StreamOpen >( &item )) {
						newDataResponseStream = peer.connection.openInStream( streamOpen->value );
						break;
					}
				}
			}
		}

		else if (const auto * ann = get_if<NetworkProtocol::Header::AnnounceSelf>(&item)) {
			const auto & dgst = ann->value;
			if (dgst != self.ref()->digest() &&
					holds_alternative<monostate>(peer.identity)) {
				reply.header({ NetworkProtocol::Header::AnnounceSelf { self.ref()->digest() }});

				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = peer.partStorage.ref(dgst),
					.missing = {},
				});
				waiting.push_back(wref);
				peer.identity = wref;
				wref->check( reply, peer.requestedData );
			}
		}

		else if (const auto * anu = get_if<NetworkProtocol::Header::AnnounceUpdate>(&item)) {
			if (holds_alternative<Identity>(peer.identity)) {
				const auto & dgst = anu->value;

				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = peer.partStorage.ref(dgst),
					.missing = {},
				});
				waiting.push_back(wref);
				peer.identityUpdates.push_back(wref);
				wref->check( reply, peer.requestedData );
			}
		}

		else if (const auto * req = get_if<NetworkProtocol::Header::ChannelRequest>(&item)) {
			const auto & dgst = req->value;
			reply.header({ NetworkProtocol::Header::Acknowledged { dgst } });

			if (holds_alternative<Stored<ChannelRequest>>(peer.connection.channel()) &&
					std::get<Stored<ChannelRequest>>(peer.connection.channel()).ref().digest() < dgst) {
				// TODO: reject request with lower priority
			}

			else if (holds_alternative<Stored<ChannelAccept>>(peer.connection.channel())) {
				// TODO: reject when we already sent accept
			}

			else {
				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = peer.partStorage.ref(dgst),
					.missing = {},
				});
				waiting.push_back(wref);
				peer.connection.channel() = wref;
				wref->check( reply, peer.requestedData );
			}
		}

		else if (const auto * acc = get_if<NetworkProtocol::Header::ChannelAccept>(&item)) {
			const auto & dgst = acc->value;
			if (holds_alternative<Stored<ChannelAccept>>(peer.connection.channel()) &&
					std::get<Stored<ChannelAccept>>(peer.connection.channel()).ref().digest() < dgst) {
				// TODO: reject request with lower priority
			}

			else {
				auto cres = peer.tempStorage.copy(peer.partStorage.ref(dgst));
				if (auto r = get_if<Ref>(&cres)) {
					auto acc = ChannelAccept::load(*r);
					if (holds_alternative<Identity>(peer.identity) &&
							acc.isSignedBy(std::get<Identity>(peer.identity).keyMessage())) {
						reply.header({ NetworkProtocol::Header::Acknowledged { dgst } });
						peer.finalizeChannel(reply, acc.data->channel());
					}
				}
			}
		}

		else if (const auto * stype = get_if<NetworkProtocol::Header::ServiceType>(&item)) {
			if (!serviceType)
				serviceType = stype->value;
		}

		else if (const auto * sref = get_if<NetworkProtocol::Header::ServiceRef>(&item)) {
			if (!serviceType)
				for (auto & item : header.items)
					if (const auto * stype = get_if<NetworkProtocol::Header::ServiceType>(&item)) {
						serviceType = stype->value;
						break;
					}

			if (serviceType) {
				const auto & dgst = sref->value;
				auto pref = peer.partStorage.ref(dgst);

				shared_ptr<WaitingRef> wref(new WaitingRef {
					.storage = peer.tempStorage,
					.ref = pref,
					.missing = {},
				});
				waiting.push_back(wref);
				peer.serviceQueue.emplace_back(*serviceType, wref);
				wref->check( reply, peer.requestedData );
			}
		}
	}

	if( newDataResponseStream )
		peer.dataResponseStreams.push_back( move( newDataResponseStream ));
}

void Server::Priv::handleLocalHeadChange(const Head<LocalState> & head)
{
	scoped_lock lock(dataMutex);
	scoped_lock slock(selfMutex);

	if (auto id = head->identity()) {
		if (*id != self) {
			self = *id;
			protocol.updateIdentity(*id);
		}
	}
}

void Server::Peer::updateIdentity(ReplyBuilder &, vector<shared_ptr<erebos::Peer::Priv>> & notifyPeers)
{
	if (holds_alternative<shared_ptr<WaitingRef>>(identity)) {
		if (auto ref = std::get<shared_ptr<WaitingRef>>(identity)->check())
			if (auto id = Identity::load(*ref)) {
				identity.emplace<Identity>(*id);
				if (lpeer)
					notifyPeers.push_back(lpeer);
			}
	}
	else if (holds_alternative<Identity>(identity)) {
		if (!identityUpdates.empty()) {
			decltype(identityUpdates) keep;
			vector<StoredIdentityPart> updates;

			for (auto wref : identityUpdates) {
				if (auto ref = wref->check())
					updates.push_back(StoredIdentityPart::load(*ref));
				else
					keep.push_back(move(wref));
			}

			identityUpdates = move(keep);

			if (!updates.empty()) {
				auto nid = get<Identity>(identity).update(updates);
				if (nid != get<Identity>(identity)) {
					identity = move(nid);
					if (lpeer)
						notifyPeers.push_back(lpeer);
				}
			}
		}
	}
}

void Server::Peer::updateChannel(ReplyBuilder & reply)
{
	if (!holds_alternative<Identity>(identity))
		return;

	if (holds_alternative<monostate>(connection.channel())) {
		auto req = Channel::generateRequest(tempStorage,
				server.self, std::get<Identity>(identity));
		connection.channel().emplace<Stored<ChannelRequest>>(req);
		reply.header({ NetworkProtocol::Header::ChannelRequest { req.ref().digest() } });
		reply.body(req.ref());
		reply.body(req->data.ref());
		reply.body(req->data->key.ref());
		for (const auto & sig : req->sigs)
			reply.body(sig.ref());
	}

	if (holds_alternative<shared_ptr<WaitingRef>>(connection.channel())) {
		if( auto ref = std::get< shared_ptr< WaitingRef >>( connection.channel())->check( reply, requestedData )) {
			auto req = Stored<ChannelRequest>::load(*ref);
			if (holds_alternative<Identity>(identity) &&
					req->isSignedBy(std::get<Identity>(identity).keyMessage())) {
				if (auto acc = Channel::acceptRequest(server.self, std::get<Identity>(identity), req)) {
					connection.channel().emplace<Stored<ChannelAccept>>(*acc);
					reply.header({ NetworkProtocol::Header::ChannelAccept { acc->ref().digest() } });
					reply.body(acc->ref());
					reply.body(acc.value()->data.ref());
					reply.body(acc.value()->data->key.ref());
					for (const auto & sig : acc.value()->sigs)
						reply.body(sig.ref());
				} else {
					connection.channel() = monostate();
				}
			} else {
				connection.channel() = monostate();
			}
		}
	}
}

void Server::Peer::finalizeChannel(ReplyBuilder & reply, unique_ptr<Channel> ch)
{
	connection.channel().emplace<unique_ptr<Channel>>(move(ch));

	vector<NetworkProtocol::Header::Item> hitems;
	for (const auto & r : server.self.extRefs())
		reply.header(NetworkProtocol::Header::AnnounceUpdate { r.digest() });
	for (const auto & r : server.self.updates())
		reply.header(NetworkProtocol::Header::AnnounceUpdate { r.digest() });
}

void Server::Peer::updateService(ReplyBuilder & reply, vector<tuple<shared_ptr<erebos::Peer::Priv>, Service &, Ref>> & readyServices)
{
	decltype(serviceQueue) next;
	for (auto & x : serviceQueue) {
		if( auto ref = std::get<1>(x)->check( reply, requestedData )) {
			if (lpeer) {
				for (auto & svc : server.services) {
					if (svc->uuid() == std::get<UUID>(x)) {
						readyServices.emplace_back(lpeer, *svc, *ref);
						break;
					}
				}
			}
		} else {
			next.push_back(std::move(x));
		}
	}
	serviceQueue = std::move(next);
}

void Server::Peer::checkDataResponseStreams( ReplyBuilder & reply )
{
	for( auto & s : dataResponseStreams ) {
		if( s->isComplete() ) {
			auto objects = PartialObject::decodeMany( partStorage, s->readAll() );
			vector< PartialRef > refs;
			refs.reserve( objects.size() );
			for( const auto & obj : objects ) {
				auto ref = partStorage.storeObject( obj );
				refs.push_back( ref );
				requestedData.erase(
						std::remove( requestedData.begin(), requestedData.end(), ref.digest() ),
						requestedData.end() );
			}

			for( auto & pwref : server.waiting ) {
				if (auto wref = pwref.lock()) {
					for( const auto & ref : refs ) {
						if( std::find( wref->missing.begin(), wref->missing.end(), ref.digest() ) !=
								wref->missing.end() ) {
							if( wref->check( reply, requestedData ) )
								pwref.reset();
						}
					}
				}
			}
			server.waiting.erase( std::remove_if( server.waiting.begin(), server.waiting.end(),
						[](auto & wref) { return wref.expired(); }), server.waiting.end() );
		}
	}
}


void ReplyBuilder::header(NetworkProtocol::Header::Item && item)
{
	for (const auto & x : mheader)
		if (x == item)
			return;
	mheader.emplace_back(std::move(item));
}

void ReplyBuilder::body(const Ref & ref)
{
	for (const auto & x : mbody)
		if (x.digest() == ref.digest())
			return;

	bodySize += ref->encode().size();
	mbody.push_back(ref);
}

void ReplyBuilder::stream( shared_ptr< NetworkProtocol::OutStream > s )
{
	mheader.emplace_back( Header::StreamOpen{ s->id });
	mstream = move( s );
}

vector<Object> ReplyBuilder::body() const
{
	vector<Object> res;
	res.reserve(mbody.size());
	for (const Ref & ref : mbody)
		res.push_back(*ref);
	return res;
}

size_t ReplyBuilder::size() const
{
	return mheader.size() * Header::itemSize + bodySize;
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

optional<Ref> WaitingRef::check( ReplyBuilder & reply, const vector< Digest > & alreadyRequested)
{
	if (auto r = check())
		return r;

	for( const auto & d : missing ) {
		if( std::find( alreadyRequested.begin(), alreadyRequested.end(), d ) ==
				alreadyRequested.end() )
			reply.header({ NetworkProtocol::Header::DataRequest { d } });
	}

	return nullopt;
}
