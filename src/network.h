#pragma once

#include <erebos/network.h>

#include "network/protocol.h"

#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

#include <netinet/in.h>

using std::condition_variable;
using std::monostate;
using std::mutex;
using std::optional;
using std::shared_lock;
using std::shared_mutex;
using std::shared_ptr;
using std::string;
using std::thread;
using std::unique_ptr;
using std::variant;
using std::vector;
using std::tuple;
using std::weak_ptr;

using std::enable_shared_from_this;

namespace chrono = std::chrono;
using chrono::steady_clock;

namespace erebos {

class ReplyBuilder;
struct WaitingRef;

struct Server::Peer
{
	Peer(const Peer &) = delete;
	Peer & operator=(const Peer &) = delete;

	Priv & server;
	NetworkProtocol::Connection connection;

	variant<monostate,
		shared_ptr<struct WaitingRef>,
		Identity> identity;
	vector<shared_ptr<WaitingRef>> identityUpdates;

	Storage tempStorage;
	PartialStorage partStorage;

	vector<tuple<UUID, shared_ptr<WaitingRef>>> serviceQueue {};
	vector<vector<uint8_t>> secureOutQueue {};

	shared_ptr<erebos::Peer::Priv> lpeer = nullptr;

	void send(const NetworkProtocol::Header &, const vector<Object> &, bool secure);
	void updateIdentity(ReplyBuilder &);
	void updateChannel(ReplyBuilder &);
	void finalizeChannel(ReplyBuilder &, unique_ptr<Channel>);
	void updateService(ReplyBuilder &);
	void trySendOutQueue();
};

struct Peer::Priv : enable_shared_from_this<Peer::Priv>
{
	weak_ptr<Server::Peer> speer;
	weak_ptr<PeerList::Priv> list;
	size_t listIndex;

	void notifyWatchers();
};

struct PeerList::Priv : enable_shared_from_this<PeerList::Priv>
{
	mutex dataMutex;
	vector<shared_ptr<Peer::Priv>> peers;
	vector<function<void(size_t, const Peer *)>> watchers;

	void push(const shared_ptr<Server::Peer> &);
};

struct Server::Priv
{
	Priv(const Head<LocalState> & local, const Identity & self);
	~Priv();

	shared_ptr<Priv> getptr();

	void doListen();
	void doAnnounce();

	bool isSelfAddress(const sockaddr_in6 & paddr);
	Peer * findPeer(NetworkProtocol::Connection::Id cid) const;
	Peer & getPeer(const sockaddr_in6 & paddr);
	Peer & addPeer(NetworkProtocol::Connection conn);
	void handlePacket(Peer &, const NetworkProtocol::Header &, ReplyBuilder &);

	void handleLocalHeadChange(const Head<LocalState> &);

	constexpr static uint16_t discoveryPort { 29665 };
	constexpr static chrono::seconds announceInterval { 60 };

	mutable mutex dataMutex;
	condition_variable announceCondvar;
	bool finish = false;

	shared_mutex selfMutex;
	Identity self;
	const Bhv<LocalState> localState;

	thread threadListen;
	thread threadAnnounce;

	vector<shared_ptr<Peer>> peers;
	PeerList plist;

	vector<struct NetworkProtocol::Header> outgoing;
	vector<weak_ptr<WaitingRef>> waiting;

	NetworkProtocol protocol;
	vector<in_addr> localAddresses;
	vector<in_addr> bcastAddresses;

	// Stop watching before destroying other data
	WatchedHead<LocalState> localHead;

	// Start destruction with finalizing services
	vector<unique_ptr<Service>> services;
};

}
