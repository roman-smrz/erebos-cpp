#pragma once

#include <erebos/network.h>

#include "channel.h"

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <netinet/in.h>

using std::condition_variable;
using std::monostate;
using std::mutex;
using std::optional;
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
	const sockaddr_in addr;

	variant<monostate,
		shared_ptr<struct WaitingRef>,
		Identity> identity;
	vector<shared_ptr<WaitingRef>> identityUpdates;

	variant<monostate,
		Stored<ChannelRequest>,
		shared_ptr<struct WaitingRef>,
		Stored<ChannelAccept>,
		unique_ptr<Channel>> channel;

	Storage tempStorage;
	PartialStorage partStorage;

	vector<tuple<UUID, shared_ptr<WaitingRef>>> serviceQueue {};
	vector<vector<uint8_t>> secureOutQueue {};

	shared_ptr<erebos::Peer::Priv> lpeer = nullptr;

	void send(const struct TransportHeader &, const vector<Object> &, bool secure);
	void updateIdentity(ReplyBuilder &);
	void updateChannel(ReplyBuilder &);
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

struct TransportHeader
{
	enum class Type {
		Acknowledged,
		DataRequest,
		DataResponse,
		AnnounceSelf,
		AnnounceUpdate,
		ChannelRequest,
		ChannelAccept,
		ServiceType,
		ServiceRef,
	};

	struct Item {
		const Type type;
		const variant<PartialRef, UUID> value;
	};

	TransportHeader(const vector<Item> & items): items(items) {}
	static optional<TransportHeader> load(const PartialRef &);
	static optional<TransportHeader> load(const PartialObject &);
	PartialObject toObject() const;

	const vector<Item> items;
};

class ReplyBuilder
{
public:
	void header(TransportHeader::Item &&);
	void body(const Ref &);

	const vector<TransportHeader::Item> & header() const { return mheader; }
	vector<Object> body() const;

private:
	vector<TransportHeader::Item> mheader;
	vector<Ref> mbody;
};

struct WaitingRef
{
	const Storage storage;
	const PartialRef ref;
	const Server::Peer & peer;
	vector<Digest> missing;

	optional<Ref> check();
	optional<Ref> check(ReplyBuilder &);
};

struct Server::Priv
{
	Priv(const Head<LocalState> & local, const Identity & self,
			vector<unique_ptr<Service>> && svcs);
	~Priv();

	shared_ptr<Priv> getptr();

	void doListen();
	void doAnnounce();

	bool isSelfAddress(const sockaddr_in & paddr);
	Peer & getPeer(const sockaddr_in & paddr);
	void handlePacket(Peer &, const TransportHeader &, ReplyBuilder &);

	void handleLocalHeadChange(const Head<LocalState> &);

	constexpr static uint16_t discoveryPort { 29665 };
	constexpr static chrono::seconds announceInterval { 60 };

	mutex dataMutex;
	condition_variable announceCondvar;
	bool finish = false;

	Identity self;
	Bhv<LocalState> localState;

	thread threadListen;
	thread threadAnnounce;

	vector<shared_ptr<Peer>> peers;
	PeerList plist;

	vector<struct TransportHeader> outgoing;
	vector<weak_ptr<WaitingRef>> waiting;

	int sock;
	vector<in_addr> localAddresses;
	vector<in_addr> bcastAddresses;

	// Stop watching before destroying other data
	WatchedHead<LocalState> localHead;

	// Start destruction with finalizing services
	vector<unique_ptr<Service>> services;
};

}
