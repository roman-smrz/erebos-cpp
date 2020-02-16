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
using std::weak_ptr;

using std::enable_shared_from_this;

namespace chrono = std::chrono;
using chrono::steady_clock;

namespace erebos {

struct Server::Peer
{
	Peer(const Peer &) = delete;
	Peer & operator=(const Peer &) = delete;

	Priv & server;
	const sockaddr_in addr;

	variant<monostate,
		shared_ptr<struct WaitingRef>,
		Identity> identity;

	variant<monostate,
		Stored<ChannelRequest>,
		shared_ptr<struct WaitingRef>,
		Stored<ChannelAccept>,
		Stored<Channel>> channel;

	Storage tempStorage;
	PartialStorage partStorage;

	shared_ptr<erebos::Peer::Priv> lpeer = nullptr;

	void send(const struct TransportHeader &, const vector<Object> &) const;
	void updateIdentity(struct ReplyBuilder &);
	void updateChannel(struct ReplyBuilder &);
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
		const variant<PartialRef, string> value;
	};

	TransportHeader(const vector<Item> & items): items(items) {}
	static optional<TransportHeader> load(const PartialRef &);
	static optional<TransportHeader> load(const PartialObject &);
	PartialObject toObject() const;

	const vector<Item> items;
};

struct WaitingRef
{
	const Storage storage;
	const PartialRef ref;
	const Server::Peer & peer;
	vector<Digest> missing;

	optional<Ref> check(vector<TransportHeader::Item> * request = nullptr);
};

struct ReplyBuilder
{
	vector<TransportHeader::Item> header;
	vector<Object> body;
};

struct Server::Priv
{
	Priv(const Identity & self);
	~Priv();
	void doListen();
	void doAnnounce();

	Peer & getPeer(const sockaddr_in & paddr);
	void handlePacket(Peer &, const TransportHeader &, ReplyBuilder &);

	constexpr static uint16_t discoveryPort { 29665 };
	constexpr static chrono::seconds announceInterval { 60 };

	mutex dataMutex;
	condition_variable announceCondvar;
	bool finish = false;

	Identity self;
	thread threadListen;
	thread threadAnnounce;

	vector<shared_ptr<Peer>> peers;
	PeerList plist;

	vector<struct TransportHeader> outgoing;
	vector<weak_ptr<WaitingRef>> waiting;

	int sock;
	vector<in_addr> bcastAddresses;
};

}
