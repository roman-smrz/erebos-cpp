#pragma once

#include <erebos/network.h>

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

namespace chrono = std::chrono;
using chrono::steady_clock;

namespace erebos {

struct Peer
{
	Peer(const Peer &) = delete;
	Peer & operator=(const Peer &) = delete;

	const int sock;
	const sockaddr_in addr;

	variant<monostate,
		shared_ptr<struct WaitingRef>,
		Identity> identity;

	Storage tempStorage;
	PartialStorage partStorage;

	void send(const struct TransportHeader &, const vector<Object> &) const;
	void updateIdentity();
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
	const Peer & peer;
	vector<Digest> missing;

	optional<Ref> check(vector<TransportHeader::Item> * request = nullptr);
};

struct Server::Priv
{
	Priv(const Identity & self);
	~Priv();
	void doListen();
	void doAnnounce();

	Peer & getPeer(const sockaddr_in & paddr);
	void handlePacket(Peer &, const TransportHeader &);

	constexpr static uint16_t discoveryPort { 29665 };
	constexpr static chrono::seconds announceInterval { 60 };

	mutex dataMutex;
	condition_variable announceCondvar;
	bool finish = false;

	Identity self;
	thread threadListen;
	thread threadAnnounce;

	vector<unique_ptr<Peer>> peers;
	vector<struct TransportHeader> outgoing;
	vector<weak_ptr<WaitingRef>> waiting;

	int sock;
	vector<in_addr> bcastAddresses;
};

}
