#pragma once

#include <erebos/network.h>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <netinet/in.h>

using std::condition_variable;
using std::mutex;
using std::optional;
using std::string;
using std::thread;
using std::variant;
using std::vector;

namespace chrono = std::chrono;
using chrono::steady_clock;

namespace erebos {

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
		const variant<Ref, string> value;
	};

	TransportHeader(const vector<Item> & items): items(items) {}
	static optional<TransportHeader> load(const Ref &);
	Ref store(const Storage & st) const;

	const vector<Item> items;
};

struct Server::Priv
{
	Priv(const Identity & self);
	~Priv();
	void doListen();
	void doAnnounce();

	constexpr static uint16_t discoveryPort { 29665 };
	constexpr static chrono::seconds announceInterval { 60 };

	mutex dataMutex;
	condition_variable announceCondvar;
	bool finish = false;

	Identity self;
	thread threadListen;
	thread threadAnnounce;

	int sock;
	vector<in_addr> bcastAddresses;
};

}
