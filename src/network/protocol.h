#pragma once

#include "channel.h"

#include <erebos/storage.h>

#include <netinet/in.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <variant>
#include <vector>
#include <optional>

namespace erebos {

using std::mutex;
using std::optional;
using std::unique_ptr;
using std::variant;
using std::vector;

class NetworkProtocol
{
public:
	NetworkProtocol();
	explicit NetworkProtocol(int sock);
	NetworkProtocol(const NetworkProtocol &) = delete;
	NetworkProtocol(NetworkProtocol &&);
	NetworkProtocol & operator=(const NetworkProtocol &) = delete;
	NetworkProtocol & operator=(NetworkProtocol &&);
	~NetworkProtocol();

	class Connection;

	struct Header;

	struct NewConnection;
	struct ConnectionReadReady;
	struct ProtocolClosed {};

	using PollResult = variant<
		NewConnection,
		ConnectionReadReady,
		ProtocolClosed>;

	PollResult poll();

	using ChannelState = variant<monostate,
		Stored<ChannelRequest>,
		shared_ptr<struct WaitingRef>,
		Stored<ChannelAccept>,
		unique_ptr<Channel>>;

	Connection connect(sockaddr_in6 addr);

	bool recvfrom(vector<uint8_t> & buffer, sockaddr_in6 & addr);
	void sendto(const vector<uint8_t> & buffer, sockaddr_in addr);
	void sendto(const vector<uint8_t> & buffer, sockaddr_in6 addr);

	void shutdown();

private:
	int sock;

	mutex protocolMutex;
	vector<uint8_t> buffer;

	struct ConnectionPriv;
	vector<ConnectionPriv *> connections;
};

class NetworkProtocol::Connection
{
	friend class NetworkProtocol;
	Connection(unique_ptr<ConnectionPriv> p);
public:
	Connection(const Connection &) = delete;
	Connection(Connection &&);
	Connection & operator=(const Connection &) = delete;
	Connection & operator=(Connection &&);
	~Connection();

	using Id = uintptr_t;
	Id id() const;

	const sockaddr_in6 & peerAddress() const;

	optional<Header> receive(const PartialStorage &);
	bool send(const PartialStorage &, const NetworkProtocol::Header &,
			const vector<Object> &, bool secure);

	void close();

	// temporary:
	ChannelState & channel();
	void trySendOutQueue();

private:
	unique_ptr<ConnectionPriv> p;
};

struct NetworkProtocol::NewConnection { Connection conn; };
struct NetworkProtocol::ConnectionReadReady { Connection::Id id; };

struct NetworkProtocol::Header
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
		const variant<Digest, UUID> value;

		bool operator==(const Item &) const;
		bool operator!=(const Item & other) const { return !(*this == other); }
	};

	Header(const vector<Item> & items): items(items) {}
	static optional<Header> load(const PartialRef &);
	static optional<Header> load(const PartialObject &);
	PartialObject toObject(const PartialStorage &) const;

	const vector<Item> items;
};

class ReplyBuilder
{
public:
	void header(NetworkProtocol::Header::Item &&);
	void body(const Ref &);

	const vector<NetworkProtocol::Header::Item> & header() const { return mheader; }
	vector<Object> body() const;

private:
	vector<NetworkProtocol::Header::Item> mheader;
	vector<Ref> mbody;
};

struct WaitingRef
{
	const Storage storage;
	const PartialRef ref;
	vector<Digest> missing;

	optional<Ref> check();
	optional<Ref> check(ReplyBuilder &);
};

}
