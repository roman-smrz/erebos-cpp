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
	explicit NetworkProtocol(int sock, Identity self);
	NetworkProtocol(const NetworkProtocol &) = delete;
	NetworkProtocol(NetworkProtocol &&);
	NetworkProtocol & operator=(const NetworkProtocol &) = delete;
	NetworkProtocol & operator=(NetworkProtocol &&);
	~NetworkProtocol();

	static constexpr char defaultVersion[] = "0.1";

	class Connection;
	class Stream;
	class InStream;
	class OutStream;

	struct Header;
	struct StreamData;

	struct ReceivedAnnounce;
	struct NewConnection;
	struct ConnectionReadReady;
	struct ProtocolClosed {};

	using PollResult = variant<
		ReceivedAnnounce,
		NewConnection,
		ConnectionReadReady,
		ProtocolClosed>;

	PollResult poll();

	struct Cookie { vector<uint8_t> value; };

	using ChannelState = variant<monostate,
		Stored<ChannelRequest>,
		shared_ptr<struct WaitingRef>,
		Stored<ChannelAccept>,
		unique_ptr<Channel>>;

	Connection connect(sockaddr_in6 addr);

	void updateIdentity(Identity self);
	void announceTo(variant<sockaddr_in, sockaddr_in6> addr);

	void shutdown();

private:
	bool recvfrom(vector<uint8_t> & buffer, sockaddr_in6 & addr);
	void sendto(const vector<uint8_t> & buffer, variant<sockaddr_in, sockaddr_in6> addr);

	void sendCookie(variant<sockaddr_in, sockaddr_in6> addr);
	optional<Connection> verifyNewConnection(const Header & header, sockaddr_in6 addr);

	Cookie generateCookie(variant<sockaddr_in, sockaddr_in6> addr) const;
	bool verifyCookie(variant<sockaddr_in, sockaddr_in6> addr, const Cookie & cookie) const;

	int sock;

	mutex protocolMutex;
	vector<uint8_t> buffer;

	optional<Identity> self;

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
	size_t mtu() const;

	optional<Header> receive(const PartialStorage &);
	bool send(const PartialStorage &, NetworkProtocol::Header,
			const vector<Object> &, bool secure);
	bool send( const StreamData & chunk );

	void close();

	shared_ptr< InStream > openInStream( uint8_t sid );
	shared_ptr< OutStream > openOutStream();

	// temporary:
	ChannelState & channel();
	void trySendOutQueue();

private:
	static variant< monostate, Header, StreamData >
		parsePacket(vector<uint8_t> & buf,
				Channel * channel, const PartialStorage & st,
				optional<uint64_t> & secure);

	unique_ptr<ConnectionPriv> p;
};

class NetworkProtocol::Stream
{
	friend class NetworkProtocol;
	friend class NetworkProtocol::Connection;

protected:
	Stream(uint8_t id_);

public:
	void close();

protected:
	bool hasDataLocked() const;

	size_t writeLocked( const uint8_t * buf, size_t size );
	size_t readLocked( uint8_t * buf, size_t size );

public:
	const uint8_t id;

protected:
	bool closed { false };
	vector< uint8_t > writeBuffer;
	vector< uint8_t > readBuffer;
	vector< uint8_t >::const_iterator readPtr;
	mutable mutex streamMutex;
};

class NetworkProtocol::InStream : public NetworkProtocol::Stream
{
	friend class NetworkProtocol;
	friend class NetworkProtocol::Connection;

protected:
	InStream(uint8_t id): Stream( id ) {}

public:
	bool isComplete() const;
	vector< uint8_t > readAll();
	size_t read( uint8_t * buf, size_t size );

protected:
	void writeChunk( StreamData chunk );
	bool tryUseChunkLocked( const StreamData & chunk );

private:
	uint64_t nextSequence { 0 };
	vector< StreamData > outOfOrderChunks;
};

class NetworkProtocol::OutStream : public NetworkProtocol::Stream
{
	friend class NetworkProtocol;
	friend class NetworkProtocol::Connection;

protected:
	OutStream(uint8_t id): Stream( id ) {}

public:
	size_t write( const uint8_t * buf, size_t size );

private:
	StreamData getNextChunkLocked( size_t size );

	uint64_t nextSequence { 0 };
};

struct NetworkProtocol::ReceivedAnnounce { sockaddr_in6 addr; Digest digest; };
struct NetworkProtocol::NewConnection { Connection conn; };
struct NetworkProtocol::ConnectionReadReady { Connection::Id id; };

struct NetworkProtocol::Header
{
	struct Acknowledged { Digest value; };
	struct AcknowledgedSingle { uint64_t value; };
	struct Version { string value; };
	struct Initiation { Digest value; };
	struct CookieSet { Cookie value; };
	struct CookieEcho { Cookie value; };
	struct DataRequest { Digest value; };
	struct DataResponse { Digest value; };
	struct AnnounceSelf { Digest value; };
	struct AnnounceUpdate { Digest value; };
	struct ChannelRequest { Digest value; };
	struct ChannelAccept { Digest value; };
	struct ServiceType { UUID value; };
	struct ServiceRef { Digest value; };
	struct StreamOpen { uint8_t value; };

	using Item = variant<
		Acknowledged,
		AcknowledgedSingle,
		Version,
		Initiation,
		CookieSet,
		CookieEcho,
		DataRequest,
		DataResponse,
		AnnounceSelf,
		AnnounceUpdate,
		ChannelRequest,
		ChannelAccept,
		ServiceType,
		ServiceRef,
		StreamOpen>;

	static constexpr size_t itemSize = 78; /* estimate for size of ref-containing headers */

	Header(const vector<Item> & items): items(items) {}
	static optional<Header> load(const PartialRef &);
	static optional<Header> load(const PartialObject &);
	PartialObject toObject(const PartialStorage &) const;

	template<class T> const T * lookupFirst() const;
	bool isAcknowledged() const;

	vector<Item> items;
};

struct NetworkProtocol::StreamData
{
	uint8_t id;
	uint8_t sequence;
	vector< uint8_t > data;
};

template<class T>
const T * NetworkProtocol::Header::lookupFirst() const
{
	for (const auto & h : items)
		if (auto ptr = std::get_if<T>(&h))
			return ptr;
	return nullptr;
}

bool operator==(const NetworkProtocol::Header::Item &, const NetworkProtocol::Header::Item &);
inline bool operator!=(const NetworkProtocol::Header::Item & left,
		const NetworkProtocol::Header::Item & right)
{ return not (left == right); }

inline bool operator==(const NetworkProtocol::Cookie & left, const NetworkProtocol::Cookie & right)
{ return left.value == right.value; }

}
