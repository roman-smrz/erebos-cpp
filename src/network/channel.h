#pragma once

#include <erebos/storage.h>

#include "../identity.h"

#include <atomic>
#include <memory>

namespace erebos {

using std::array;
using std::atomic;
using std::unique_ptr;

struct ChannelRequestData
{
	Ref store(const Storage & st) const;
	static ChannelRequestData load(const Ref &);

	const vector<Stored<Signed<IdentityData>>> peers;
	const Stored<PublicKexKey> key;
};

typedef Signed<ChannelRequestData> ChannelRequest;

struct ChannelAcceptData
{
	Ref store(const Storage & st) const;
	static ChannelAcceptData load(const Ref &);

	unique_ptr<class Channel> channel() const;

	const Stored<ChannelRequest> request;
	const Stored<PublicKexKey> key;
};

typedef Signed<ChannelAcceptData> ChannelAccept;

class Channel
{
public:
	Channel(const vector<Stored<Signed<IdentityData>>> & peers,
			vector<uint8_t> && key, bool ourRequest):
		peers(peers),
		key(std::move(key)),
		nonceFixedOur({ uint8_t(ourRequest ? 1 : 2), 0, 0, 0, 0, 0 }),
		nonceFixedPeer({ uint8_t(ourRequest ? 2 : 1), 0, 0, 0, 0, 0 })
	{}

	Channel(const Channel &) = delete;
	Channel(Channel &&) = delete;
	Channel & operator=(const Channel &) = delete;
	Channel & operator=(Channel &&) = delete;

	static Stored<ChannelRequest> generateRequest(const Storage &,
			const Identity & self, const Identity & peer);
	static optional<Stored<ChannelAccept>> acceptRequest(const Identity & self,
			const Identity & peer, const Stored<ChannelRequest> & request);

	using Buffer = vector<uint8_t>;
	using BufferCIt = Buffer::const_iterator;
	uint64_t encrypt(BufferCIt plainBegin, BufferCIt plainEnd,
			Buffer & encBuffer, size_t encOffset);
	optional<uint64_t> decrypt(BufferCIt encBegin, BufferCIt encEnd,
			Buffer & decBuffer, size_t decOffset);

private:
	const vector<Stored<Signed<IdentityData>>> peers;
	const vector<uint8_t> key;

	const array<uint8_t, 6> nonceFixedOur;
	const array<uint8_t, 6> nonceFixedPeer;
	atomic<uint64_t> nonceCounter = 0;
};

}
