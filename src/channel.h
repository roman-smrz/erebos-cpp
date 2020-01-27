#pragma once

#include <erebos/storage.h>

#include "identity.h"

namespace erebos {

struct ChannelRequestData
{
	Ref store(const Storage & st) const;
	static optional<ChannelRequestData> load(const Ref &);

	const vector<Stored<Signed<IdentityData>>> peers;
	const Stored<PublicKexKey> key;
};

typedef Signed<ChannelRequestData> ChannelRequest;

struct ChannelAcceptData
{
	Ref store(const Storage & st) const;
	static optional<ChannelAcceptData> load(const Ref &);

	Stored<class Channel> channel() const;

	const Stored<ChannelRequest> request;
	const Stored<PublicKexKey> key;
};

typedef Signed<ChannelAcceptData> ChannelAccept;

class Channel
{
public:
	Channel(const vector<Stored<Signed<IdentityData>>> & peers,
			vector<uint8_t> && key):
		peers(peers),
		key(std::move(key))
	{}

	Ref store(const Storage & st) const;
	static optional<Channel> load(const Ref &);

	static Stored<ChannelRequest> generateRequest(const Storage &,
			const Identity & self, const Identity & peer);
	static optional<Stored<ChannelAccept>> acceptRequest(const Identity & self,
			const Identity & peer, const Stored<ChannelRequest> & request);

	vector<uint8_t> encrypt(const vector<uint8_t> &) const;
	optional<vector<uint8_t>> decrypt(const vector<uint8_t> &) const;

private:
	const vector<Stored<Signed<IdentityData>>> peers;
	const vector<uint8_t> key;
};

}
