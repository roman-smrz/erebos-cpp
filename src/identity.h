#pragma once

#include <erebos/identity.h>
#include "pubkey.h"

#include <future>

using std::function;
using std::optional;
using std::shared_future;
using std::string;
using std::vector;

namespace erebos {

struct IdentityData
{
	static IdentityData load(const Ref &);
	Ref store(const Storage & st) const;

	const vector<Stored<Signed<IdentityData>>> prev;
	const optional<string> name;
	const optional<Stored<Signed<IdentityData>>> owner;
	const Stored<PublicKey> keyIdentity;
	const optional<Stored<PublicKey>> keyMessage;
};

struct Identity::Priv
{
	vector<Stored<Signed<IdentityData>>> data;
	vector<Stored<Signed<IdentityData>>> updates;
	shared_future<optional<string>> name;
	optional<Identity> owner;
	Stored<PublicKey> keyMessage;

	static bool verifySignatures(const Stored<Signed<IdentityData>> & sdata);
	static shared_ptr<Priv> validate(const vector<Stored<Signed<IdentityData>>> & sdata);
	static optional<Stored<IdentityData>> lookupProperty(
			const vector<Stored<Signed<IdentityData>>> & data,
			function<bool(const IdentityData &)> sel);
};

struct Identity::Builder::Priv
{
	Storage storage;
	vector<Stored<Signed<IdentityData>>> prev = {};
	optional<string> name = nullopt;
	optional<Identity> owner = nullopt;
	Stored<PublicKey> keyIdentity;
	optional<Stored<PublicKey>> keyMessage;
};

}
