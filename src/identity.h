#pragma once

#include <erebos/identity.h>
#include "pubkey.h"

#include <future>
#include <variant>

using std::function;
using std::optional;
using std::shared_future;
using std::string;
using std::variant;
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

struct IdentityExtension
{
	static IdentityExtension load(const Ref &);
	Ref store(const Storage & st) const;

	const Stored<Signed<IdentityData>> base;
	const vector<StoredIdentityPart> prev;
	const optional<string> name;
	const optional<StoredIdentityPart> owner;
};

struct Identity::Priv
{
	vector<StoredIdentityPart> data;
	vector<StoredIdentityPart> updates;
	shared_future<optional<string>> name;
	optional<Identity> owner;
	Stored<PublicKey> keyMessage;

	static bool verifySignatures(const StoredIdentityPart & sdata);
	static shared_ptr<Priv> validate(const vector<StoredIdentityPart> & sdata);
	static optional<StoredIdentityPart> lookupProperty(
			const vector<StoredIdentityPart> & data,
			function<bool(const StoredIdentityPart &)> sel);
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
