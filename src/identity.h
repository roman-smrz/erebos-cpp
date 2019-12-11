#pragma once

#include <erebos/identity.h>
#include "pubkey.h"

using std::function;
using std::optional;
using std::string;
using std::vector;

namespace erebos {

class IdentityData
{
public:
	static optional<IdentityData> load(const Ref &);

	const vector<Stored<Signed<IdentityData>>> prev;
	const optional<string> name;
	const optional<Stored<Signed<IdentityData>>> owner;
	const Stored<PublicKey> keyIdentity;
	const optional<Stored<PublicKey>> keyMessage;
};

class Identity::Priv
{
public:
	vector<Stored<Signed<IdentityData>>> data;
	shared_future<optional<string>> name;
	optional<Identity> owner;

	static bool verifySignatures(const Stored<Signed<IdentityData>> & sdata);
	static shared_ptr<Priv> validate(const vector<Stored<Signed<IdentityData>>> & sdata);
	optional<Stored<IdentityData>> lookupProperty(
			function<bool(const IdentityData &)> sel) const;
};

}
