#pragma once

#include <erebos/state.h>

#include "pubkey.h"

using std::optional;
using std::vector;

namespace erebos {

struct LocalState::Priv
{
	optional<Identity> identity;
	vector<Stored<struct SharedState>> shared;
};

struct SharedState
{
	explicit SharedState(vector<Stored<SharedState>> prev,
			UUID type, vector<Ref> value):
		prev(prev), type(type), value(value) {}
	explicit SharedState(const Ref &);
	static SharedState load(const Ref & ref) { return SharedState(ref); }
	Ref store(const Storage &) const;

	vector<Stored<SharedState>> prev;
	UUID type;
	vector<Ref> value;
};

}
