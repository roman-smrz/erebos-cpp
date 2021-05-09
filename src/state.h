#pragma once

#include <erebos/state.h>
#include <erebos/identity.h>

#include "pubkey.h"

using std::optional;
using std::shared_ptr;
using std::vector;

namespace erebos {

struct SharedState::Priv
{
	vector<Ref> lookup(UUID) const;

	vector<Stored<struct SharedData>> tip;
};

struct LocalState::Priv
{
	optional<Identity> identity;
	SharedState::Priv shared;
};

struct SharedData
{
	explicit SharedData(vector<Stored<SharedData>> prev,
			UUID type, vector<Ref> value):
		prev(prev), type(type), value(value) {}
	explicit SharedData(const Ref &);
	static SharedData load(const Ref & ref) { return SharedData(ref); }
	Ref store(const Storage &) const;

	vector<Stored<SharedData>> prev;
	UUID type;
	vector<Ref> value;
};

}
