#include "identity.h"

#include <algorithm>
#include <set>

using namespace erebos;

using std::async;
using std::nullopt;
using std::set;

optional<Identity> Identity::load(const Ref & ref)
{
	return Identity::load(vector { ref });
}

optional<Identity> Identity::load(const vector<Ref> & refs)
{
	vector<Stored<Signed<IdentityData>>> data;
	data.reserve(refs.size());

	for (const auto & ref : refs) {
		auto d = Stored<Signed<IdentityData>>::load(ref);
		if (!d)
			return nullopt;
		data.push_back(*d);
	}

	if (auto ptr = Priv::validate(data))
		return Identity(ptr);
	return nullopt;
}

optional<string> Identity::name() const
{
	return p->name.get();
}

optional<Identity> Identity::owner() const
{
	return p->owner;
}

optional<IdentityData> IdentityData::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	vector<Stored<Signed<IdentityData>>> prev;
	for (auto p : rec->items("SPREV"))
		if (const auto & x = p.as<Signed<IdentityData>>())
			prev.push_back(x.value());

	auto keyIdentity = rec->item("key-id").as<PublicKey>();
	if (!keyIdentity)
		return nullopt;

	return IdentityData {
		.prev = std::move(prev),
		.name = rec->item("name").asText(),
		.owner = rec->item("owner").as<Signed<IdentityData>>(),
		.keyIdentity = keyIdentity.value(),
		.keyMessage = rec->item("key-msg").as<PublicKey>(),
	};
}

bool Identity::Priv::verifySignatures(const Stored<Signed<IdentityData>> & sdata)
{
	if (!sdata->isSignedBy(sdata->data->keyIdentity))
		return false;

	for (const auto & p : sdata->data->prev)
		if (!sdata->isSignedBy(p->data->keyIdentity))
			return false;

	if (sdata->data->owner &&
			!sdata->isSignedBy(sdata->data->owner.value()->data->keyIdentity))
		return false;

	for (const auto & p : sdata->data->prev)
		if (!verifySignatures(p))
			return false;

	return true;
}

shared_ptr<Identity::Priv> Identity::Priv::validate(const vector<Stored<Signed<IdentityData>>> & sdata)
{
	for (const auto & d : sdata)
		if (!verifySignatures(d))
			return nullptr;

	auto p = new Priv {
		.data = sdata,
	};
	shared_ptr<Priv> ret(p);

	auto ownerProp = p->lookupProperty([]
			(const IdentityData & d) { return d.owner.has_value(); });
	if (ownerProp) {
		auto owner = validate({ *ownerProp.value()->owner });
		if (!owner)
			return nullptr;
		p->owner.emplace(Identity(owner));
	}

	p->name = async(std::launch::deferred, [p] () -> optional<string> {
		if (auto d = p->lookupProperty([] (const IdentityData & d) { return d.name.has_value(); }))
			return d.value()->name;
		return nullopt;
	});

	return ret;
}

optional<Stored<IdentityData>> Identity::Priv::lookupProperty(
		function<bool(const IdentityData &)> sel) const
{
	set<Stored<Signed<IdentityData>>> current, prop_heads;

	for (const auto & d : data)
		current.insert(d);

	while (!current.empty()) {
		Stored<Signed<IdentityData>> sdata =
			current.extract(current.begin()).value();

		if (sel(*sdata->data))
			prop_heads.insert(sdata);
		else
			for (const auto & p : sdata->data->prev)
				current.insert(p);
	}

	for (auto x = prop_heads.begin(); x != prop_heads.end(); x++)
		for (auto y = std::next(x); y != prop_heads.end();)
			if (y->precedes(*x))
				y = prop_heads.erase(y);
			else
				y++;

	if (prop_heads.begin() != prop_heads.end())
		return (*prop_heads.begin())->data;
	return nullopt;
}
