#include "identity.h"

#include <algorithm>
#include <set>
#include <stdexcept>

using namespace erebos;

using std::async;
using std::nullopt;
using std::runtime_error;
using std::set;

const UUID Identity::sharedTypeId { "0c6c1fe0-f2d7-4891-926b-c332449f7871" };

Identity::Identity(const Priv * p): p(p) {}
Identity::Identity(shared_ptr<const Priv> && p): p(std::move(p)) {}

optional<Identity> Identity::load(const Ref & ref)
{
	return Identity::load(vector { ref });
}

optional<Identity> Identity::load(const vector<Ref> & refs)
{
	vector<Stored<Signed<IdentityData>>> data;
	data.reserve(refs.size());

	for (const auto & ref : refs)
		data.push_back(Stored<Signed<IdentityData>>::load(ref));

	if (auto ptr = Priv::validate(data))
		return Identity(ptr);
	return nullopt;
}

vector<Ref> Identity::store(const Storage & st) const
{
	vector<Ref> res;
	res.reserve(p->data.size());
	for (const auto & x : p->data)
		res.push_back(x.store(st));
	return res;
}

optional<string> Identity::name() const
{
	return p->name.get();
}

optional<Identity> Identity::owner() const
{
	return p->owner;
}

const Identity & Identity::finalOwner() const
{
	if (p->owner)
		return p->owner->finalOwner();
	return *this;
}

Stored<PublicKey> Identity::keyMessage() const
{
	return p->keyMessage;
}

bool Identity::sameAs(const Identity & other) const
{
	// TODO: proper identity check
	return p->data[0]->data->keyIdentity ==
		other.p->data[0]->data->keyIdentity;
}

optional<Ref> Identity::ref() const
{
	if (p->data.size() == 1)
		return p->data[0].ref();
	return nullopt;
}

Identity::Builder Identity::create(const Storage & st)
{
	return Builder (new Builder::Priv {
		.storage = st,
		.keyIdentity = SecretKey::generate(st).pub(),
		.keyMessage = SecretKey::generate(st).pub(),
	});
}

Identity::Builder Identity::modify() const
{
	return Builder (new Builder::Priv {
		.storage = p->data[0].ref().storage(),
		.prev = p->data,
		.keyIdentity = p->data[0]->data->keyIdentity,
		.keyMessage = p->data[0]->data->keyMessage,
	});
}


Identity::Builder::Builder(Priv * p): p(p) {}

Identity Identity::Builder::commit() const
{
	auto idata = p->storage.store(IdentityData {
		.prev = p->prev,
		.name = p->name,
		.owner = p->owner && p->owner->p->data.size() == 1 ?
			optional(p->owner->p->data[0]) : nullopt,
		.keyIdentity = p->keyIdentity,
		.keyMessage = p->keyMessage,
	});

	auto key = SecretKey::load(p->keyIdentity);
	if (!key)
		throw runtime_error("failed to load secret key");

	auto sdata = key->sign(idata);
	if (idata->owner) {
		if (auto okey = SecretKey::load((*idata->owner)->data->keyIdentity))
			sdata = okey->signAdd(sdata);
		else
			throw runtime_error("failed to load secret key");
	}

	auto p = Identity::Priv::validate({ sdata });
	if (!p)
		throw runtime_error("failed to validate committed identity");

	return Identity(std::move(p));
}

void Identity::Builder::name(const string & val)
{
	p->name = val;
}

void Identity::Builder::owner(const Identity & val)
{
	p->owner.emplace(val);
}

IdentityData IdentityData::load(const Ref & ref)
{
	if (auto rec = ref->asRecord()) {
		vector<Stored<Signed<IdentityData>>> prev;
		for (auto p : rec->items("SPREV"))
			if (const auto & x = p.as<Signed<IdentityData>>())
				prev.push_back(x.value());

		if (auto keyIdentity = rec->item("key-id").as<PublicKey>())
			return IdentityData {
				.prev = std::move(prev),
				.name = rec->item("name").asText(),
				.owner = rec->item("owner").as<Signed<IdentityData>>(),
				.keyIdentity = keyIdentity.value(),
				.keyMessage = rec->item("key-msg").as<PublicKey>(),
			};
	}

	return IdentityData {
		.prev = {},
		.name = nullopt,
		.owner = nullopt,
		.keyIdentity = Stored<PublicKey>::load(ref.storage().zref()),
		.keyMessage = nullopt,
	};
}

Ref IdentityData::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto p : prev)
		items.emplace_back("SPREV", p.ref());
	if (name)
		items.emplace_back("name", *name);
	if (owner)
		items.emplace_back("owner", owner->ref());
	items.emplace_back("key-id", keyIdentity.ref());
	if (keyMessage)
		items.emplace_back("key-msg", keyMessage->ref());

	return st.storeObject(Record(std::move(items)));
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

	auto keyMessageItem = lookupProperty(sdata, []
			(const IdentityData & d) { return d.keyMessage.has_value(); });
	if (!keyMessageItem)
		return nullptr;

	auto p = new Priv {
		.data = sdata,
		.name = {},
		.owner = nullopt,
		.keyMessage = keyMessageItem.value()->keyMessage.value(),
	};
	shared_ptr<Priv> ret(p);

	auto ownerProp = lookupProperty(sdata, []
			(const IdentityData & d) { return d.owner.has_value(); });
	if (ownerProp) {
		auto owner = validate({ *ownerProp.value()->owner });
		if (!owner)
			return nullptr;
		p->owner.emplace(Identity(owner));
	}

	p->name = async(std::launch::deferred, [p] () -> optional<string> {
		if (auto d = lookupProperty(p->data, [] (const IdentityData & d) { return d.name.has_value(); }))
			return d.value()->name;
		return nullopt;
	});

	return ret;
}

optional<Stored<IdentityData>> Identity::Priv::lookupProperty(
			const vector<Stored<Signed<IdentityData>>> & data,
		function<bool(const IdentityData &)> sel)
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
