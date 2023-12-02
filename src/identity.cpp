#include "identity.h"

#include <erebos/state.h>

#include <algorithm>
#include <set>
#include <stdexcept>

using namespace erebos;

using std::async;
using std::get_if;
using std::nullopt;
using std::runtime_error;
using std::set;
using std::visit;

template<class>
inline constexpr bool always_false_v = false;

DEFINE_SHARED_TYPE(optional<Identity>,
		"0c6c1fe0-f2d7-4891-926b-c332449f7871",
		&Identity::load,
		[](const optional<Identity> & id) {
			if (id)
				return id->store();
			return vector<Ref>();
		})

Identity::Identity(const Priv * p): p(p) {}
Identity::Identity(shared_ptr<const Priv> && p): p(std::move(p)) {}

optional<Identity> Identity::load(const Ref & ref)
{
	return Identity::load(vector { ref });
}

optional<Identity> Identity::load(const vector<Ref> & refs)
{
	vector<StoredIdentityPart> data;
	data.reserve(refs.size());

	for (const auto & ref : refs)
		data.push_back(StoredIdentityPart::load(ref));

	return load(data);
}

optional<Identity> Identity::load(const vector<Stored<Signed<IdentityData>>> & data)
{
	vector<StoredIdentityPart> parts;
	parts.reserve(data.size());

	for (const auto & d : data)
		parts.emplace_back(d);

	return load(parts);
}

optional<Identity> Identity::load(const vector<StoredIdentityPart> & data)
{
	if (auto ptr = Priv::validate(data))
		return Identity(ptr);
	return nullopt;
}

vector<Ref> Identity::store() const
{
	vector<Ref> res;
	res.reserve(p->data.size());
	for (const auto & x : p->data)
		res.push_back(x.ref());
	return res;
}

vector<Ref> Identity::store(const Storage & st) const
{
	vector<Ref> res;
	res.reserve(p->data.size());
	for (const auto & x : p->data)
		res.push_back(x.store(st));
	return res;
}

vector<Stored<Signed<IdentityData>>> Identity::data() const
{
	vector<Stored<Signed<IdentityData>>> base;
	base.reserve(p->data.size());

	for (const auto & d : p->data)
		base.push_back(d.base());
	return base;
}

vector<StoredIdentityPart> Identity::extData() const
{
	return p->data;
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

Stored<PublicKey> Identity::keyIdentity() const
{
	return p->data[0].base()->data->keyIdentity;
}

Stored<PublicKey> Identity::keyMessage() const
{
	return p->keyMessage;
}

bool Identity::sameAs(const Identity & other) const
{
	// TODO: proper identity check
	return p->data[0].base()->data->keyIdentity ==
		other.p->data[0].base()->data->keyIdentity;
}

bool Identity::operator==(const Identity & other) const
{
	return p->data == other.p->data &&
		p->updates == other.p->updates;
}

bool Identity::operator!=(const Identity & other) const
{
	return !(*this == other);
}

optional<Ref> Identity::ref() const
{
	if (p->data.size() == 1)
		return p->data[0].base().ref();
	return nullopt;
}

vector<Ref> Identity::refs() const
{
	vector<Ref> res;
	res.reserve(p->data.size());
	for (const auto & idata : p->data)
		res.push_back(idata.ref());
	return res;
}

vector<Ref> Identity::updates() const
{
	vector<Ref> res;
	res.reserve(p->updates.size());
	for (const auto & idata : p->updates)
		res.push_back(idata.ref());
	return res;
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
		.prev = data(),
		.keyIdentity = p->data[0].base()->data->keyIdentity,
		.keyMessage = p->data[0].base()->data->keyMessage,
	});
}

Identity Identity::update(const vector<Stored<Signed<IdentityData>>> & updates) const
{
	vector<StoredIdentityPart> eupdates;
	eupdates.reserve(updates.size());
	for (const auto & u : updates)
		eupdates.emplace_back(u);
	return update(eupdates);
}

static bool intersectsRoots(const vector<Digest> & x, const vector<Digest> & y)
{
	for (size_t i = 0, j = 0;
			i < x.size() && j < y.size(); ) {
		if (x[i] == y[j])
			return true;
		if (x[i] < y[j])
			i++;
		else
			j++;
	}
	return false;
}

Identity Identity::update(const vector<StoredIdentityPart> & updates) const
{
	vector<StoredIdentityPart> ndata = p->data;
	vector<StoredIdentityPart> ownerUpdates = p->updates;

	for (const auto & u : updates) {
		bool isOur = false;
		for (const auto & d : p->data) {
			if (intersectsRoots(u.roots(), d.roots())) {
				isOur = true;
				break;
			}
		}

		if (isOur)
			ndata.emplace_back(u);
		else
			ownerUpdates.emplace_back(u);
	}

	filterAncestors(ndata);
	filterAncestors(ownerUpdates);

	if (auto p = Priv::validate(ndata)) {
		p->updates = move(ownerUpdates);
		if (p->owner && !p->updates.empty())
			p->owner = p->owner->update(p->updates);
		return Identity(move(p));
	}

	return *this;
}


Identity::Builder::Builder(Priv * p): p(p) {}

Identity Identity::Builder::commit() const
{
	auto idata = p->storage.store(IdentityData {
		.prev = p->prev,
		.name = p->name,
		.owner = p->owner && p->owner->p->data.size() == 1 ?
			optional(p->owner->p->data[0].base()) : nullopt,
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

	auto p = Identity::Priv::validate({ StoredIdentityPart(sdata) });
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
		if (auto keyIdentity = rec->item("key-id").as<PublicKey>())
			return IdentityData {
				.prev = rec->items("SPREV").as<Signed<IdentityData>>(),
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

	for (const auto & p : prev)
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

IdentityExtension IdentityExtension::load(const Ref & ref)
{
	if (auto rec = ref->asRecord()) {
		if (auto base = rec->item("SBASE").as<Signed<IdentityData>>()) {
			vector<StoredIdentityPart> prev;
			for (const auto & r : rec->items("SPREV").asRef())
				prev.push_back(StoredIdentityPart::load(r));

			auto ownerRef = rec->item("owner").asRef();
			return IdentityExtension {
				.base = *base,
				.prev = move(prev),
				.name = rec->item("name").asText(),
				.owner = ownerRef ? optional(StoredIdentityPart::load(*ownerRef)) : nullopt,
			};
		}
	}

	return IdentityExtension {
		.base = Stored<Signed<IdentityData>>::load(ref.storage().zref()),
		.prev = {},
		.name = nullopt,
		.owner = nullopt,
	};
}

StoredIdentityPart StoredIdentityPart::load(const Ref & ref)
{
	if (auto srec = ref->asRecord()) {
		if (auto sref = srec->item("SDATA").asRef()) {
			if (auto rec = (*sref)->asRecord()) {
				if (rec->item("SBASE")) {
					return StoredIdentityPart(Stored<Signed<IdentityExtension>>::load(ref));
				}
			}
		}
	}

	return StoredIdentityPart(Stored<Signed<IdentityData>>::load(ref));
}

Ref StoredIdentityPart::store(const Storage & st) const
{
	return visit([&](auto && p) {
		return p.store(st);
	}, part);
}

const Ref & StoredIdentityPart::ref() const
{
	return visit([&](auto && p) -> auto const & {
		return p.ref();
	}, part);
}

const Stored<Signed<IdentityData>> & StoredIdentityPart::base() const
{
	return visit([&](auto && p) -> auto const & {
		using T = std::decay_t<decltype(p)>;
		if constexpr (std::is_same_v<T, Stored<Signed<IdentityData>>>)
			return p;
		else if constexpr (std::is_same_v<T, Stored<Signed<IdentityExtension>>>)
			return p->data->base;
		else
			static_assert(always_false_v<T>, "non-exhaustive visitor!");
	}, part);
}

vector<StoredIdentityPart> StoredIdentityPart::previous() const
{
	return visit([&](auto && p) {
		using T = std::decay_t<decltype(p)>;
		if constexpr (std::is_same_v<T, Stored<Signed<IdentityData>>>) {
			vector<StoredIdentityPart> res;
			res.reserve(p->data->prev.size());
			for (const auto & x : p->data->prev)
				res.emplace_back(x);
			return res;

		} else if constexpr (std::is_same_v<T, Stored<Signed<IdentityExtension>>>) {
			vector<StoredIdentityPart> res;
			res.reserve(1 + p->data->prev.size());
			res.emplace_back(p->data->base);
			for (const auto & x : p->data->prev)
				res.push_back(x);
			return res;

		} else {
			static_assert(always_false_v<T>, "non-exhaustive visitor!");
		}
	}, part);
}

vector<Digest> StoredIdentityPart::roots() const
{
	return visit([&](auto && p) {
		return p.roots();
	}, part);
}

optional<string> StoredIdentityPart::name() const
{
	return visit([&](auto && p) {
		return p->data->name;
	}, part);
}

optional<StoredIdentityPart> StoredIdentityPart::owner() const
{
	return visit([&](auto && p) -> optional<StoredIdentityPart> {
		if (p->data->owner)
			return StoredIdentityPart(p->data->owner.value());
		return nullopt;
	}, part);
}

bool StoredIdentityPart::isSignedBy(const Stored<PublicKey> & key) const
{
	return visit([&](auto && p) {
		return p->isSignedBy(key);
	}, part);
}


bool Identity::Priv::verifySignatures(const StoredIdentityPart & sdata)
{
	if (!sdata.isSignedBy(sdata.base()->data->keyIdentity))
		return false;

	for (const auto & p : sdata.previous())
		if (!sdata.isSignedBy(p.base()->data->keyIdentity))
			return false;

	if (auto owner = sdata.owner())
		if (!sdata.isSignedBy(owner->base()->data->keyIdentity))
			return false;

	for (const auto & p : sdata.previous())
		if (!verifySignatures(p))
			return false;

	return true;
}

shared_ptr<Identity::Priv> Identity::Priv::validate(const vector<StoredIdentityPart> & sdata)
{
	for (const auto & d : sdata)
		if (!verifySignatures(d))
			return nullptr;

	auto keyMessageItem = lookupProperty(sdata, []
			(const StoredIdentityPart & d) { return d.base()->data->keyMessage.has_value(); });
	if (!keyMessageItem)
		return nullptr;

	auto p = new Priv {
		.data = sdata,
		.updates = {},
		.name = {},
		.owner = nullopt,
		.keyMessage = keyMessageItem->base()->data->keyMessage.value(),
	};
	shared_ptr<Priv> ret(p);

	auto ownerProp = lookupProperty(sdata, []
			(const StoredIdentityPart & d) { return d.owner().has_value(); });
	if (ownerProp) {
		auto owner = validate({ ownerProp->owner().value() });
		if (!owner)
			return nullptr;
		p->owner.emplace(Identity(owner));
	}

	p->name = async(std::launch::deferred, [p] () -> optional<string> {
		if (auto d = lookupProperty(p->data, [] (const StoredIdentityPart & d) { return d.name().has_value(); }))
			return d->name();
		return nullopt;
	});

	return ret;
}

optional<StoredIdentityPart> Identity::Priv::lookupProperty(
			const vector<StoredIdentityPart> & data,
		function<bool(const StoredIdentityPart &)> sel)
{
	set<StoredIdentityPart> current, prop_heads;

	for (const auto & d : data)
		current.insert(d);

	while (!current.empty()) {
		StoredIdentityPart sdata =
			current.extract(current.begin()).value();

		if (sel(sdata))
			prop_heads.insert(sdata);
		else
			for (const auto & p : sdata.previous())
				current.insert(p);
	}

	for (auto x = prop_heads.begin(); x != prop_heads.end(); x++)
		for (auto y = prop_heads.begin(); y != prop_heads.end();)
			if (y != x && precedes(*y, *x))
				y = prop_heads.erase(y);
			else
				y++;

	if (prop_heads.begin() != prop_heads.end())
		return *prop_heads.begin();
	return nullopt;
}
