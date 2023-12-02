#include "state.h"

#include "identity.h"

using namespace erebos;

using std::make_shared;

const UUID LocalState::headTypeId { "1d7491a9-7bcb-4eaa-8f13-c8c4c4087e4e" };

LocalState::LocalState():
	p(make_shared<Priv>())
{}

LocalState::LocalState(const Ref & ref):
	LocalState()
{
	auto rec = ref->asRecord();
	if (!rec)
		return;

	if (auto x = rec->item("id").asRef())
		p->identity = Identity::load(*x);

	p->shared.tip = rec->items("shared").as<SharedData>();

	if (p->identity) {
		vector<StoredIdentityPart> updates;
		for (const auto & r : lookupShared(SharedType<optional<Identity>>::id))
			updates.push_back(StoredIdentityPart::load(r));
		if (!updates.empty())
			p->identity = p->identity->update(updates);
	}
}

Ref LocalState::store(const Storage & st) const
{
	vector<Record::Item> items;

	if (p->identity)
		items.emplace_back("id", *p->identity->ref());
	for (const auto & x : p->shared.tip)
		items.emplace_back("shared", x);

	return st.storeObject(Record(std::move(items)));
}

const optional<Identity> & LocalState::identity() const
{
	return p->identity;
}

LocalState LocalState::identity(const Identity & id) const
{
	LocalState ret;
	ret.p->identity = id;
	ret.p->shared = p->shared;
	return ret;
}

vector<Ref> LocalState::lookupShared(UUID type) const
{
	return p->shared.lookup(type);
}

vector<Ref> SharedState::lookup(UUID type) const
{
	return p->lookup(type);
}

vector<Ref> SharedState::Priv::lookup(UUID type) const
{
	vector<Stored<SharedData>> found;
	vector<Stored<SharedData>> process = tip;

	while (!process.empty()) {
		auto cur = std::move(process.back());
		process.pop_back();

		if (cur->type == type) {
			found.push_back(std::move(cur));
			continue;
		}

		for (const auto & x : cur->prev)
			process.push_back(x);
	}

	filterAncestors(found);
	vector<Ref> res;
	for (const auto & s : found)
		for (const auto & v : s->value)
			res.push_back(v);
	return res;
}

vector<Ref> LocalState::sharedRefs() const
{
	vector<Ref> refs;
	for (const auto & x : p->shared.tip)
		refs.push_back(x.ref());
	return refs;
}

LocalState LocalState::sharedRefAdd(const Ref & ref) const
{
	const Storage * st;
	if (p->shared.tip.size() > 0)
		st = &p->shared.tip[0].ref().storage();
	else if (p->identity)
		st = &p->identity->ref()->storage();
	else
		st = &ref.storage();

	LocalState ret;
	ret.p->identity = p->identity;
	ret.p->shared = p->shared;
	ret.p->shared.tip.push_back(SharedData(ref).store(*st));
	filterAncestors(ret.p->shared.tip);
	return ret;
}

LocalState LocalState::updateShared(UUID type, const vector<Ref> & xs) const
{
	const Storage * st;
	if (p->shared.tip.size() > 0)
		st = &p->shared.tip[0].ref().storage();
	else if (p->identity)
		st = &p->identity->ref()->storage();
	else if (xs.size() > 0)
		st = &xs[0].storage();
	else
		return *this;

	LocalState ret;
	ret.p->identity = p->identity;
	ret.p->shared.tip.push_back(SharedData(p->shared.tip, type, xs).store(*st));
	return ret;
}


bool SharedState::operator==(const SharedState & other) const
{
	return p->tip == other.p->tip;
}

bool SharedState::operator!=(const SharedState & other) const
{
	return p->tip != other.p->tip;
}


SharedData::SharedData(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return;

	prev = rec->items("PREV").as<SharedData>();
	if (auto x = rec->item("type").asUUID())
		type = *x;
	value = rec->items("value").asRef();
}

Ref SharedData::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto & x : prev)
		items.emplace_back("PREV", x);
	items.emplace_back("type", type);
	for (const auto & x : value)
		items.emplace_back("value", x);

	return st.storeObject(Record(std::move(items)));
}

template<>
optional<Identity> LocalState::lens<optional<Identity>>(const LocalState & x)
{
	return x.identity();
}

template<>
vector<Ref> LocalState::lens<vector<Ref>>(const LocalState & x)
{
	return x.sharedRefs();
}

template<>
SharedState LocalState::lens<SharedState>(const LocalState & x)
{
	return SharedState(shared_ptr<SharedState::Priv>(x.p, &x.p->shared));
}
