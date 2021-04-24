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

	for (auto i : rec->items("shared"))
		if (const auto & x = i.as<SharedState>())
			p->shared.push_back(*x);
}

Ref LocalState::store(const Storage & st) const
{
	vector<Record::Item> items;

	if (p->identity)
		items.emplace_back("id", *p->identity->ref());
	for (const auto & x : p->shared)
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
	vector<Stored<SharedState>> found;
	vector<Stored<SharedState>> process = p->shared;

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
	for (const auto & x : p->shared)
		refs.push_back(x.ref());
	return refs;
}

LocalState LocalState::sharedRefAdd(const Ref & ref) const
{
	const Storage * st;
	if (p->shared.size() > 0)
		st = &p->shared[0].ref().storage();
	else if (p->identity)
		st = &p->identity->ref()->storage();
	else
		st = &ref.storage();

	LocalState ret;
	ret.p->identity = p->identity;
	ret.p->shared = p->shared;
	ret.p->shared.push_back(SharedState(ref).store(*st));
	filterAncestors(ret.p->shared);
	return ret;
}

LocalState LocalState::updateShared(UUID type, const vector<Ref> & xs) const
{
	const Storage * st;
	if (p->shared.size() > 0)
		st = &p->shared[0].ref().storage();
	else if (p->identity)
		st = &p->identity->ref()->storage();
	else if (xs.size() > 0)
		st = &xs[0].storage();
	else
		return *this;

	LocalState ret;
	ret.p->identity = p->identity;
	ret.p->shared.push_back(SharedState(p->shared, type, xs).store(*st));
	return ret;
}


SharedState::SharedState(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return;

	for (auto i : rec->items("PREV"))
		if (const auto & x = i.as<SharedState>())
			prev.push_back(*x);

	if (auto x = rec->item("type").asUUID())
		type = *x;

	for (auto i : rec->items("value"))
		if (const auto & x = i.asRef())
			value.push_back(*x);
}

Ref SharedState::store(const Storage & st) const
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
