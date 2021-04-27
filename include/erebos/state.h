#pragma once

#include <erebos/identity.h>
#include <erebos/uuid.h>

#include <optional>

namespace erebos {

using std::optional;
using std::shared_ptr;
using std::vector;

class LocalState
{
public:
	LocalState();
	explicit LocalState(const Ref &);
	static LocalState load(const Ref & ref) { return LocalState(ref); }
	Ref store(const Storage &) const;

	static const UUID headTypeId;

	const optional<Identity> & identity() const;
	LocalState identity(const Identity &) const;

	template<class T> optional<T> shared() const;
	template<class T> LocalState shared(const vector<Stored<T>> &) const;
	template<class T> LocalState shared(const Stored<T> & x) const { return shared({ x }); };
	template<class T> LocalState shared(const Storage & st, const T & x)
	{ return updateShared(T::sharedTypeId, x.store(st)); }

	vector<Ref> sharedRefs() const;
	LocalState sharedRefAdd(const Ref &) const;

	template<typename T> static T lens(const LocalState &);

private:
	vector<Ref> lookupShared(UUID) const;
	LocalState updateShared(UUID, const vector<Ref> &) const;

	struct Priv;
	std::shared_ptr<Priv> p;
};

class SharedState
{
public:
	template<class T> optional<T> get() const;
	template<typename T> static T lens(const SharedState &);

	bool operator==(const SharedState &) const;
	bool operator!=(const SharedState &) const;

private:
	vector<Ref> lookup(UUID) const;

	struct Priv;
	SharedState(shared_ptr<Priv> && p): p(std::move(p)) {}
	shared_ptr<Priv> p;
	friend class LocalState;
};

template<class T>
optional<T> LocalState::shared() const
{
	return T::load(lookupShared(T::sharedTypeId));
}

template<class T>
LocalState LocalState::shared(const vector<Stored<T>> & v) const
{
	vector<Ref> refs;
	for (const auto & x : v)
		refs.push_back(x.ref());
	return updateShared(T::sharedTypeId, refs);
}

template<class T>
optional<T> SharedState::get() const
{
	return T::load(lookup(T::sharedTypeId));
}

template<class T>
T SharedState::lens(const SharedState & x)
{
	return T::value_type::load(x.lookup(T::value_type::sharedTypeId));
}

}
