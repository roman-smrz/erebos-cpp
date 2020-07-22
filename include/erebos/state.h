#pragma once

#include <erebos/identity.h>
#include <erebos/uuid.h>

#include <optional>

namespace erebos {

using std::optional;
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

private:
	vector<Ref> lookupShared(UUID) const;
	LocalState updateShared(UUID, const vector<Ref> &) const;

	struct Priv;
	std::shared_ptr<Priv> p;
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
	for (const auto x : v)
		refs.push_back(x.ref());
	return updateShared(T::sharedTypeId, refs);
}

}
