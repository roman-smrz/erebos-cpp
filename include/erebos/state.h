#pragma once

#include <erebos/storage.h>
#include <erebos/uuid.h>

#include <memory>
#include <optional>
#include <vector>

namespace erebos {

using std::optional;
using std::shared_ptr;
using std::vector;

template<typename T>
struct SharedType
{
	static const UUID id;
	static T(*const load)(const vector<Ref> &);
	static vector<Ref>(*const store)(const T &);
};

#define DECLARE_SHARED_TYPE(T) \
	template<> const UUID erebos::SharedType<T>::id; \
	template<> T(*const erebos::SharedType<T>::load)(const std::vector<erebos::Ref> &); \
	template<> std::vector<erebos::Ref>(*const erebos::SharedType<T>::store) (const T &);

#define DEFINE_SHARED_TYPE(T, id_, load_, store_) \
	template<> const UUID erebos::SharedType<T>::id { id_ }; \
	template<> T(*const erebos::SharedType<T>::load)(const vector<Ref> &) { load_ }; \
	template<> std::vector<erebos::Ref>(*const erebos::SharedType<T>::store) (const T &) { store_ };

class Identity;

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

	template<class T> T shared() const;
	template<class T> LocalState shared(const T & x) const;

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
	template<class T> T get() const;
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
T LocalState::shared() const
{
	return SharedType<T>::load(lookupShared(SharedType<T>::id));
}

template<class T>
LocalState LocalState::shared(const T & x) const
{
	return updateShared(SharedType<T>::id, SharedType<T>::store(x));
}

template<class T>
T SharedState::get() const
{
	return SharedType<T>::load(lookup(SharedType<T>::id));
}

template<class T>
T SharedState::lens(const SharedState & x)
{
	return x.get<T>();
}

}
