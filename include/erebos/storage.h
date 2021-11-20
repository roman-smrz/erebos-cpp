#pragma once

#include <erebos/frp.h>
#include <erebos/time.h>
#include <erebos/uuid.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace erebos {

class Storage;
class PartialStorage;
class Digest;
class Ref;
class PartialRef;

template<class S> class RecordT;
typedef RecordT<Storage> Record;
typedef RecordT<PartialStorage> PartialRecord;
template<class S> class ObjectT;
typedef ObjectT<Storage> Object;
typedef ObjectT<PartialStorage> PartialObject;
class Blob;

template<typename T> class Stored;
template<typename T> class Head;

using std::bind;
using std::call_once;
using std::make_unique;
using std::move;

class PartialStorage
{
public:
	typedef erebos::PartialRef Ref;

	PartialStorage(const PartialStorage &) = default;
	PartialStorage & operator=(const PartialStorage &) = delete;
	virtual ~PartialStorage() = default;

	bool operator==(const PartialStorage &) const;
	bool operator!=(const PartialStorage &) const;

	PartialRef ref(const Digest &) const;

	std::optional<PartialObject> loadObject(const Digest &) const;
	PartialRef storeObject(const PartialObject &) const;
	PartialRef storeObject(const PartialRecord &) const;
	PartialRef storeObject(const Blob &) const;

protected:
	friend class Storage;
	friend erebos::Ref;
	friend erebos::PartialRef;
	struct Priv;
	const std::shared_ptr<const Priv> p;
	PartialStorage(const std::shared_ptr<const Priv> & p): p(p) {}
};

class Storage : public PartialStorage
{
public:
	typedef erebos::Ref Ref;

	Storage(const std::filesystem::path &);
	Storage(const Storage &) = default;
	Storage & operator=(const Storage &) = delete;

	Storage deriveEphemeralStorage() const;
	PartialStorage derivePartialStorage() const;

	std::optional<Ref> ref(const Digest &) const;
	Ref zref() const;

	std::optional<Object> loadObject(const Digest &) const;
	Ref storeObject(const Object &) const;
	Ref storeObject(const Record &) const;
	Ref storeObject(const Blob &) const;

	std::variant<Ref, std::vector<Digest>> copy(const PartialRef &) const;
	std::variant<Ref, std::vector<Digest>> copy(const PartialObject &) const;
	Ref copy(const Ref &) const;
	Ref copy(const Object &) const;

	template<typename T> Stored<T> store(const T &) const;

	template<typename T> std::optional<Head<T>> head(UUID id) const;
	template<typename T> std::vector<Head<T>> heads() const;
	template<typename T> Head<T> storeHead(const T &) const;
	template<typename T> Head<T> storeHead(const Stored<T> &) const;

	void storeKey(Ref pubref, const std::vector<uint8_t> &) const;
	std::optional<std::vector<uint8_t>> loadKey(Ref pubref) const;

protected:
	template<typename T> friend class Head;
	template<typename T> friend class WatchedHead;

	Storage(const std::shared_ptr<const Priv> & p): PartialStorage(p) {}

	std::optional<Ref> headRef(UUID type, UUID id) const;
	std::vector<std::tuple<UUID, Ref>> headRefs(UUID type) const;
	static UUID storeHead(UUID type, const Ref & ref);
	static bool replaceHead(UUID type, UUID id, const Ref & old, const Ref & ref);
	static std::optional<Ref> updateHead(UUID type, UUID id, const Ref & old, const std::function<Ref(const Ref &)> &);
	int watchHead(UUID type, UUID id, const std::function<void(const Ref &)>) const;
	void unwatchHead(UUID type, UUID id, int watchId) const;
};

class Digest
{
public:
	static constexpr size_t size = 32;

	Digest(const Digest &) = default;
	Digest & operator=(const Digest &) = default;

	explicit Digest(std::array<uint8_t, size> value): value(value) {}
	explicit Digest(const std::string &);
	explicit operator std::string() const;
	bool isZero() const;

	static Digest of(const std::vector<uint8_t> & content);
	template<class S> static Digest of(const ObjectT<S> &);

	const std::array<uint8_t, size> & arr() const { return value; }

	bool operator==(const Digest & other) const { return value == other.value; }
	bool operator!=(const Digest & other) const { return value != other.value; }
	bool operator<(const Digest & other) const { return value < other.value; }
	bool operator<=(const Digest & other) const { return value <= other.value; }
	bool operator>(const Digest & other) const { return value > other.value; }
	bool operator>=(const Digest & other) const { return value >= other.value; }

private:
	std::array<uint8_t, size> value;
};

template<class S>
Digest Digest::of(const ObjectT<S> & obj)
{
	return Digest::of(obj.encode());
}

class PartialRef
{
public:
	PartialRef(const PartialRef &) = default;
	PartialRef(PartialRef &&) = default;
	PartialRef & operator=(const PartialRef &) = default;
	PartialRef & operator=(PartialRef &&) = default;

	static PartialRef create(const PartialStorage &, const Digest &);

	const Digest & digest() const;

	operator bool() const;
	const PartialObject operator*() const;
	std::unique_ptr<PartialObject> operator->() const;

	const PartialStorage & storage() const;

protected:
	friend class Storage;
	struct Priv;
	std::shared_ptr<const Priv> p;
	PartialRef(const std::shared_ptr<const Priv> p): p(p) {}
};

class Ref : public PartialRef
{
public:
	Ref(const Ref &) = default;
	Ref(Ref &&) = default;
	Ref & operator=(const Ref &) = default;
	Ref & operator=(Ref &&) = default;

	bool operator==(const Ref &) const;
	bool operator!=(const Ref &) const;

	static std::optional<Ref> create(const Storage &, const Digest &);
	static Ref zcreate(const Storage &);

	explicit constexpr operator bool() const { return true; }
	const Object operator*() const;
	std::unique_ptr<Object> operator->() const;

	const Storage & storage() const;

protected:
	Ref(const std::shared_ptr<const Priv> p): PartialRef(p) {}
};

template<class S>
class RecordT
{
public:
	class Item {
	public:
		struct UnknownType
		{
			std::string type;
			std::string value;
		};

		typedef std::variant<
			std::monostate,
			int,
			std::string,
			std::vector<uint8_t>,
			ZonedTime,
			UUID,
			typename S::Ref,
			UnknownType> Variant;

		Item(const std::string & name):
			Item(name, std::monostate()) {}
		Item(const std::string & name, Variant value):
			name(name), value(value) {}
		template<typename T>
		Item(const std::string & name, const Stored<T> & value):
			Item(name, value.ref()) {}

		Item(const Item &) = default;
		Item & operator=(const Item &) = delete;

		operator bool() const;

		std::optional<int> asInteger() const;
		std::optional<std::string> asText() const;
		std::optional<std::vector<uint8_t>> asBinary() const;
		std::optional<ZonedTime> asDate() const;
		std::optional<UUID> asUUID() const;
		std::optional<typename S::Ref> asRef() const;
		std::optional<UnknownType> asUnknown() const;

		template<typename T> std::optional<Stored<T>> as() const;

		const std::string name;
		const Variant value;
	};

private:
	RecordT(const std::shared_ptr<std::vector<Item>> & ptr):
		ptr(ptr) {}

public:
	RecordT(const std::vector<Item> &);
	RecordT(std::vector<Item> &&);
	std::vector<uint8_t> encode() const;

	const std::vector<Item> & items() const;
	Item item(const std::string & name) const;
	Item operator[](const std::string & name) const;
	std::vector<Item> items(const std::string & name) const;

private:
	friend ObjectT<S>;
	std::vector<uint8_t> encodeInner() const;
	static std::optional<RecordT<S>> decode(const S &,
			std::vector<uint8_t>::const_iterator,
			std::vector<uint8_t>::const_iterator);

	const std::shared_ptr<const std::vector<Item>> ptr;
};

extern template class RecordT<Storage>;
extern template class RecordT<PartialStorage>;

class Blob
{
public:
	Blob(const std::vector<uint8_t> &);

	const std::vector<uint8_t> & data() const { return *ptr; }
	std::vector<uint8_t> encode() const;

private:
	friend Object;
	friend PartialObject;
	std::vector<uint8_t> encodeInner() const;
	static Blob decode(
			std::vector<uint8_t>::const_iterator,
			std::vector<uint8_t>::const_iterator);

	Blob(std::shared_ptr<std::vector<uint8_t>> ptr): ptr(ptr) {}

	const std::shared_ptr<const std::vector<uint8_t>> ptr;
};

template<class S>
class ObjectT
{
public:
	typedef std::variant<
		RecordT<S>,
		Blob,
		std::monostate> Variants;

	ObjectT(const ObjectT<S> &) = default;
	ObjectT(Variants content): content(content) {}
	ObjectT<S> & operator=(const ObjectT<S> &) = default;

	static std::optional<std::tuple<ObjectT<S>, std::vector<uint8_t>::const_iterator>>
		decodePrefix(const S &,
				std::vector<uint8_t>::const_iterator,
				std::vector<uint8_t>::const_iterator);

	static std::optional<ObjectT<S>> decode(const S &, const std::vector<uint8_t> &);
	static std::optional<ObjectT<S>> decode(const S &,
			std::vector<uint8_t>::const_iterator,
			std::vector<uint8_t>::const_iterator);
	static std::vector<ObjectT<S>> decodeMany(const S &, const std::vector<uint8_t> &);
	std::vector<uint8_t> encode() const;
	static ObjectT<S> load(const typename S::Ref &);

	std::optional<RecordT<S>> asRecord() const;
	std::optional<Blob> asBlob() const;

private:
	friend RecordT<S>;
	friend Blob;

	Variants content;
};

extern template class ObjectT<Storage>;
extern template class ObjectT<PartialStorage>;

template<class S>
template<typename T>
std::optional<Stored<T>> RecordT<S>::Item::as() const
{
	if (auto ref = asRef())
		return Stored<T>::load(ref.value());
	return std::nullopt;
}

template<typename T>
class Stored
{
	Stored(Ref ref, T x);
	friend class Storage;
	friend class Head<T>;
public:
	Stored(const Stored &) = default;
	Stored(Stored &&) = default;
	Stored & operator=(const Stored &) = default;
	Stored & operator=(Stored &&) = default;

	Stored(Ref);
	static Stored<T> load(const Ref &);
	Ref store(const Storage &) const;

	bool operator==(const Stored<T> & other) const
	{ return p->ref.digest() == other.p->ref.digest(); }
	bool operator!=(const Stored<T> & other) const
	{ return p->ref.digest() != other.p->ref.digest(); }
	bool operator<(const Stored<T> & other) const
	{ return p->ref.digest() < other.p->ref.digest(); }
	bool operator<=(const Stored<T> & other) const
	{ return p->ref.digest() <= other.p->ref.digest(); }
	bool operator>(const Stored<T> & other) const
	{ return p->ref.digest() > other.p->ref.digest(); }
	bool operator>=(const Stored<T> & other) const
	{ return p->ref.digest() >= other.p->ref.digest(); }

	void init() const;
	const T & operator*() const { init(); return *p->val; }
	const T * operator->() const { init(); return p->val.get(); }

	std::vector<Stored<T>> previous() const;
	bool precedes(const Stored<T> &) const;

	const Ref & ref() const { return p->ref; }

private:
	struct Priv {
		const Ref ref;
		mutable std::once_flag once {};
		mutable std::unique_ptr<T> val {};
		mutable std::function<T()> init {};
	};
	std::shared_ptr<Priv> p;
};

template<typename T>
void Stored<T>::init() const
{
	call_once(p->once, [this]() {
		p->val = std::make_unique<T>(p->init());
		p->init = decltype(p->init)();
	});
}

template<typename T>
Stored<T> Storage::store(const T & val) const
{
	return Stored(val.store(*this), val);
}

template<typename T>
Stored<T>::Stored(Ref ref, T x):
	p(new Priv {
		.ref = move(ref),
		.val = make_unique<T>(move(x)),
	})
{
	call_once(p->once, [](){});
}

template<typename T>
Stored<T>::Stored(Ref ref):
	p(new Priv {
		.ref = move(ref),
	})
{
	p->init = [p = p.get()]() { return T::load(p->ref); };
}

template<typename T>
Stored<T> Stored<T>::load(const Ref & ref)
{
	return Stored(ref);
}

template<typename T>
Ref Stored<T>::store(const Storage & st) const
{
	if (st == p->ref.storage())
		return p->ref;
	return st.storeObject(*p->ref);
}

template<typename T>
std::vector<Stored<T>> Stored<T>::previous() const
{
	auto rec = p->ref->asRecord();
	if (!rec)
		return {};

	auto sdata = rec->item("SDATA").asRef();
	if (sdata) {
		auto drec = sdata.value()->asRecord();
		if (!drec)
			return {};

		std::vector<Stored<T>> res;
		for (const Record::Item & i : drec->items("SPREV"))
			if (auto x = i.as<T>())
				res.push_back(*x);
		return res;
	}

	std::vector<Stored<T>> res;
	for (const Record::Item & i : rec->items("PREV"))
		if (auto x = i.as<T>())
			res.push_back(*x);
	return res;
}

template<typename T>
bool Stored<T>::precedes(const Stored<T> & other) const
{
	for (const auto & x : other.previous()) {
		if (*this == x || precedes(x))
			return true;
	}
	return false;
}

template<typename T>
void filterAncestors(std::vector<Stored<T>> & xs)
{
	if (xs.size() < 2)
		return;

	std::sort(xs.begin(), xs.end());
	xs.erase(std::unique(xs.begin(), xs.end()), xs.end());

	std::vector<Stored<T>> old;
	old.swap(xs);

	for (auto i = old.begin(); i != old.end(); i++) {
		bool add = true;
		for (const auto & x : xs)
			if (i->precedes(x)) {
				add = false;
				break;
			}
		if (add)
			for (auto j = i + 1; j != old.end(); j++)
				if (i->precedes(*j)) {
					add = false;
					break;
				}
		if (add)
			xs.push_back(std::move(*i));
	}
}

template<class T> class WatchedHead;

template<class T>
class Head
{
	Head(UUID id, Stored<T> stored):
		mid(id), mstored(move(stored)) {}
	Head(UUID id, Ref ref, T val):
		mid(id), mstored(move(ref), move(val)) {}
	friend class Storage;
public:
	Head(UUID id, Ref ref): mid(id), mstored(ref) {}

	const T & operator*() const { return *mstored; }
	const T * operator->() const { return &(*mstored); }

	UUID id() const { return mid; }
	const Stored<T> & stored() const { return mstored; }
	const Ref & ref() const { return mstored.ref(); }

	std::optional<Head<T>> update(const std::function<Stored<T>(const Stored<T> &)> &) const;
	WatchedHead<T> watch(const std::function<void(const Head<T> &)> &) const;

	Bhv<T> behavior() const;

private:
	UUID mid;
	Stored<T> mstored;
};

template<class T>
class WatchedHead : public Head<T>
{
	friend class Head<T>;
	WatchedHead(const Head<T> & h, int watcherId):
		Head<T>(h), watcherId(watcherId) {}
	int watcherId;

public:
	WatchedHead(WatchedHead<T> && h):
		Head<T>(h), watcherId(h.watcherId)
	{ h.watcherId = -1; }

	WatchedHead<T> & operator=(WatchedHead<T> && h)
	{ watcherId = h.watcherId; h.watcherId = -1; return *this; }

	WatchedHead<T> & operator=(const Head<T> & h) {
		if (Head<T>::id() != h.id())
			throw std::runtime_error("WatchedHead ID mismatch");
		static_cast<Head<T> &>(*this) = h;
		return *this;
	}
	~WatchedHead();
};

template<class T>
class HeadBhv : public BhvSource<T>
{
public:
	HeadBhv(const Head<T> & head):
		whead(head.watch([this] (const Head<T> & cur) {
			BhvCurTime ctime;
			whead = cur;
			BhvImplBase::updated(ctime);
		})) {}

	T get(const BhvCurTime &, const std::monostate &) const { return *whead; }

private:
	WatchedHead<T> whead;
};

template<typename T>
std::optional<Head<T>> Storage::head(UUID id) const
{
	if (auto ref = headRef(T::headTypeId, id))
		return Head<T>(id, *ref);
	return std::nullopt;
}

template<typename T>
std::vector<Head<T>> Storage::heads() const
{
	std::vector<Head<T>> res;
	for (const auto & x : headRefs(T::headTypeId))
		res.emplace_back(std::get<UUID>(x), std::get<Ref>(x));
	return res;
}

template<typename T>
Head<T> Storage::storeHead(const T & val) const
{
	auto ref = val.store(*this);
	auto id = storeHead(T::headTypeId, ref);
	return Head(id, ref, val);
}

template<typename T>
Head<T> Storage::storeHead(const Stored<T> & val) const
{
	auto id = storeHead(T::headTypeId, val.ref());
	return Head(id, val);
}

template<typename T>
std::optional<Head<T>> Head<T>::update(const std::function<Stored<T>(const Stored<T> &)> & f) const
{
	auto res = Storage::updateHead(T::headTypeId, mid, ref(), [&f, this](const Ref & r) {
		return f(r.digest() == ref().digest() ? stored() : Stored<T>::load(r)).ref();
	});

	if (!res)
		return std::nullopt;
	if (res->digest() == ref().digest())
		return *this;
	return Head<T>(mid, *res);
}

template<typename T>
WatchedHead<T> Head<T>::watch(const std::function<void(const Head<T> &)> & watcher) const
{
	int wid = stored().ref().storage().watchHead(T::headTypeId, id(), [id = id(), watcher] (const Ref & ref) {
		watcher(Head<T>(id, ref));
	});
	return WatchedHead<T>(*this, wid);
}

template<typename T>
Bhv<T> Head<T>::behavior() const
{
	return make_shared<HeadBhv<T>>(*this);
}

template<class T>
WatchedHead<T>::~WatchedHead()
{
	if (watcherId >= 0)
		Head<T>::stored().ref().storage().unwatchHead(
				T::headTypeId, Head<T>::id(), watcherId);
}

}

namespace std
{
	template<> struct hash<erebos::Digest>
	{
		std::size_t operator()(const erebos::Digest & dgst) const noexcept
		{
			std::size_t res;
			std::memcpy(&res, dgst.arr().data(), sizeof res);
			return res;
		}
	};
}
