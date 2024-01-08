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
using std::monostate;
using std::move;
using std::optional;
using std::shared_ptr;
using std::string;
using std::variant;
using std::vector;

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

public:
	// For test usage
	const Priv & priv() const { return *p; }
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
	static PartialRef zcreate(const PartialStorage &);

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

	vector<Ref> previous() const;
	class Generation generation() const;
	vector<Digest> roots() const;

private:
	class Generation generationLocked() const;
	class vector<Digest> rootsLocked() const;

protected:
	Ref(const std::shared_ptr<const Priv> p): PartialRef(p) {}
};

template<class S>
class RecordT
{
public:
	class Item;
	class Items;

private:
	RecordT(const std::shared_ptr<std::vector<Item>> & ptr):
		ptr(ptr) {}

public:
	RecordT(): RecordT(std::vector<Item> {}) {}
	RecordT(const std::vector<Item> &);
	RecordT(std::vector<Item> &&);
	std::vector<uint8_t> encode() const;

	Items items() const;
	Item item(const std::string & name) const;
	Item operator[](const std::string & name) const;
	Items items(const std::string & name) const;

private:
	friend ObjectT<S>;
	std::vector<uint8_t> encodeInner() const;
	static std::optional<RecordT<S>> decode(const S &,
			std::vector<uint8_t>::const_iterator,
			std::vector<uint8_t>::const_iterator);

	const std::shared_ptr<const std::vector<Item>> ptr;
};

template<class S>
class RecordT<S>::Item
{
public:
	struct UnknownType
	{
		string type;
		string value;
	};

	struct Empty {};

	using Integer = int;
	using Text = string;
	using Binary = vector<uint8_t>;
	using Date = ZonedTime;
	using UUID = erebos::UUID;
	using Ref = typename S::Ref;

	using Variant = variant<
		monostate,
		Empty,
		int,
		string,
		vector<uint8_t>,
		ZonedTime,
		UUID,
		typename S::Ref,
		UnknownType>;

	Item(const string & name):
		Item(name, monostate()) {}
	Item(const string & name, Variant value):
		name(name), value(value) {}
	template<typename T>
	Item(const string & name, const Stored<T> & value):
		Item(name, value.ref()) {}

	Item(const Item &) = default;
	Item & operator=(const Item &) = delete;

	operator bool() const;

	optional<Empty> asEmpty() const;
	optional<Integer> asInteger() const;
	optional<Text> asText() const;
	optional<Binary> asBinary() const;
	optional<Date> asDate() const;
	optional<UUID> asUUID() const;
	optional<Ref> asRef() const;
	optional<UnknownType> asUnknown() const;

	template<typename T> optional<Stored<T>> as() const;

	const string name;
	const Variant value;
};

template<class S>
class RecordT<S>::Items
{
public:
	using Empty = typename Item::Empty;
	using Integer = typename Item::Integer;
	using Text = typename Item::Text;
	using Binary = typename Item::Binary;
	using Date = typename Item::Date;
	using UUID = typename Item::UUID;
	using Ref = typename Item::Ref;
	using UnknownType = typename Item::UnknownType;

	Items(shared_ptr<const vector<Item>> items);
	Items(shared_ptr<const vector<Item>> items, string filter);

	class Iterator
	{
		Iterator(const Items & source, size_t idx);
		friend Items;
	public:
		using iterator_category = std::forward_iterator_tag;
		using value_type = Item;
		using difference_type = ssize_t;
		using pointer = const Item *;
		using reference = const Item &;

		Iterator(const Iterator &) = default;
		~Iterator() = default;
		Iterator & operator=(const Iterator &) = default;
		Iterator & operator++();
		value_type operator*() const { return (*source.items)[idx]; }
		bool operator==(const Iterator & other) const { return idx == other.idx; }
		bool operator!=(const Iterator & other) const { return idx != other.idx; }

	private:
		const Items & source;
		size_t idx;
	};

	Iterator begin() const;
	Iterator end() const;

	vector<Empty> asEmpty() const;
	vector<Integer> asInteger() const;
	vector<Text> asText() const;
	vector<Binary> asBinary() const;
	vector<Date> asDate() const;
	vector<UUID> asUUID() const;
	vector<Ref> asRef() const;
	vector<UnknownType> asUnknown() const;

	template<typename T> vector<Stored<T>> as() const;

private:
	const shared_ptr<const vector<Item>> items;
	const optional<string> filter;
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

	operator bool() const;

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

template<class S>
template<typename T>
vector<Stored<T>> RecordT<S>::Items::as() const
{
	auto refs = asRef();
	vector<Stored<T>> res;
	res.reserve(refs.size());
	for (const auto & ref : refs)
		res.push_back(Stored<T>::load(ref));
	return res;
}

class Generation
{
public:
	Generation();
	static Generation next(const vector<Generation> &);

	explicit operator string() const;

private:
	Generation(size_t);
	size_t gen;
};

template<typename T>
class Stored
{
	Stored(Ref ref, T x);
	friend class Storage;
	friend class Head<T>;
public:
	Stored() = default;
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

	Generation generation() const { return p->ref.generation(); }

	std::vector<Stored<T>> previous() const;
	bool precedes(const Stored<T> &) const;

	std::vector<Digest> roots() const { return p->ref.roots(); }

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
	auto refs = p->ref.previous();
	vector<Stored<T>> res;
	res.reserve(refs.size());
	for (const auto & r : refs)
		res.push_back(Stored<T>::load(r));
	return res;
}

template<typename T>
bool precedes(const T & ancestor, const T & descendant)
{
	for (const auto & x : descendant.previous()) {
		if (ancestor == x || precedes(ancestor, x))
			return true;
	}
	return false;
}

template<typename T>
bool Stored<T>::precedes(const Stored<T> & other) const
{
	return erebos::precedes(*this, other);
}

template<typename T>
void filterAncestors(std::vector<T> & xs)
{
	if (xs.size() < 2)
		return;

	std::sort(xs.begin(), xs.end());
	xs.erase(std::unique(xs.begin(), xs.end()), xs.end());

	std::vector<T> old;
	old.swap(xs);

	for (auto i = old.begin(); i != old.end(); i++) {
		bool add = true;
		for (const auto & x : xs)
			if (precedes(*i, x)) {
				add = false;
				break;
			}
		if (add)
			for (auto j = i + 1; j != old.end(); j++)
				if (precedes(*i, *j)) {
					add = false;
					break;
				}
		if (add)
			xs.push_back(std::move(*i));
	}
}

template<class T> class WatchedHead;
template<class T> class HeadBhv;

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
	const Storage & storage() const { return mstored.ref().storage(); }

	optional<Head<T>> reload() const;
	std::optional<Head<T>> update(const std::function<Stored<T>(const Stored<T> &)> &) const;
	WatchedHead<T> watch(const std::function<void(const Head<T> &)> &) const;

	Bhv<T> behavior() const;

private:
	UUID mid;
	Stored<T> mstored;
};

/**
 * Manages registered watch callbacks to Head<T> object using RAII principle.
 */
template<class T>
class WatchedHead : public Head<T>
{
	friend class Head<T>;
	friend class HeadBhv<T>;

	WatchedHead(const Head<T> & h):
		Head<T>(h), watcherId(-1) {}
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

	/// Destructor stops the watching started with Head<T>::watch call.
	/**
	 * Once the WatchedHead object is destroyed, no further Head<T> changes
	 * will trigger the associated callback.
	 *
	 * The destructor also ensures that any scheduled callback run
	 * triggered by a previous change to the head is executed and finished
	 * before the destructor returns. The exception is when the destructor
	 * is called directly from the callback itself, in which case the
	 * destructor returns immediately.
	 */
	~WatchedHead();
};

template<class T>
class HeadBhv : public BhvSource<T>
{
public:
	HeadBhv(const Head<T> & head):
		whead(head)
	{}

	T get(const BhvCurTime &, const std::monostate &) const { return *whead; }

private:
	friend class Head<T>;

	void init()
	{
		whead = whead.watch([wp = weak_ptr<BhvImplBase>(BhvImplBase::shared_from_this()), this] (const Head<T> & cur) {
			// make sure this object still exists
			if (auto ptr = wp.lock()) {
				BhvCurTime ctime;
				whead = cur;
				BhvImplBase::updated(ctime);
			}
		});
	}

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
optional<Head<T>> Head<T>::reload() const
{
	return storage().template head<T>(id());
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
	int wid = storage().watchHead(T::headTypeId, id(), [id = id(), watcher] (const Ref & ref) {
		watcher(Head<T>(id, ref));
	});
	return WatchedHead<T>(*this, wid);
}

template<typename T>
Bhv<T> Head<T>::behavior() const
{
	auto cur = reload();
	auto ret = make_shared<HeadBhv<T>>(cur ? *cur : *this);
	ret->init();
	return ret;
}

template<class T>
WatchedHead<T>::~WatchedHead()
{
	if (watcherId >= 0)
		Head<T>::storage().unwatchHead(
				T::headTypeId, Head<T>::id(), watcherId);
}

template<class T>
vector<Ref> storedRefs(const vector<Stored<T>> & v)
{
	vector<Ref> res;
	res.reserve(v.size());
	for (const auto & x : v)
		res.push_back(x.ref());
	return res;
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
