#pragma once

#include <array>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
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
	PartialStorage(const std::shared_ptr<const Priv> p): p(p) {}
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

	std::optional<Object> loadObject(const Digest &) const;
	Ref storeObject(const Object &) const;
	Ref storeObject(const Record &) const;
	Ref storeObject(const Blob &) const;

	std::variant<Ref, std::vector<Digest>> copy(const PartialRef &) const;
	std::variant<Ref, std::vector<Digest>> copy(const PartialObject &) const;
	Ref copy(const Ref &) const;
	Ref copy(const Object &) const;

	template<typename T> Stored<T> store(const T &) const;

	void storeKey(Ref pubref, const std::vector<uint8_t> &) const;
	std::optional<std::vector<uint8_t>> loadKey(Ref pubref) const;

protected:
	Storage(const std::shared_ptr<const Priv> p): PartialStorage(p) {}
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

class PartialRef
{
public:
	PartialRef(const PartialRef &) = default;
	PartialRef & operator=(const PartialRef &) = delete;

	static PartialRef create(PartialStorage, const Digest &);

	const Digest & digest() const;

	operator bool() const;
	const PartialObject operator*() const;
	std::unique_ptr<PartialObject> operator->() const;

	const PartialStorage & storage() const;

protected:
	friend class Storage;
	struct Priv;
	const std::shared_ptr<const Priv> p;
	PartialRef(const std::shared_ptr<const Priv> p): p(p) {}
};

class Ref : public PartialRef
{
public:
	Ref(const Ref &) = default;
	Ref & operator=(const Ref &) = delete;

	static std::optional<Ref> create(Storage, const Digest &);

	constexpr operator bool() const { return true; }
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
			typename S::Ref,
			UnknownType> Variant;

		Item(const std::string & name):
			Item(name, std::monostate()) {}
		Item(const std::string & name, Variant value):
			name(name), value(value) {}
		template<typename T>
		Item(const std::string & name, const Stored<T> & value):
			Item(name, value.ref) {}

		Item(const Item &) = default;
		Item & operator=(const Item &) = delete;

		operator bool() const;

		std::optional<int> asInteger() const;
		std::optional<std::string> asText() const;
		std::optional<std::vector<uint8_t>> asBinary() const;
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
		Blob> Variants;

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
	static std::optional<ObjectT<S>> load(const typename S::Ref &);

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
	Stored(Ref ref, std::shared_ptr<T> val): ref(ref), val(val) {}
	friend class Storage;
public:
	static std::optional<Stored<T>> load(const Ref &);
	Ref store(const Storage &) const;

	bool operator==(const Stored<T> & other) const
	{ return ref.digest() == other.ref.digest(); }
	bool operator!=(const Stored<T> & other) const
	{ return ref.digest() != other.ref.digest(); }
	bool operator<(const Stored<T> & other) const
	{ return ref.digest() < other.ref.digest(); }
	bool operator<=(const Stored<T> & other) const
	{ return ref.digest() <= other.ref.digest(); }
	bool operator>(const Stored<T> & other) const
	{ return ref.digest() > other.ref.digest(); }
	bool operator>=(const Stored<T> & other) const
	{ return ref.digest() >= other.ref.digest(); }

	const T & operator*() const { return *val; }
	const T * operator->() const { return val.get(); }

	std::vector<Stored<T>> previous() const;
	bool precedes(const Stored<T> &) const;

	const Ref ref;
	const std::shared_ptr<T> val;
};

template<typename T>
Stored<T> Storage::store(const T & val) const
{
	return Stored(val.store(*this), std::make_shared<T>(val));
}

template<typename T>
std::optional<Stored<T>> Stored<T>::load(const Ref & ref)
{
	if (auto val = T::load(ref))
		return Stored(ref, std::make_shared<T>(val.value()));
	return std::nullopt;
}

template<typename T>
Ref Stored<T>::store(const Storage & st) const
{
	if (st == ref.storage())
		return ref;
	return st.storeObject(*ref);
}

template<typename T>
std::vector<Stored<T>> Stored<T>::previous() const
{
	auto rec = ref->asRecord();
	if (!rec)
		return {};

	auto sdata = rec->item("SDATA").asRef();
	if (sdata) {
		auto drec = sdata.value()->asRecord();
		if (!drec)
			return {};

		std::vector<Stored<T>> res;
		for (const auto & i : drec->items("SPREV"))
			if (auto x = i.as<T>())
				res.push_back(*x);
		return res;
	}

	std::vector<Stored<T>> res;
	for (auto & i : rec->items("PREV"))
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
