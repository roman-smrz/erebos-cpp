#pragma once

#include <array>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace erebos {

class Storage;
class Digest;
class Ref;
class Object;
template<typename T> class Stored;

class Storage
{
public:
	Storage(const Storage &) = default;
	Storage & operator=(const Storage &) = delete;

	static std::optional<Storage> open(std::filesystem::path path);

	bool operator==(const Storage &) const;
	bool operator!=(const Storage &) const;

	std::optional<Ref> ref(const Digest &) const;

	std::optional<Object> loadObject(const Digest &) const;
	Ref storeObject(const Object &) const;
	Ref storeObject(const class Record &) const;
	Ref storeObject(const class Blob &) const;

	template<typename T> Stored<T> store(const T &) const;

	void storeKey(Ref pubref, const std::vector<uint8_t> &) const;
	std::optional<std::vector<uint8_t>> loadKey(Ref pubref) const;

private:
	friend class Ref;
	struct Priv;
	const std::shared_ptr<const Priv> p;
	Storage(const std::shared_ptr<const Priv> p): p(p) {}
};

class Digest
{
public:
	static constexpr size_t size = 32;

	Digest(const Digest &) = default;
	Digest & operator=(const Digest &) = delete;

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

class Ref
{
public:
	Ref(const Ref &) = default;
	Ref & operator=(const Ref &) = delete;

	static std::optional<Ref> create(Storage, const Digest &);

	const Digest & digest() const;
	const Object & operator*() const;
	const Object * operator->() const;

	const Storage & storage() const;

private:
	friend class Storage;
	struct Priv;
	const std::shared_ptr<const Priv> p;
	Ref(const std::shared_ptr<const Priv> p): p(p) {}
};

class Record
{
public:
	class Item {
	public:
		typedef std::variant<
			std::monostate,
			int,
			std::string,
			std::vector<uint8_t>,
			Ref> Variant;

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
		std::optional<Ref> asRef() const;

		template<typename T> std::optional<Stored<T>> as() const;

		const std::string name;
		const Variant value;
	};

private:
	Record(const std::shared_ptr<std::vector<Item>> & ptr):
		ptr(ptr) {}

public:
	Record(const std::vector<Item> &);
	Record(std::vector<Item> &&);
	std::vector<uint8_t> encode() const;

	const std::vector<Item> & items() const;
	Item item(const std::string & name) const;
	Item operator[](const std::string & name) const;
	std::vector<Item> items(const std::string & name) const;

private:
	friend class Object;
	std::vector<uint8_t> encodeInner() const;
	static Record decode(Storage,
			std::vector<uint8_t>::const_iterator,
			std::vector<uint8_t>::const_iterator);

	const std::shared_ptr<const std::vector<Item>> ptr;
};

class Blob
{
public:
	Blob(const std::vector<uint8_t> &);

	const std::vector<uint8_t> & data() const { return *ptr; }
	std::vector<uint8_t> encode() const;

private:
	friend class Object;
	std::vector<uint8_t> encodeInner() const;
	static Blob decode(Storage,
			std::vector<uint8_t>::const_iterator,
			std::vector<uint8_t>::const_iterator);

	Blob(std::shared_ptr<std::vector<uint8_t>> ptr): ptr(ptr) {}

	const std::shared_ptr<const std::vector<uint8_t>> ptr;
};

class Object
{
public:
	typedef std::variant<
		Record,
		Blob> Variants;

	Object(const Object &) = default;
	Object(Variants content): content(content) {}
	Object & operator=(const Object &) = delete;

	static std::optional<Object> decode(Storage, const std::vector<uint8_t> &);
	std::vector<uint8_t> encode() const;
	static std::optional<Object> load(const Ref &);

	std::optional<Record> asRecord() const;
	std::optional<Blob> asBlob() const;

private:
	friend class Record;
	friend class Blob;

	Variants content;
};

template<typename T>
std::optional<Stored<T>> Record::Item::as() const
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
