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

class Storage
{
public:
	Storage(const Storage &) = default;
	Storage & operator=(const Storage &) = delete;

	static std::optional<Storage> open(std::filesystem::path path);
	std::optional<Ref> ref(const Digest &) const;
	std::optional<Object> load(const Digest &) const;
	Ref store(const Object &) const;

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
			int,
			std::string,
			std::vector<uint8_t>,
			Ref> Variant;

		Item(const std::string & name, Variant value):
			name(name), value(value) {}
		Item(const Item &) = default;
		Item & operator=(const Item &) = delete;

		std::optional<int> asInteger() const;
		std::optional<std::string> asText() const;
		std::optional<std::vector<uint8_t>> asBinary() const;
		std::optional<Ref> asRef() const;

	private:
		friend class Record;
		std::string name;
		Variant value;
	};

private:
	Record(const std::shared_ptr<std::vector<Item>> & ptr):
		ptr(ptr) {}

public:
	Record(const std::vector<Item> &);
	std::vector<uint8_t> encode() const;

	const std::vector<Item> & items() const;
	std::optional<Item> item(const std::string & name) const;
	std::optional<Item> operator[](const std::string & name) const;
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

	std::optional<Record> asRecord() const;
	std::optional<Blob> asBlob() const;

private:
	friend class Record;
	friend class Blob;

	Variants content;
};

}
