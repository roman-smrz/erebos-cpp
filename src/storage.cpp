#include "storage.h"
#include "base64.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <stdexcept>
#include <thread>

#include <stdio.h>

#include <blake2.h>
#include <zlib.h>

using namespace erebos;

using std::array;
using std::copy;
using std::holds_alternative;
using std::ifstream;
using std::is_same_v;
using std::make_shared;
using std::make_unique;
using std::monostate;
using std::nullopt;
using std::ofstream;
using std::runtime_error;
using std::shared_ptr;
using std::string;
using std::to_string;
using std::tuple;

FilesystemStorage::FilesystemStorage(const fs::path & path):
	root(path)
{
	if (!fs::is_directory(path))
		fs::create_directory(path);

	if (!fs::is_directory(path/"objects"))
		fs::create_directory(path/"objects");

	if (!fs::is_directory(path/"heads"))
		fs::create_directory(path/"heads");
}

bool FilesystemStorage::contains(const Digest & digest) const
{
	return fs::exists(objectPath(digest));
}

optional<vector<uint8_t>> FilesystemStorage::loadBytes(const Digest & digest) const
{
	vector<uint8_t> in(CHUNK);
	vector<uint8_t> out;
	size_t decoded = 0;

	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	int ret = inflateInit(&strm);
	if (ret != Z_OK)
		throw runtime_error("zlib initialization failed");

	ifstream fin(objectPath(digest), std::ios::binary);
	if (!fin.is_open())
		return nullopt;

	while (!fin.eof() && ret != Z_STREAM_END) {
		fin.read((char*) in.data(), in.size());
		if (fin.bad()) {
			inflateEnd(&strm);
			throw runtime_error("failed to read stored file");
		}
		strm.avail_in = fin.gcount();
		if (strm.avail_in == 0)
			break;
		strm.next_in = in.data();

		do {
			if (out.size() < decoded + in.size())
				out.resize(decoded + in.size());

			strm.avail_out = out.size() - decoded;
			strm.next_out = out.data() + decoded;
			ret = inflate(&strm, Z_NO_FLUSH);
			switch (ret) {
			case Z_STREAM_ERROR:
			case Z_NEED_DICT:
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				inflateEnd(&strm);
				throw runtime_error("zlib decoding failed");
			}
			decoded = out.size() - strm.avail_out;
		} while (strm.avail_out == 0);
	}


	inflateEnd(&strm);
	if (ret != Z_STREAM_END)
		throw runtime_error("zlib decoding failed");

	out.resize(decoded);
	return out;
}

void FilesystemStorage::storeBytes(const Digest & digest, const vector<uint8_t> & in)
{
	vector<uint8_t> out(CHUNK);

	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK)
		throw runtime_error("zlib initialization failed");

	auto path = objectPath(digest);
	auto lock = path;
	lock += ".lock";

	fs::create_directories(path.parent_path());

	// No way to use open exclusively in c++ stdlib
	FILE *f = nullptr;
	for (int i = 0; i < 10; i++) {
		f = fopen(lock.c_str(), "wbxe");
		if (f || errno != EEXIST)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	if (fs::exists(path)) {
		if (f) {
			fclose(f);
			fs::remove(lock);
		}
		return;
	}
	if (!f)
		throw runtime_error("failed to open storage file");

	strm.avail_in = in.size();
	strm.next_in = const_cast<uint8_t*>(in.data());
	do {
		strm.avail_out = out.size();
		strm.next_out = out.data();
		ret = deflate(&strm, Z_FINISH);
		if (ret == Z_STREAM_ERROR)
			break;
		size_t have = out.size() - strm.avail_out;
		if (fwrite(out.data(), 1, have, f) != have || ferror(f)) {
			ret = Z_ERRNO;
			break;
		}
	} while (strm.avail_out == 0);

	fclose(f);
	deflateEnd(&strm);

	if (strm.avail_in != 0 || ret != Z_STREAM_END) {
		fs::remove(lock);
		throw runtime_error("failed to deflate object");
	}

	fs::rename(lock, path);
}

optional<vector<uint8_t>> FilesystemStorage::loadKey(const Digest & pubref) const
{
	fs::path path = keyPath(pubref);
	std::error_code err;
	size_t size = fs::file_size(path, err);
	if (err)
		return nullopt;

	vector<uint8_t> key(size);
	ifstream file(keyPath(pubref));
	file.read((char *) key.data(), size);
	return key;
}

void FilesystemStorage::storeKey(const Digest & pubref, const vector<uint8_t> & key)
{
	fs::path path = keyPath(pubref);
	fs::create_directories(path.parent_path());
	ofstream file(path);
	file.write((const char *) key.data(), key.size());
}

fs::path FilesystemStorage::objectPath(const Digest & digest) const
{
	string name(digest);
	return root/"objects"/
		fs::path(name.begin(), name.begin() + 2)/
		fs::path(name.begin() + 2, name.end());
}

fs::path FilesystemStorage::keyPath(const Digest & digest) const
{
	string name(digest);
	return root/"keys"/fs::path(name.begin(), name.end());
}

bool MemoryStorage::contains(const Digest & digest) const
{
	return storage.find(digest) != storage.end();
}

optional<vector<uint8_t>> MemoryStorage::loadBytes(const Digest & digest) const
{
	auto it = storage.find(digest);
	if (it != storage.end())
		return it->second;
	return nullopt;
}

void MemoryStorage::storeBytes(const Digest & digest, const vector<uint8_t> & content)
{
	storage.emplace(digest, content);
}

optional<vector<uint8_t>> MemoryStorage::loadKey(const Digest & digest) const
{
	auto it = keys.find(digest);
	if (it != keys.end())
		return it->second;
	return nullopt;
}

void MemoryStorage::storeKey(const Digest & digest, const vector<uint8_t> & content)
{
	keys.emplace(digest, content);
}

bool ChainStorage::contains(const Digest & digest) const
{
	return storage->contains(digest) ||
		(parent && parent->contains(digest));
}

optional<vector<uint8_t>> ChainStorage::loadBytes(const Digest & digest) const
{
	if (auto res = storage->loadBytes(digest))
		return res;
	if (parent)
		return parent->loadBytes(digest);
	return nullopt;
}

void ChainStorage::storeBytes(const Digest & digest, const vector<uint8_t> & content)
{
	storage->storeBytes(digest, content);
}

optional<vector<uint8_t>> ChainStorage::loadKey(const Digest & digest) const
{
	if (auto res = storage->loadKey(digest))
		return res;
	if (parent)
		return parent->loadKey(digest);
	return nullopt;
}

void ChainStorage::storeKey(const Digest & digest, const vector<uint8_t> & content)
{
	storage->storeKey(digest, content);
}


Storage::Storage(const fs::path & path):
	PartialStorage(shared_ptr<Priv>(new Priv { .backend = make_shared<FilesystemStorage>(path) }))
{}

Storage Storage::deriveEphemeralStorage() const
{
	return Storage(shared_ptr<Priv>(new Priv { .backend =
		make_shared<ChainStorage>(
				make_shared<MemoryStorage>(),
				make_unique<ChainStorage>(p->backend)
				)}));
}

PartialStorage Storage::derivePartialStorage() const
{
	return PartialStorage(shared_ptr<Priv>(new Priv { .backend =
		make_shared<ChainStorage>(
				make_shared<MemoryStorage>(),
				make_unique<ChainStorage>(p->backend)
				)}));
}

bool PartialStorage::operator==(const PartialStorage & other) const
{
	return p == other.p;
}

bool PartialStorage::operator!=(const PartialStorage & other) const
{
	return p != other.p;
}

PartialRef PartialStorage::ref(const Digest & digest) const
{
	return PartialRef::create(*this, digest);
}

optional<Ref> Storage::ref(const Digest & digest) const
{
	return Ref::create(*this, digest);
}

Digest PartialStorage::Priv::storeBytes(const vector<uint8_t> & content) const
{
	array<uint8_t, Digest::size> arr;
	int ret = blake2b(arr.data(), content.data(), nullptr,
			Digest::size, content.size(), 0);
	if (ret != 0)
		throw runtime_error("failed to compute digest");

	Digest digest(arr);
	backend->storeBytes(digest, content);
	return digest;
}

optional<vector<uint8_t>> PartialStorage::Priv::loadBytes(const Digest & digest) const
{
	auto ocontent = backend->loadBytes(digest);
	if (!ocontent.has_value())
		return nullopt;
	auto content = ocontent.value();

	array<uint8_t, Digest::size> arr;
	int ret = blake2b(arr.data(), content.data(), nullptr,
			Digest::size, content.size(), 0);
	if (ret != 0 || digest != Digest(arr))
		throw runtime_error("digest verification failed");

	return content;
}

optional<PartialObject> PartialStorage::loadObject(const Digest & digest) const
{
	if (auto content = p->loadBytes(digest))
		return PartialObject::decode(*this, *content);
	return nullopt;
}

PartialRef PartialStorage::storeObject(const PartialObject & obj) const
{ return ref(p->storeBytes(obj.encode())); }

PartialRef PartialStorage::storeObject(const PartialRecord & val) const
{ return storeObject(PartialObject(val)); }

PartialRef PartialStorage::storeObject(const Blob & val) const
{ return storeObject(PartialObject(val)); }

optional<Object> Storage::loadObject(const Digest & digest) const
{
	if (auto content = p->loadBytes(digest))
		return Object::decode(*this, *content);
	return nullopt;
}

Ref Storage::storeObject(const Object & object) const
{ return copy(object); }

Ref Storage::storeObject(const Record & val) const
{ return storeObject(Object(val)); }

Ref Storage::storeObject(const Blob & val) const
{ return storeObject(Object(val)); }

template<class S>
optional<Digest> Storage::Priv::copy(const typename S::Ref & pref, vector<Digest> * missing) const
{
	if (backend->contains(pref.digest()))
		return pref.digest();
	if (pref)
		return copy<S>(*pref, missing);
	if (missing)
		missing->push_back(pref.digest());
	return nullopt;
}

template<class S>
optional<Digest> Storage::Priv::copy(const ObjectT<S> & pobj, vector<Digest> * missing) const
{
	bool fail = false;
	if (auto rec = pobj.asRecord())
		for (const auto & item : rec->items())
			if (auto r = item.asRef())
				if (!copy<S>(*r, missing))
					fail = true;

	if (fail)
		return nullopt;

	return storeBytes(pobj.encode());
}

variant<Ref, vector<Digest>> Storage::copy(const PartialRef & pref) const
{
	vector<Digest> missing;
	if (auto digest = p->copy<PartialStorage>(pref, &missing))
		return Ref::create(*this, *digest).value();
	return missing;
}

variant<Ref, vector<Digest>> Storage::copy(const PartialObject & pobj) const
{
	vector<Digest> missing;
	if (auto digest = p->copy<PartialStorage>(pobj, &missing))
		return Ref::create(*this, *digest).value();
	return missing;
}

Ref Storage::copy(const Ref & ref) const
{
	if (auto digest = p->copy<Storage>(ref, nullptr))
		return Ref::create(*this, *digest).value();
	throw runtime_error("corrupted storage");
}

Ref Storage::copy(const Object & obj) const
{
	if (auto digest = p->copy<Storage>(obj, nullptr))
		return Ref::create(*this, *digest).value();
	throw runtime_error("corrupted storage");
}

void Storage::storeKey(Ref pubref, const vector<uint8_t> & key) const
{
	p->backend->storeKey(pubref.digest(), key);
}

optional<vector<uint8_t>> Storage::loadKey(Ref pubref) const
{
	return p->backend->loadKey(pubref.digest());
}


Digest::Digest(const string & str)
{
	if (str.size() != 2 * size)
		throw runtime_error("invalid ref digest");

	for (size_t i = 0; i < size; i++)
		std::from_chars(str.data() + 2 * i,
				str.data() + 2 * i + 2,
				value[i], 16);
}

Digest::operator string() const
{
	string res(size * 2, '0');
	for (size_t i = 0; i < size; i++)
		std::to_chars(res.data() + 2 * i + (value[i] < 0x10),
				res.data() + 2 * i + 2,
				value[i], 16);
	return res;
}


PartialRef PartialRef::create(PartialStorage st, const Digest & digest)
{
	auto p = new Priv {
		.storage = make_unique<PartialStorage>(st),
		.digest = digest,
	};

	return PartialRef(shared_ptr<Priv>(p));
}

const Digest & PartialRef::digest() const
{
	return p->digest;
}

PartialRef::operator bool() const
{
	return storage().p->backend->contains(p->digest);
}

const PartialObject PartialRef::operator*() const
{
	if (auto res = p->storage->loadObject(p->digest))
		return *res;
	throw runtime_error("failed to load object from partial storage");
}

unique_ptr<PartialObject> PartialRef::operator->() const
{
	return make_unique<PartialObject>(**this);
}

const PartialStorage & PartialRef::storage() const
{
	return *p->storage;
}

optional<Ref> Ref::create(Storage st, const Digest & digest)
{
	if (!st.p->backend->contains(digest))
		return nullopt;

	auto p = new Priv {
		.storage = make_unique<PartialStorage>(st),
		.digest = digest,
	};

	return Ref(shared_ptr<Priv>(p));
}

const Object Ref::operator*() const
{
	if (auto res = static_cast<Storage*>(p->storage.get())->loadObject(p->digest))
		return *res;
	throw runtime_error("falied to load object - corrupted storage");
}

unique_ptr<Object> Ref::operator->() const
{
	return make_unique<Object>(**this);
}

const Storage & Ref::storage() const
{
	return *static_cast<const Storage*>(p->storage.get());
}


UUID::UUID(string str)
{
	if (uuid_parse(str.c_str(), uuid) != 0)
		throw runtime_error("invalid UUID");
}

UUID::operator string() const
{
	string str(UUID_STR_LEN - 1, '\0');
	uuid_unparse_lower(uuid, str.data());
	return str;
}

bool UUID::operator==(const UUID & other) const
{
	return std::equal(std::begin(uuid), std::end(uuid), std::begin(other.uuid));
}

bool UUID::operator!=(const UUID & other) const
{
	return !(*this == other);
}


template<class S>
RecordT<S>::Item::operator bool() const
{
	return !holds_alternative<monostate>(value);
}

template<class S>
optional<int> RecordT<S>::Item::asInteger() const
{
	if (holds_alternative<int>(value))
		return std::get<int>(value);
	return nullopt;
}

template<class S>
optional<string> RecordT<S>::Item::asText() const
{
	if (holds_alternative<string>(value))
		return std::get<string>(value);
	return nullopt;
}

template<class S>
optional<vector<uint8_t>> RecordT<S>::Item::asBinary() const
{
	if (holds_alternative<vector<uint8_t>>(value))
		return std::get<vector<uint8_t>>(value);
	return nullopt;
}

template<class S>
optional<UUID> RecordT<S>::Item::asUUID() const
{
	if (holds_alternative<UUID>(value))
		return std::get<UUID>(value);
	return nullopt;
}

template<class S>
optional<typename S::Ref> RecordT<S>::Item::asRef() const
{
	if (holds_alternative<typename S::Ref>(value))
		return std::get<typename S::Ref>(value);
	return nullopt;
}

template<class S>
optional<typename RecordT<S>::Item::UnknownType> RecordT<S>::Item::asUnknown() const
{
	if (holds_alternative<typename Item::UnknownType>(value))
		return std::get<typename Item::UnknownType>(value);
	return nullopt;
}


template<class S>
RecordT<S>::RecordT(const vector<Item> & from):
	ptr(new vector<Item>(from))
{}

template<class S>
RecordT<S>::RecordT(vector<Item> && from):
	ptr(new vector<Item>(std::move(from)))
{}

template<class S>
optional<RecordT<S>> RecordT<S>::decode(const S & st,
		vector<uint8_t>::const_iterator begin,
		vector<uint8_t>::const_iterator end)
{
	auto items = make_shared<vector<Item>>();

	while (begin != end) {
		const auto newline = std::find(begin, end, '\n');
		if (newline == end)
			throw runtime_error("invalid record");

		const auto colon = std::find(begin, newline, ':');
		if (colon == newline)
			throw runtime_error("invalid record");

		const auto space = std::find(colon, newline, ' ');
		if (space == newline)
			throw runtime_error("invalid record");

		const auto name = string(begin, colon);
		const auto type = string(colon + 1, space);
		const auto value = string(space + 1, newline);

		if (type == "i")
			items->emplace_back(name, std::stoi(value));
		else if (type == "t")
			items->emplace_back(name, value);
		else if (type == "b")
			items->emplace_back(name, base64::decode(value));
		else if (type == "u")
			items->emplace_back(name, UUID(value));
		else if (type == "r.b2") {
			if constexpr (is_same_v<S, Storage>) {
				if (auto ref = st.ref(Digest(value)))
					items->emplace_back(name, ref.value());
				else
					return nullopt;
			} else if constexpr (std::is_same_v<S, PartialStorage>) {
				items->emplace_back(name, st.ref(Digest(value)));
			}
		} else
			items->emplace_back(name,
					typename Item::UnknownType { type, value });

		begin = newline + 1;
	}

	return RecordT<S>(items);
}

template<class S>
vector<uint8_t> RecordT<S>::encode() const
{
	return ObjectT<S>(*this).encode();
}

template<class S>
const vector<typename RecordT<S>::Item> & RecordT<S>::items() const
{
	return *ptr;
}

template<class S>
typename RecordT<S>::Item RecordT<S>::item(const string & name) const
{
	for (auto item : *ptr) {
		if (item.name == name)
			return item;
	}
	return Item("", monostate());
}

template<class S>
typename RecordT<S>::Item RecordT<S>::operator[](const string & name) const
{
	return item(name);
}

template<class S>
vector<typename RecordT<S>::Item> RecordT<S>::items(const string & name) const
{
	vector<Item> res;
	for (auto item : *ptr) {
		if (item.name == name)
			res.push_back(item);
	}
	return res;
}

template<class S>
vector<uint8_t> RecordT<S>::encodeInner() const
{
	vector<uint8_t> res;
	auto inserter = std::back_inserter(res);
	for (const auto & item : *ptr) {
		copy(item.name.begin(), item.name.end(), inserter);
		inserter = ':';

		string type;
		string value;

		if (auto x = item.asInteger()) {
			type = "i";
			value = to_string(*x);
		} else if (auto x = item.asText()) {
			type = "t";
			value = *x;
		} else if (auto x = item.asBinary()) {
			type = "b";
			value = base64::encode(*x);
		} else if (auto x = item.asUUID()) {
			type = "u";
			value = string(*x);
		} else if (auto x = item.asRef()) {
			type = "r.b2";
			value = string(x->digest());
		} else if (auto x = item.asUnknown()) {
			type = x->type;
			value = x->value;
		} else {
			throw runtime_error("unhandeled record item type");
		}

		copy(type.begin(), type.end(), inserter);
		inserter = ' ';
		copy(value.begin(), value.end(), inserter);
		inserter = '\n';
	}
	return res;
}

template class erebos::RecordT<Storage>;
template class erebos::RecordT<PartialStorage>;


Blob::Blob(const vector<uint8_t> & vec):
	ptr(make_shared<vector<uint8_t>>(vec))
{}

vector<uint8_t> Blob::encode() const
{
	return Object(*this).encode();
}

vector<uint8_t> Blob::encodeInner() const
{
	return *ptr;
}

Blob Blob::decode(
		vector<uint8_t>::const_iterator begin,
		vector<uint8_t>::const_iterator end)
{
	return Blob(make_shared<vector<uint8_t>>(begin, end));
}

template<class S>
optional<tuple<ObjectT<S>, vector<uint8_t>::const_iterator>>
ObjectT<S>::decodePrefix(const S & st,
		vector<uint8_t>::const_iterator begin,
		vector<uint8_t>::const_iterator end)
{
	auto newline = std::find(begin, end, '\n');
	if (newline == end)
		return nullopt;

	auto space = std::find(begin, newline, ' ');
	if (space == newline)
		return nullopt;

	ssize_t size = std::stoi(string(space + 1, newline));
	if (end - newline - 1 < size)
		return nullopt;
	auto cend = newline + 1 + size;

	string type(begin, space);
	optional<ObjectT<S>> obj;
	if (type == "rec")
		if (auto rec = RecordT<S>::decode(st, newline + 1, cend))
			obj.emplace(*rec);
		else
			return nullopt;
	else if (type == "blob")
		obj.emplace(Blob::decode(newline + 1, cend));
	else
		throw runtime_error("unknown object type '" + type + "'");

	if (obj)
		return std::make_tuple(*obj, cend);
	return nullopt;
}

template<class S>
optional<ObjectT<S>> ObjectT<S>::decode(const S & st, const vector<uint8_t> & data)
{
	return decode(st, data.begin(), data.end());
}

template<class S>
optional<ObjectT<S>> ObjectT<S>::decode(const S & st,
		vector<uint8_t>::const_iterator begin,
		vector<uint8_t>::const_iterator end)
{
	if (auto res = decodePrefix(st, begin, end)) {
		auto [obj, next] = *res;
		if (next == end)
			return obj;
	}
	return nullopt;
}

template<class S>
vector<uint8_t> ObjectT<S>::encode() const
{
	vector<uint8_t> res, inner;
	string type;

	if (auto rec = asRecord()) {
		type = "rec";
		inner = rec->encodeInner();
	} else if (auto blob = asBlob()) {
		type = "blob";
		inner = blob->encodeInner();
	} else {
		throw runtime_error("unhandeled object type");
	}

	auto inserter = std::back_inserter(res);
	copy(type.begin(), type.end(), inserter);
	inserter = ' ';

	auto slen = to_string(inner.size());
	copy(slen.begin(), slen.end(), inserter);
	inserter = '\n';

	copy(inner.begin(), inner.end(), inserter);
	return res;
}

template<class S>
optional<ObjectT<S>> ObjectT<S>::load(const typename S::Ref & ref)
{
	if (ref)
		return *ref;
	return nullopt;
}

template<class S>
optional<RecordT<S>> ObjectT<S>::asRecord() const
{
	if (holds_alternative<RecordT<S>>(content))
		return std::get<RecordT<S>>(content);
	return nullopt;
}

template<class S>
optional<Blob> ObjectT<S>::asBlob() const
{
	if (holds_alternative<Blob>(content))
		return std::get<Blob>(content);
	return nullopt;
}

template class erebos::ObjectT<Storage>;
template class erebos::ObjectT<PartialStorage>;

vector<Stored<Object>> erebos::collectStoredObjects(const Stored<Object> & from)
{
	unordered_set<Digest> seen;
	vector<Stored<Object>> queue { from };
	vector<Stored<Object>> res;

	while (!queue.empty()) {
		auto cur = queue.back();
		queue.pop_back();

		auto [it, added] = seen.insert(cur.ref.digest());
		if (!added)
			continue;

		res.push_back(cur);

		if (auto rec = cur->asRecord())
			for (const auto & item : rec->items())
				if (auto ref = item.asRef())
					queue.push_back(*Stored<Object>::load(*ref));
	}

	return res;
}
