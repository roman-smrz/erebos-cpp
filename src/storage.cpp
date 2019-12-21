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
using std::make_shared;
using std::monostate;
using std::nullopt;
using std::ofstream;
using std::runtime_error;
using std::shared_ptr;
using std::string;
using std::to_string;

optional<Storage> Storage::open(fs::path path)
{
	if (!fs::is_directory(path))
		fs::create_directory(path);

	if (!fs::is_directory(path/"objects"))
		fs::create_directory(path/"objects");

	if (!fs::is_directory(path/"heads"))
		fs::create_directory(path/"heads");

	return Storage(shared_ptr<const Priv>(new Priv { path }));
}

bool Storage::operator==(const Storage & other) const
{
	return p == other.p;
}

bool Storage::operator!=(const Storage & other) const
{
	return p != other.p;
}

fs::path Storage::Priv::objectPath(const Digest & digest) const
{
	string name(digest);
	return root/"objects"/
		fs::path(name.begin(), name.begin() + 2)/
		fs::path(name.begin() + 2, name.end());
}

fs::path Storage::Priv::keyPath(const Digest & digest) const
{
	string name(digest);
	return root/"keys"/fs::path(name.begin(), name.end());
}

optional<Ref> Storage::ref(const Digest & digest) const
{
	return Ref::create(*this, digest);
}

optional<vector<uint8_t>> Storage::Priv::loadBytes(const Digest & digest) const
{
	vector<uint8_t> in(Priv::CHUNK);
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

optional<Object> Storage::loadObject(const Digest & digest) const
{
	auto ocontent = p->loadBytes(digest);
	if (!ocontent.has_value())
		return nullopt;
	auto content = ocontent.value();

	array<uint8_t, Digest::size> arr;
	int ret = blake2b(arr.data(), content.data(), nullptr,
			Digest::size, content.size(), 0);
	if (ret != 0 || digest != Digest(arr))
		throw runtime_error("digest verification failed");

	return Object::decode(*this, content);
}

void Storage::Priv::storeBytes(const Digest & digest, const vector<uint8_t> & in) const
{
	vector<uint8_t> out(Priv::CHUNK);

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

Ref Storage::storeObject(const Object & object) const
{
	// TODO: ensure storage transitively
	auto content = object.encode();

	array<uint8_t, Digest::size> arr;
	int ret = blake2b(arr.data(), content.data(), nullptr,
			Digest::size, content.size(), 0);
	if (ret != 0)
		throw runtime_error("failed to compute digest");

	Digest digest(arr);
	p->storeBytes(digest, content);
	return Ref::create(*this, digest).value();
}

Ref Storage::storeObject(const class Record & val) const
{ return storeObject(Object(val)); }

Ref Storage::storeObject(const class Blob & val) const
{ return storeObject(Object(val)); }

void Storage::storeKey(Ref pubref, const vector<uint8_t> & key) const
{
	ofstream file(p->keyPath(pubref.digest()));
	file.write((const char *) key.data(), key.size());
}

optional<vector<uint8_t>> Storage::loadKey(Ref pubref) const
{
	fs::path path = p->keyPath(pubref.digest());
	std::error_code err;
	size_t size = fs::file_size(path, err);
	if (err)
		return nullopt;

	vector<uint8_t> key(size);
	ifstream file(p->keyPath(pubref.digest()));
	file.read((char *) key.data(), size);
	return key;
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


optional<Ref> Ref::create(Storage st, const Digest & digest)
{
	if (!fs::exists(st.p->objectPath(digest)))
		return nullopt;

	auto p = new Priv {
		.storage = st,
		.digest = digest,
		.object = {},
	};

	p->object = std::async(std::launch::deferred, [p] {
		auto obj = p->storage.loadObject(p->digest);
		if (!obj.has_value())
			throw runtime_error("failed to decode bytes");

		return obj.value();
	});

	return Ref(shared_ptr<Priv>(p));
}

const Digest & Ref::digest() const
{
	return p->digest;
}

const Object & Ref::operator*() const
{
	return p->object.get();
}

const Object * Ref::operator->() const
{
	return &p->object.get();
}

const Storage & Ref::storage() const
{
	return p->storage;
}


Record::Item::operator bool() const
{
	return !holds_alternative<monostate>(value);
}

optional<int> Record::Item::asInteger() const
{
	if (holds_alternative<int>(value))
		return std::get<int>(value);
	return nullopt;
}

optional<string> Record::Item::asText() const
{
	if (holds_alternative<string>(value))
		return std::get<string>(value);
	return nullopt;
}

optional<vector<uint8_t>> Record::Item::asBinary() const
{
	if (holds_alternative<vector<uint8_t>>(value))
		return std::get<vector<uint8_t>>(value);
	return nullopt;
}

optional<Ref> Record::Item::asRef() const
{
	if (holds_alternative<Ref>(value))
		return std::get<Ref>(value);
	return nullopt;
}


Record::Record(const vector<Item> & from):
	ptr(new vector<Item>(from))
{}

Record::Record(vector<Item> && from):
	ptr(new vector<Item>(std::move(from)))
{}

Record Record::decode(Storage st,
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
		else if (type == "r.b2")
			items->emplace_back(name, Ref::create(st, Digest(value)).value());
		else
			throw runtime_error("unknown record item type");

		begin = newline + 1;
	}

	return Record(items);
}

vector<uint8_t> Record::encode() const
{
	return Object(*this).encode();
}

const vector<Record::Item> & Record::items() const
{
	return *ptr;
}

Record::Item Record::item(const string & name) const
{
	for (auto item : *ptr) {
		if (item.name == name)
			return item;
	}
	return Item("", monostate());
}

Record::Item Record::operator[](const string & name) const
{
	return item(name);
}

vector<Record::Item> Record::items(const string & name) const
{
	vector<Item> res;
	for (auto item : *ptr) {
		if (item.name == name)
			res.push_back(item);
	}
	return res;
}


vector<uint8_t> Record::encodeInner() const
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
		} else if (auto x = item.asRef()) {
			type = "r.b2";
			value = string(x->digest());
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

Blob Blob::decode(Storage,
		vector<uint8_t>::const_iterator begin,
		vector<uint8_t>::const_iterator end)
{
	return Blob(make_shared<vector<uint8_t>>(begin, end));
}


optional<Object> Object::decode(Storage st, const vector<uint8_t> & data)
{
	auto newline = std::find(data.begin(), data.end(), '\n');
	if (newline == data.end())
		return nullopt;

	auto space = std::find(data.begin(), newline, ' ');
	if (space == newline)
		return nullopt;

	ssize_t size = std::stoi(string(space + 1, newline));
	if (data.end() - newline - 1 != size)
		return nullopt;

	string type(data.begin(), space);
	if (type == "rec")
		return Object(Record::decode(st, newline + 1, data.end()));
	else if (type == "blob")
		return Object(Blob::decode(st, newline + 1, data.end()));
	else
		throw runtime_error("unknown object type '" + type + "'");

	return nullopt;
}

vector<uint8_t> Object::encode() const
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

optional<Object> Object::load(const Ref & ref)
{
	return *ref;
}

optional<Record> Object::asRecord() const
{
	if (holds_alternative<Record>(content))
		return std::get<Record>(content);
	return nullopt;
}

optional<Blob> Object::asBlob() const
{
	if (holds_alternative<Blob>(content))
		return std::get<Blob>(content);
	return nullopt;
}
