#include "storage.h"

#include <charconv>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <stdexcept>
#include <thread>

#include <poll.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>

#include <blake2.h>
#include <zlib.h>

using namespace erebos;

using std::array;
using std::copy;
using std::get;
using std::holds_alternative;
using std::ifstream;
using std::invalid_argument;
using std::is_same_v;
using std::make_shared;
using std::make_unique;
using std::monostate;
using std::nullopt;
using std::ofstream;
using std::out_of_range;
using std::runtime_error;
using std::scoped_lock;
using std::shared_ptr;
using std::string;
using std::system_error;
using std::to_string;
using std::weak_ptr;

void StorageWatchCallback::schedule(UUID uuid, const Digest & dgst)
{
	scoped_lock lock(runMutex);
	scheduled.emplace(uuid, dgst);
}

void StorageWatchCallback::run()
{
	scoped_lock lock(runMutex);
	if (scheduled) {
		auto [uuid, dgst] = *scheduled;
		scheduled.reset(); // avoid running the callback twice

		callback(uuid, dgst);
	}
}

FilesystemStorage::FilesystemStorage(const fs::path & path):
	root(path)
{
}

FilesystemStorage::~FilesystemStorage()
{
	if (inotifyWakeup >= 0) {
		uint64_t x = 1;
		write(inotifyWakeup, &x, sizeof(x));
	}

	if (watcherThread.joinable())
		watcherThread.join();

	if (inotify >= 0)
		close(inotify);

	if (inotifyWakeup >= 0)
		close(inotifyWakeup);

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

	FILE * f = openLockFile(lock);
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

optional<Digest> FilesystemStorage::headRef(UUID type, UUID id) const
{
	ifstream fin(headPath(type, id));
	if (!fin)
		return nullopt;

	string sdgst;
	fin >> sdgst;
	return Digest(sdgst);
}

vector<tuple<UUID, Digest>> FilesystemStorage::headRefs(UUID type) const
{
	vector<tuple<UUID, Digest>> res;
	string stype(type);
	fs::path ptype(stype.begin(), stype.end());
	try {
		for (const auto & p : fs::directory_iterator(root/"heads"/ptype))
			if (auto u = UUID::fromString(p.path().filename())) {
				ifstream fin(p.path());
				if (fin) {
					string sdgst;
					fin >> sdgst;
					res.emplace_back(*u, Digest(sdgst));
				}
			}
	} catch (const fs::filesystem_error & e) {
		if (e.code() == std::errc::no_such_file_or_directory)
			return {};
		throw e;
	}
	return res;
}

UUID FilesystemStorage::storeHead(UUID type, const Digest & dgst)
{
	auto id = UUID::generate();
	auto path = headPath(type, id);
	fs::create_directories(path.parent_path());
	ofstream fout(path);
	if (!fout)
		throw runtime_error("failed to open head file");

	fout << string(dgst) << '\n';
	return id;
}

bool FilesystemStorage::replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst)
{
	auto path = headPath(type, id);
	auto lock = path;
	lock += ".lock";
	FILE * f = openLockFile(lock);
	if (!f)
		throw runtime_error(("failed to lock head file " + string(path) +
					": " + string(strerror(errno))).c_str());

	string scur;
	ifstream fin(path);
	fin >> scur;
	fin.close();
	Digest cur(scur);

	if (cur != old) {
		fclose(f);
		unlink(lock.c_str());
		return false;
	}

	fprintf(f, "%s\n", string(dgst).c_str());
	fclose(f);
	fs::rename(lock, path);
	return true;
}

int FilesystemStorage::watchHead(UUID type, const function<void(UUID id, const Digest &)> & watcher)
{
	scoped_lock lock(watcherLock);
	int wid = nextWatcherId++;

	if (inotify < 0) {
		inotify = inotify_init();
		if (inotify < 0)
			throw system_error(errno, std::generic_category());

		inotifyWakeup = eventfd(0, 0);
		if (inotifyWakeup < 0)
			throw system_error(errno, std::generic_category());

		watcherThread = std::thread(&FilesystemStorage::inotifyWatch, this);
	}

	if (watchers.find(type) == watchers.end()) {
		int wd = inotify_add_watch(inotify, headPath(type).c_str(), IN_MOVED_TO);
		if (wd < 0)
			throw system_error(errno, std::generic_category());

		watchMap[wd] = type;
	}
	watchers.emplace(type, make_shared<StorageWatchCallback>(wid, watcher));

	return wid;
}

void FilesystemStorage::unwatchHead(UUID type, int wid)
{
	shared_ptr<StorageWatchCallback> cb;

	{
		scoped_lock lock(watcherLock);

		if (inotify < 0)
			return;

		auto range = watchers.equal_range(type);
		for (auto it = range.first; it != range.second; it++) {
			if (it->second->id == wid) {
				cb = move(it->second);
				watchers.erase(it);
				break;
			}
		}

		if (watchers.find(type) == watchers.end()) {
			for (auto it = watchMap.begin(); it != watchMap.end(); it++) {
				if (it->second == type) {
					if (inotify_rm_watch(inotify, it->first) < 0)
						throw system_error(errno, std::generic_category());
					watchMap.erase(it);
					break;
				}
			}
		}
	}

	// Run the last callback if scheduled and not yet executed
	if (cb)
		cb->run();
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

void FilesystemStorage::inotifyWatch()
{
	char buf[4096]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event * event;

	array pfds {
		pollfd { inotify, POLLIN, 0 },
		pollfd { inotifyWakeup, POLLIN, 0 },
	};

	while (true) {
		int ret = poll(pfds.data(), pfds.size(), -1);
		if (ret < 0)
			throw system_error(errno, std::generic_category());

		if (!(pfds[0].revents & POLLIN))
			break;

		ssize_t len = read(inotify, buf, sizeof buf);
		if (len < 0) {
			if (errno == EAGAIN)
				continue;

			throw system_error(errno, std::generic_category());
		}

		if (len == 0)
			break;

		for (char * ptr = buf; ptr < buf + len;
				ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;

			if (event->mask & IN_MOVED_TO) {
				vector<shared_ptr<StorageWatchCallback>> callbacks;

				{
					// Copy relevant callbacks to temporary array, so they
					// can be called without holding the watcherLock.

					scoped_lock lock(watcherLock);
					UUID type = watchMap[event->wd];
					if (auto mbid = UUID::fromString(event->name)) {
						if (auto mbref = headRef(type, *mbid)) {
							auto range = watchers.equal_range(type);
							for (auto it = range.first; it != range.second; it++) {
								it->second->schedule(*mbid, *mbref);
								callbacks.push_back(it->second);
							}
						}
					}
				}

				for (const auto & cb : callbacks)
					cb->run();
			}
		}
	}
}

fs::path FilesystemStorage::objectPath(const Digest & digest) const
{
	string name(digest);
	size_t delim = name.find('#');

	return root/"objects"/
		fs::path(name.begin(), name.begin() + delim)/
		fs::path(name.begin() + delim + 1, name.begin() + delim + 3)/
		fs::path(name.begin() + delim + 3, name.end());
}

fs::path FilesystemStorage::headPath(UUID type) const
{
	string stype(type);
	return root/"heads"/fs::path(stype.begin(), stype.end());
}

fs::path FilesystemStorage::headPath(UUID type, UUID id) const
{
	string sid(id);
	return headPath(type) / fs::path(sid.begin(), sid.end());
}

fs::path FilesystemStorage::keyPath(const Digest & digest) const
{
	string name(digest);
	return root/"keys"/fs::path(name.begin(), name.end());
}

FILE * FilesystemStorage::openLockFile(const fs::path & path) const
{
	fs::create_directories(path.parent_path());

	// No way to use open exclusively in c++ stdlib
	FILE *f = nullptr;
	for (int i = 0; i < 10; i++) {
		f = fopen(path.c_str(), "wbxe");
		if (f || errno != EEXIST)
			break;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	return f;
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

optional<Digest> MemoryStorage::headRef(UUID type, UUID id) const
{
	auto it = heads.find(type);
	if (it == heads.end())
		return nullopt;

	for (const auto & x : it->second)
		if (get<UUID>(x) == id)
			return get<Digest>(x);

	return nullopt;
}

vector<tuple<UUID, Digest>> MemoryStorage::headRefs(UUID type) const
{
	auto it = heads.find(type);
	if (it != heads.end())
		return it->second;
	return {};
}

UUID MemoryStorage::storeHead(UUID type, const Digest & dgst)
{
	auto id = UUID::generate();
	auto it = heads.find(type);
	if (it == heads.end())
		heads[type] = { { id, dgst } };
	else
		it->second.emplace_back(id, dgst);
	return id;
}

bool MemoryStorage::replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst)
{
	auto it = heads.find(type);
	if (it == heads.end())
		return false;

	for (auto & x : it->second)
		if (get<UUID>(x) == id) {
			if (get<Digest>(x) == old) {
				get<Digest>(x) = dgst;
				return true;
			} else {
				return false;
			}
		}

	return false;
}

int MemoryStorage::watchHead(UUID type, const function<void(UUID id, const Digest &)> & watcher)
{
	scoped_lock lock(watcherLock);
	int wid = nextWatcherId++;
	watchers.emplace(type, make_shared<StorageWatchCallback>(wid, watcher));
	return wid;
}

void MemoryStorage::unwatchHead(UUID type, int wid)
{
	shared_ptr<StorageWatchCallback> cb;

	{
		scoped_lock lock(watcherLock);

		auto range = watchers.equal_range(type);
		for (auto it = range.first; it != range.second; it++) {
			if (it->second->id == wid) {
				cb = move(it->second);
				watchers.erase(it);
				break;
			}
		}
	}

	// Run the last callback if scheduled and not yet executed
	if (cb)
		cb->run();
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

optional<Digest> ChainStorage::headRef(UUID type, UUID id) const
{
	if (auto res = storage->headRef(type, id))
		return res;
	if (parent)
		return parent->headRef(type, id);
	return nullopt;
}

vector<tuple<UUID, Digest>> ChainStorage::headRefs(UUID type) const
{
	auto res = storage->headRefs(type);
	if (parent)
		for (auto x : parent->headRefs(type)) {
			bool add = true;
			for (const auto & y : res)
				if (get<UUID>(y) == get<UUID>(x)) {
					add = false;
					break;
				}
			if (add)
				res.push_back(x);
		}
	return res;
}

UUID ChainStorage::storeHead(UUID type, const Digest & dgst)
{
	return storage->storeHead(type, dgst);
}

bool ChainStorage::replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst)
{
	return storage->replaceHead(type, id, old, dgst);
}

int ChainStorage::watchHead(UUID type, const function<void(UUID id, const Digest &)> & watcher)
{
	scoped_lock lock(watcherLock);
	int wid = nextWatcherId++;

	int id1 = parent->watchHead(type, watcher);
	int id2 = storage->watchHead(type, watcher);
	watchers.emplace(wid, tuple(id1, id2));

	return wid;
}

void ChainStorage::unwatchHead(UUID type, int wid)
{
	scoped_lock lock(watcherLock);

	auto [id1, id2] = watchers.extract(wid).mapped();
	parent->unwatchHead(type, id1);
	storage->unwatchHead(type, id2);
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

Ref Storage::zref() const
{
	return Ref::zcreate(*this);
}

Digest PartialStorage::Priv::storeBytes(const vector<uint8_t> & content) const
{
	Digest digest = Digest::of(content);
	backend->storeBytes(digest, content);
	return digest;
}

optional<vector<uint8_t>> PartialStorage::Priv::loadBytes(const Digest & digest) const
{
	auto ocontent = backend->loadBytes(digest);
	if (!ocontent.has_value())
		return nullopt;
	auto content = ocontent.value();

	if (digest != Digest::of(content))
		throw runtime_error("digest verification failed");

	return content;
}

optional<PartialObject> PartialStorage::loadObject(const Digest & digest) const
{
	if (digest.isZero())
		return PartialObject(monostate());
	if (auto content = p->loadBytes(digest))
		return PartialObject::decode(*this, *content);
	return nullopt;
}

PartialRef PartialStorage::storeObject(const PartialObject & obj) const
{
	if (not obj)
		return PartialRef::zcreate(*this);
	return ref(p->storeBytes(obj.encode()));
}

PartialRef PartialStorage::storeObject(const PartialRecord & val) const
{ return storeObject(PartialObject(val)); }

PartialRef PartialStorage::storeObject(const Blob & val) const
{ return storeObject(PartialObject(val)); }

optional<Object> Storage::loadObject(const Digest & digest) const
{
	if (digest.isZero())
		return Object(monostate());
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
	if (pref.digest().isZero())
		return pref.digest();
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
	if (not pobj)
		return Digest(array<uint8_t, Digest::size> {});

	bool fail = false;
	if (auto rec = pobj.asRecord())
		for (const auto & r : rec->items().asRef())
			if (!copy<S>(r, missing))
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

optional<Ref> Storage::headRef(UUID type, UUID id) const
{
	if (auto dgst = p->backend->headRef(type, id))
		return ref(*dgst);
	return nullopt;
}

vector<tuple<UUID, Ref>> Storage::headRefs(UUID type) const
{
	vector<tuple<UUID, Ref>> res;
	for (auto x : p->backend->headRefs(type))
		if (auto r = ref(get<Digest>(x)))
			res.emplace_back(get<UUID>(x), *r);
	return res;
}

UUID Storage::storeHead(UUID type, const Ref & ref)
{
	return ref.storage().p->backend->storeHead(type, ref.digest());
}

bool Storage::replaceHead(UUID type, UUID id, const Ref & old, const Ref & ref)
{
	return ref.storage().p->backend->replaceHead(type, id, old.digest(), ref.digest());
}

optional<Ref> Storage::updateHead(UUID type, UUID id, const Ref & old, const std::function<Ref(const Ref &)> & f)
{
	auto cur = old.storage().headRef(type, id);
	if (!cur)
		return nullopt;

	Ref r = f(*cur);
	if (r.digest() == cur->digest() || replaceHead(type, id, *cur, r))
		return r;

	return updateHead(type, id, *cur, f);
}

int Storage::watchHead(UUID type, UUID wid, const std::function<void(const Ref &)> watcher) const
{
	return p->backend->watchHead(type, [wp = weak_ptr<const Priv>(p), wid, watcher] (UUID id, const Digest & dgst) {
		if (id == wid)
			if (auto p = wp.lock())
				if (auto r = Ref::create(Storage(p), dgst))
					watcher(*r);
	});
}

void Storage::unwatchHead(UUID type, UUID, int wid) const
{
	p->backend->unwatchHead(type, wid);
}


Digest::Digest(const string & str)
{
	if (str.size() != 2 * size + 7)
		throw runtime_error("invalid ref digest");

	if (strncmp(str.data(), "blake2#", 7) != 0)
		throw runtime_error("invalid ref digest");

	for (size_t i = 0; i < size; i++)
		std::from_chars(str.data() + 7 + 2 * i,
				str.data() + 7 + 2 * i + 2,
				value[i], 16);
}

Digest::operator string() const
{
	string res(size * 2 + 7, '0');
	memcpy(res.data(), "blake2#", 7);
	for (size_t i = 0; i < size; i++)
		std::to_chars(res.data() + 7 + 2 * i + (value[i] < 0x10),
				res.data() + 7 + 2 * i + 2,
				value[i], 16);
	return res;
}

bool Digest::isZero() const
{
	for (uint8_t x : value)
		if (x) return false;
	return true;
}

Digest Digest::of(const vector<uint8_t> & content)
{
	array<uint8_t, size> arr;
	int ret = blake2b(arr.data(), content.data(), nullptr,
			size, content.size(), 0);
	if (ret != 0)
		throw runtime_error("failed to compute digest");

	return Digest(arr);
}


PartialRef PartialRef::create(const PartialStorage & st, const Digest & digest)
{
	auto p = new Priv {
		.storage = make_unique<PartialStorage>(st),
		.digest = digest,
	};

	return PartialRef(shared_ptr<Priv>(p));
}

PartialRef PartialRef::zcreate(const PartialStorage & st)
{
	return create(st, Digest(array<uint8_t, Digest::size> {}));
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

bool Ref::operator==(const Ref & other) const
{
	return p->digest == other.p->digest;
}

bool Ref::operator!=(const Ref & other) const
{
	return p->digest != other.p->digest;
}

optional<Ref> Ref::create(const Storage & st, const Digest & digest)
{
	if (!st.p->backend->contains(digest))
		return nullopt;

	auto p = new Priv {
		.storage = make_unique<PartialStorage>(st),
		.digest = digest,
	};

	return Ref(shared_ptr<Priv>(p));
}

Ref Ref::zcreate(const Storage & st)
{
	auto p = new Priv {
		.storage = make_unique<PartialStorage>(st),
		.digest = Digest(array<uint8_t, Digest::size> {}),
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

vector<Ref> Ref::previous() const
{
	auto rec = (**this).asRecord();
	if (!rec)
		return {};

	if (auto sdata = rec->item("SDATA").asRef()) {
		if (auto drec = sdata.value()->asRecord()) {
			auto res = drec->items("SPREV").asRef();
			if (auto base = drec->item("SBASE").asRef())
				res.push_back(*base);
			return res;
		}
		return {};
	}

	auto res = rec->items("PREV").asRef();
	if (auto base = rec->item("BASE").asRef())
		res.push_back(*base);
	return res;
}

Generation Ref::generation() const
{
	scoped_lock lock(p->storage->p->generationCacheLock);
	return generationLocked();
}

Generation Ref::generationLocked() const
{
	auto it = p->storage->p->generationCache.find(p->digest);
	if (it != p->storage->p->generationCache.end())
		return it->second;

	auto prev = previous();
	vector<Generation> pgen;
	pgen.reserve(prev.size());
	for (const auto & r : prev)
		pgen.push_back(r.generationLocked());

	auto gen = Generation::next(pgen);

	p->storage->p->generationCache.emplace(p->digest, gen);
	return gen;
}

vector<Digest> Ref::roots() const
{
	scoped_lock lock(p->storage->p->rootsCacheLock);
	return rootsLocked();
}

vector<Digest> Ref::rootsLocked() const
{
	auto it = p->storage->p->rootsCache.find(p->digest);
	if (it != p->storage->p->rootsCache.end())
		return it->second;

	vector<Digest> roots;
	auto prev = previous();

	if (prev.empty()) {
		roots.push_back(p->digest);
	} else {
		for (const auto & p : previous())
			for (const auto & r : p.rootsLocked())
				roots.push_back(r);

		std::sort(roots.begin(), roots.end());
		roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
	}

	p->storage->p->rootsCache.emplace(p->digest, roots);
	return roots;
}


template<class S>
RecordT<S>::Item::operator bool() const
{
	return !holds_alternative<monostate>(value);
}

template<class S>
optional<typename RecordT<S>::Item::Empty> RecordT<S>::Item::asEmpty() const
{
	if (holds_alternative<RecordT<S>::Item::Empty>(value))
		return std::get<RecordT<S>::Item::Empty>(value);
	return nullopt;
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
optional<ZonedTime> RecordT<S>::Item::asDate() const
{
	if (holds_alternative<ZonedTime>(value))
		return std::get<ZonedTime>(value);
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
RecordT<S>::Items::Items(shared_ptr<const vector<Item>> items):
	items(move(items)), filter(nullopt)
{}

template<class S>
RecordT<S>::Items::Items(shared_ptr<const vector<Item>> items, string filter):
	items(move(items)), filter(move(filter))
{}

template<class S>
RecordT<S>::Items::Iterator::Iterator(const Items & source, size_t idx):
	source(source), idx(idx)
{}

template<class S>
typename RecordT<S>::Items::Iterator & RecordT<S>::Items::Iterator::operator++()
{
	const auto & items = *source.items;
	do {
		idx++;
	} while (idx < items.size() &&
			source.filter &&
			items[idx].name != *source.filter);
	return *this;
}

template<class S>
typename RecordT<S>::Items::Iterator RecordT<S>::Items::begin() const
{
	return ++Iterator(*this, -1);
}

template<class S>
typename RecordT<S>::Items::Iterator RecordT<S>::Items::end() const
{
	return Iterator(*this, items->size());
}

template<class S>
vector<typename RecordT<S>::Item::Empty> RecordT<S>::Items::asEmpty() const
{
	vector<Empty> res;
	for (const auto & item : *this)
		if (holds_alternative<Empty>(item.value))
			res.push_back(std::get<Empty>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::Integer> RecordT<S>::Items::asInteger() const
{
	vector<Integer> res;
	for (const auto & item : *this)
		if (holds_alternative<Integer>(item.value))
			res.push_back(std::get<Integer>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::Text> RecordT<S>::Items::asText() const
{
	vector<Text> res;
	for (const auto & item : *this)
		if (holds_alternative<Text>(item.value))
			res.push_back(std::get<Text>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::Binary> RecordT<S>::Items::asBinary() const
{
	vector<Binary> res;
	for (const auto & item : *this)
		if (holds_alternative<Binary>(item.value))
			res.push_back(std::get<Binary>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::Date> RecordT<S>::Items::asDate() const
{
	vector<Date> res;
	for (const auto & item : *this)
		if (holds_alternative<Date>(item.value))
			res.push_back(std::get<Date>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::UUID> RecordT<S>::Items::asUUID() const
{
	vector<UUID> res;
	for (const auto & item : *this)
		if (holds_alternative<UUID>(item.value))
			res.push_back(std::get<UUID>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::Ref> RecordT<S>::Items::asRef() const
{
	vector<Ref> res;
	for (const auto & item : *this)
		if (holds_alternative<Ref>(item.value))
			res.push_back(std::get<Ref>(item.value));
	return res;
}

template<class S>
vector<typename RecordT<S>::Item::UnknownType> RecordT<S>::Items::asUnknown() const
{
	vector<UnknownType> res;
	for (const auto & item : *this)
		if (holds_alternative<UnknownType>(item.value))
			res.push_back(std::get<UnknownType>(item.value));
	return res;
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
		const auto colon = std::find(begin, end, ':');
		if (colon == end)
			return nullopt;
		const string name(begin, colon);

		const auto space = std::find(colon + 1, end, ' ');
		if (space == end)
			return nullopt;
		const string type(colon + 1, space);

		begin = space + 1;
		string value;
		for (bool cont = true; cont; ) {
			auto newline = std::find(begin, end, '\n');
			if (newline == end)
				return nullopt;

			if (newline + 1 != end && *(newline + 1) == '\t')
				newline++;
			else
				cont = false;

			value.append(begin, newline);
			begin = newline + 1;
		}

		if (type == "e") {
			if (value.size() != 0)
				return nullopt;
			items->emplace_back(name, typename Item::Empty {});
		} else if (type == "i")
			try {
				items->emplace_back(name, std::stoi(value));
			} catch (invalid_argument &) {
				return nullopt;
			} catch (out_of_range &) {
				return nullopt; // TODO
			}
		else if (type == "t")
			items->emplace_back(name, value);
		else if (type == "b") {
			if (value.size() % 2)
				return nullopt;
			vector<uint8_t> binary(value.size() / 2, 0);

			for (size_t i = 0; i < binary.size(); i++)
				std::from_chars(value.data() + 2 * i,
						value.data() + 2 * i + 2,
						binary[i], 16);
			items->emplace_back(name, std::move(binary));
		} else if (type == "d")
			items->emplace_back(name, ZonedTime(value));
		else if (type == "u")
			items->emplace_back(name, UUID(value));
		else if (type == "r") {
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
	}

	return RecordT<S>(items);
}

template<class S>
vector<uint8_t> RecordT<S>::encode() const
{
	return ObjectT<S>(*this).encode();
}

template<class S>
typename RecordT<S>::Items RecordT<S>::items() const
{
	return Items(ptr);
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
typename RecordT<S>::Items RecordT<S>::items(const string & name) const
{
	return Items(ptr, name);
}

template<class S>
vector<uint8_t> RecordT<S>::encodeInner() const
{
	vector<uint8_t> res;
	auto inserter = std::back_inserter(res);
	for (const auto & item : *ptr) {
		string type;
		string value;

		if (item.asEmpty()) {
			type = "e";
			value = "";
		} else if (auto x = item.asInteger()) {
			type = "i";
			value = to_string(*x);
		} else if (auto x = item.asText()) {
			type = "t";
			value = *x;
		} else if (auto x = item.asBinary()) {
			type = "b";
			value.resize(x->size() * 2, '0');
			for (size_t i = 0; i < x->size(); i++)
				std::to_chars(value.data() + 2 * i + ((*x)[i] < 0x10),
						value.data() + 2 * i + 2,
						(*x)[i], 16);
		} else if (auto x = item.asDate()) {
			type = "d";
			value = string(*x);
		} else if (auto x = item.asUUID()) {
			type = "u";
			value = string(*x);
		} else if (auto x = item.asRef()) {
			type = "r";
			if (x->digest().isZero())
				continue;
			value = string(x->digest());
		} else if (auto x = item.asUnknown()) {
			type = x->type;
			value = x->value;
		} else {
			throw runtime_error("unhandeled record item type");
		}

		copy(item.name.begin(), item.name.end(), inserter);
		inserter = ':';
		copy(type.begin(), type.end(), inserter);
		inserter = ' ';

		auto i = value.begin();
		while (true) {
			auto j = std::find(i, value.end(), '\n');
			copy(i, j, inserter);
			inserter = '\n';
			if (j == value.end())
				break;
			inserter = '\t';
			i = j + 1;
		}
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

	ssize_t size;
	try {
		size = std::stol(string(space + 1, newline));
	} catch (invalid_argument &) {
		return nullopt;
	} catch (out_of_range &) {
		// Way too big to handle anyway
		return nullopt;
	}
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

template< class S >
vector< ObjectT< S >> ObjectT< S >::decodeMany( const S & st,
		const std::vector< uint8_t > & data)
{
	vector< ObjectT< S >> objects;
	auto cur = data.begin();

	while( auto pair = decodePrefix( st, cur, data.end() )) {
		auto [ obj, next ] = *pair;
		objects.push_back( move( obj ));
		cur = next;
	}
	return objects;
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
ObjectT<S> ObjectT<S>::load(const typename S::Ref & ref)
{
	return *ref;
}

template<class S>
ObjectT<S>::operator bool() const
{
	return not holds_alternative<monostate>(content);
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


Generation::Generation(): Generation(0) {}
Generation::Generation(size_t g): gen(g) {}

Generation Generation::next(const vector<Generation> & prev)
{
	Generation ret;
	for (const auto g : prev)
		if (ret.gen <= g.gen)
			ret.gen = g.gen + 1;
	return ret;
}

Generation::operator string() const
{
	return to_string(gen);
}


vector<Stored<Object>> erebos::collectStoredObjects(const Stored<Object> & from)
{
	unordered_set<Digest> seen;
	vector<Stored<Object>> queue { from };
	vector<Stored<Object>> res;

	while (!queue.empty()) {
		auto cur = queue.back();
		queue.pop_back();

		auto [it, added] = seen.insert(cur.ref().digest());
		if (!added)
			continue;

		res.push_back(cur);

		if (auto rec = cur->asRecord())
			for (const auto & ref : rec->items().asRef())
				queue.push_back(Stored<Object>::load(ref));
	}

	return res;
}
