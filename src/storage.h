#pragma once

#include "erebos/storage.h"

#include <functional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

using std::function;
using std::mutex;
using std::optional;
using std::shared_ptr;
using std::unique_ptr;
using std::unordered_map;
using std::unordered_multimap;
using std::unordered_set;
using std::tuple;
using std::variant;
using std::vector;

namespace erebos {

class StorageBackend
{
public:
	StorageBackend() = default;
	virtual ~StorageBackend() = default;

	virtual bool contains(const Digest &) const = 0;

	virtual optional<vector<uint8_t>> loadBytes(const Digest &) const = 0;
	virtual void storeBytes(const Digest &, const vector<uint8_t> &) = 0;

	virtual optional<Digest> headRef(UUID type, UUID id) const = 0;
	virtual vector<tuple<UUID, Digest>> headRefs(UUID type) const = 0;
	virtual UUID storeHead(UUID type, const Digest & dgst) = 0;
	virtual bool replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst) = 0;
	virtual int watchHead(UUID type, const function<void(UUID id, const Digest &)> &) = 0;
	virtual void unwatchHead(UUID type, int watchId) = 0;

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const = 0;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) = 0;
};

class FilesystemStorage : public StorageBackend
{
public:
	FilesystemStorage(const fs::path &);
	virtual ~FilesystemStorage();

	virtual bool contains(const Digest &) const override;

	virtual optional<vector<uint8_t>> loadBytes(const Digest &) const override;
	virtual void storeBytes(const Digest &, const vector<uint8_t> &) override;

	virtual optional<Digest> headRef(UUID type, UUID id) const override;
	virtual vector<tuple<UUID, Digest>> headRefs(UUID type) const override;
	virtual UUID storeHead(UUID type, const Digest & dgst) override;
	virtual bool replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst) override;
	virtual int watchHead(UUID type, const function<void(UUID id, const Digest &)> &) override;
	virtual void unwatchHead(UUID type, int watchId) override;

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const override;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) override;

private:
	void inotifyWatch();

	static constexpr size_t CHUNK = 16384;

	fs::path objectPath(const Digest &) const;
	fs::path headPath(UUID id) const;
	fs::path headPath(UUID id, UUID type) const;
	fs::path keyPath(const Digest &) const;

	FILE * openLockFile(const fs::path & path) const;

	fs::path root;

	mutex watcherLock;
	std::thread watcherThread;
	int inotify = -1;
	int inotifyWakeup = -1;
	int nextWatcherId = 1;
	unordered_multimap<UUID, tuple<int, function<void(UUID id, const Digest &)>>> watchers;
	unordered_map<int, UUID> watchMap;
};

class MemoryStorage : public StorageBackend
{
public:
	MemoryStorage() = default;
	virtual ~MemoryStorage() = default;

	virtual bool contains(const Digest &) const override;

	virtual optional<vector<uint8_t>> loadBytes(const Digest &) const override;
	virtual void storeBytes(const Digest &, const vector<uint8_t> &) override;

	virtual optional<Digest> headRef(UUID type, UUID id) const override;
	virtual vector<tuple<UUID, Digest>> headRefs(UUID type) const override;
	virtual UUID storeHead(UUID type, const Digest & dgst) override;
	virtual bool replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst) override;
	virtual int watchHead(UUID type, const function<void(UUID id, const Digest &)> &) override;
	virtual void unwatchHead(UUID type, int watchId) override;

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const override;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) override;

private:
	unordered_map<Digest, vector<uint8_t>> storage;
	unordered_map<UUID, vector<tuple<UUID, Digest>>> heads;
	unordered_map<Digest, vector<uint8_t>> keys;

	mutex watcherLock;
	int nextWatcherId = 1;
	unordered_multimap<UUID, tuple<int, function<void(UUID id, const Digest &)>>> watchers;
};

class ChainStorage : public StorageBackend
{
public:
	ChainStorage(shared_ptr<StorageBackend> storage):
		ChainStorage(std::move(storage), nullptr) {}
	ChainStorage(shared_ptr<StorageBackend> storage, unique_ptr<ChainStorage> parent):
		storage(std::move(storage)), parent(std::move(parent)) {}
	virtual ~ChainStorage() = default;

	virtual bool contains(const Digest &) const override;

	virtual optional<vector<uint8_t>> loadBytes(const Digest &) const override;
	virtual void storeBytes(const Digest &, const vector<uint8_t> &) override;

	virtual optional<Digest> headRef(UUID type, UUID id) const override;
	virtual vector<tuple<UUID, Digest>> headRefs(UUID type) const override;
	virtual UUID storeHead(UUID type, const Digest & dgst) override;
	virtual bool replaceHead(UUID type, UUID id, const Digest & old, const Digest & dgst) override;
	virtual int watchHead(UUID type, const function<void(UUID id, const Digest &)> &) override;
	virtual void unwatchHead(UUID type, int watchId) override;

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const override;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) override;

private:
	shared_ptr<StorageBackend> storage;
	unique_ptr<ChainStorage> parent;

	mutex watcherLock;
	int nextWatcherId = 1;
	unordered_map<int, tuple<int, int>> watchers;
};

struct PartialStorage::Priv
{
	shared_ptr<StorageBackend> backend;

	Digest storeBytes(const vector<uint8_t> &) const;
	optional<vector<uint8_t>> loadBytes(const Digest & digest) const;

	template<class S>
	optional<Digest> copy(const typename S::Ref &, vector<Digest> *) const;
	template<class S>
	optional<Digest> copy(const ObjectT<S> &, vector<Digest> *) const;

	mutable mutex generationCacheLock {};
	mutable unordered_map<Digest, Generation> generationCache {};
};

struct PartialRef::Priv
{
	const unique_ptr<PartialStorage> storage;
	const Digest digest;
};

vector<Stored<Object>> collectStoredObjects(const Stored<Object> &);

}
