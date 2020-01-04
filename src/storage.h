#pragma once

#include "erebos/storage.h"

#include <future>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

using std::optional;
using std::shared_future;
using std::shared_ptr;
using std::unique_ptr;
using std::unordered_map;
using std::unordered_set;
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

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const = 0;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) = 0;
};

class FilesystemStorage : public StorageBackend
{
public:
	FilesystemStorage(const fs::path &);
	virtual ~FilesystemStorage() = default;

	virtual bool contains(const Digest &) const override;

	virtual optional<vector<uint8_t>> loadBytes(const Digest &) const override;
	virtual void storeBytes(const Digest &, const vector<uint8_t> &) override;

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const override;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) override;

private:
	static constexpr size_t CHUNK = 16384;

	fs::path objectPath(const Digest &) const;
	fs::path keyPath(const Digest &) const;

	fs::path root;
};

class MemoryStorage : public StorageBackend
{
public:
	MemoryStorage() = default;
	virtual ~MemoryStorage() = default;

	virtual bool contains(const Digest &) const override;

	virtual optional<vector<uint8_t>> loadBytes(const Digest &) const override;
	virtual void storeBytes(const Digest &, const vector<uint8_t> &) override;

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const override;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) override;

private:
	unordered_map<Digest, vector<uint8_t>> storage;
	unordered_map<Digest, vector<uint8_t>> keys;
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

	virtual optional<vector<uint8_t>> loadKey(const Digest &) const override;
	virtual void storeKey(const Digest &, const vector<uint8_t> &) override;

private:
	shared_ptr<StorageBackend> storage;
	unique_ptr<ChainStorage> parent;
};

struct Storage::Priv
{
	shared_ptr<StorageBackend> backend;

	optional<vector<uint8_t>> loadBytes(const Digest & digest) const;
};

struct Ref::Priv
{
	const unique_ptr<PartialStorage> storage;
	const Digest digest;
};

vector<Stored<Object>> collectStoredObjects(const Stored<Object> &);

}
