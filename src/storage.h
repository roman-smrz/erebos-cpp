#pragma once

#include "erebos/storage.h"

#include <future>
#include <unordered_set>

namespace fs = std::filesystem;

using std::optional;
using std::shared_future;
using std::unordered_set;
using std::vector;

namespace erebos {

struct Storage::Priv
{
	static constexpr size_t CHUNK = 16384;

	fs::path root;

	fs::path objectPath(const Digest &) const;
	fs::path keyPath(const Digest &) const;
	optional<vector<uint8_t>> loadBytes(const Digest &) const;
	void storeBytes(const Digest &, const vector<uint8_t> &) const;
};

struct Ref::Priv
{
	Storage storage;
	Digest digest;

	shared_future<Object> object;
};

vector<Stored<Object>> collectStoredObjects(const Stored<Object> &);

}
