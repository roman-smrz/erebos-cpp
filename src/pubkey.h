#pragma once

#include "storage.h"

#include <openssl/evp.h>

using std::nullopt;
using std::optional;
using std::shared_ptr;

namespace erebos {

class PublicKey
{
	PublicKey(EVP_PKEY * key):
		key(key, EVP_PKEY_free) {}
public:
	static optional<PublicKey> load(const Ref &);
	const shared_ptr<EVP_PKEY> key;
};

class SecretKey
{
	SecretKey(EVP_PKEY * key, const Stored<PublicKey> & pub):
		key(key, EVP_PKEY_free), pub(pub) {}

private:
	const shared_ptr<EVP_PKEY> key;
	Stored<PublicKey> pub;
};

class Signature
{
public:
	static optional<Signature> load(const Ref &);

	bool verify(const Ref &) const;

	Stored<PublicKey> key;
	vector<uint8_t> sig;
};

template<typename T>
class Signed
{
public:
	static optional<Signed<T>> load(const Ref &);

	bool isSignedBy(const Stored<PublicKey> &) const;

	const Stored<T> data;
	const vector<Stored<Signature>> sigs;
};

template<typename T>
optional<Signed<T>> Signed<T>::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	auto data = rec->item("SDATA").as<T>();
	if (!data)
		return nullopt;

	vector<Stored<Signature>> sigs;
	for (auto item : rec->items("sig"))
		if (auto sig = item.as<Signature>())
			if (sig.value()->verify(data.value().ref))
				sigs.push_back(sig.value());

	return Signed {
		.data = data.value(),
		.sigs = sigs,
	};
}

template<typename T>
bool Signed<T>::isSignedBy(const Stored<PublicKey> & key) const
{
	for (const auto & sig : sigs)
		if (sig->key == key)
			return true;
	return false;
}

}
