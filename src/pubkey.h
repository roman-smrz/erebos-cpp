#pragma once

#include "storage.h"

#include <openssl/evp.h>

using std::nullopt;
using std::optional;
using std::shared_ptr;

namespace erebos {

template<typename T> class Signed;

class PublicKey
{
	PublicKey(EVP_PKEY * key):
		key(key, EVP_PKEY_free) {}
	friend class SecretKey;
public:
	static optional<PublicKey> load(const Ref &);
	Ref store(const Storage &) const;

	const shared_ptr<EVP_PKEY> key;
};

class SecretKey
{
	SecretKey(EVP_PKEY * key, const Stored<PublicKey> & pub):
		key(key, EVP_PKEY_free), pub_(pub) {}
	SecretKey(shared_ptr<EVP_PKEY> && key, const Stored<PublicKey> & pub):
		key(key), pub_(pub) {}
public:
	static SecretKey generate(const Storage & st);
	static optional<SecretKey> load(const Stored<PublicKey> & st);

	Stored<PublicKey> pub() const { return pub_; }

	template<class T>
	Stored<Signed<T>> sign(const Stored<T> &) const;

private:
	vector<uint8_t> sign(const Digest &) const;

	const shared_ptr<EVP_PKEY> key;
	Stored<PublicKey> pub_;
};

class Signature
{
public:
	static optional<Signature> load(const Ref &);
	Ref store(const Storage &) const;

	bool verify(const Ref &) const;

	Stored<PublicKey> key;
	vector<uint8_t> sig;

private:
	friend class SecretKey;
	Signature(const Stored<PublicKey> & key, const vector<uint8_t> & sig):
		key(key), sig(sig) {}
};

template<typename T>
class Signed
{
public:
	static optional<Signed<T>> load(const Ref &);
	Ref store(const Storage &) const;

	bool isSignedBy(const Stored<PublicKey> &) const;

	const Stored<T> data;
	const vector<Stored<Signature>> sigs;

private:
	friend class SecretKey;
	Signed(const Stored<T> & data, const vector<Stored<Signature>> & sigs):
		data(data), sigs(sigs) {}
};

template<class T>
Stored<Signed<T>> SecretKey::sign(const Stored<T> & val) const
{
	auto st = val.ref.storage();
	auto sig = st.store(Signature(pub(), sign(val.ref.digest())));
	return st.store(Signed(val, { sig }));
}

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
Ref Signed<T>::store(const Storage & st) const
{
	vector<Record::Item> items;

	items.emplace_back("SDATA", data);
	for (const auto & sig : sigs)
		items.emplace_back("sig", sig);

	return st.storeObject(Record(std::move(items)));
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
