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
	static PublicKey load(const Ref &);
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

	static optional<SecretKey> fromData(const Stored<PublicKey> &, const vector<uint8_t> &);
	vector<uint8_t> getData() const;

	Stored<PublicKey> pub() const { return pub_; }

	template<class T>
	Stored<Signed<T>> sign(const Stored<T> &) const;
	template<class T>
	Stored<Signed<T>> signAdd(const Stored<Signed<T>> &) const;

private:
	vector<uint8_t> sign(const Digest &) const;

	const shared_ptr<EVP_PKEY> key;
	Stored<PublicKey> pub_;
};

class Signature
{
public:
	static Signature load(const Ref &);
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
	static Signed<T> load(const Ref &);
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
	auto st = val.ref().storage();
	auto sig = st.store(Signature(pub(), sign(val.ref().digest())));
	return st.store(Signed(val, { sig }));
}

template<class T>
Stored<Signed<T>> SecretKey::signAdd(const Stored<Signed<T>> & val) const
{
	auto st = val.ref().storage();
	auto sig = st.store(Signature(pub(), sign(val.ref().digest())));
	auto sigs = val->sigs;
	sigs.push_back(st.store(Signature(pub(), sign(val->data.ref().digest()))));
	return st.store(Signed(val->data, sigs));
}

template<typename T>
Signed<T> Signed<T>::load(const Ref & ref)
{
	if (auto rec = ref->asRecord())
		if (auto data = rec->item("SDATA").as<T>()) {
			vector<Stored<Signature>> sigs;
			for (auto item : rec->items("sig"))
				if (auto sig = item.as<Signature>())
					if (sig.value()->verify(data.value().ref()))
						sigs.push_back(sig.value());

			return Signed(*data, sigs);
		}

	return Signed(Stored<T>::load(ref.storage().zref()), {});
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


class PublicKexKey
{
	PublicKexKey(EVP_PKEY * key):
		key(key, EVP_PKEY_free) {}
	friend class SecretKexKey;
public:
	static PublicKexKey load(const Ref &);
	Ref store(const Storage &) const;

	const shared_ptr<EVP_PKEY> key;
};

class SecretKexKey
{
	SecretKexKey(EVP_PKEY * key, const Stored<PublicKexKey> & pub):
		key(key, EVP_PKEY_free), pub_(pub) {}
	SecretKexKey(shared_ptr<EVP_PKEY> && key, const Stored<PublicKexKey> & pub):
		key(key), pub_(pub) {}
public:
	static SecretKexKey generate(const Storage & st);
	static optional<SecretKexKey> load(const Stored<PublicKexKey> & st);

	Stored<PublicKexKey> pub() const { return pub_; }
	vector<uint8_t> dh(const PublicKexKey &) const;

private:
	const shared_ptr<EVP_PKEY> key;
	Stored<PublicKexKey> pub_;
};

}
