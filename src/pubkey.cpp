#include "pubkey.h"

#include <stdexcept>

using std::unique_ptr;
using std::runtime_error;
using std::string;

using namespace erebos;

optional<PublicKey> PublicKey::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	if (auto ktype = rec->item("type").asText())
		if (ktype.value() != "ed25519")
			throw runtime_error("unsupported key type " + ktype.value());

	if (auto pubkey = rec->item("pubkey").asBinary())
		return PublicKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
					pubkey.value().data(), pubkey.value().size()));

	return nullopt;
}

Ref PublicKey::store(const Storage & st) const
{
	vector<Record::Item> items;

	items.emplace_back("type", "ed25519");

	vector<uint8_t> keyData;
	size_t keyLen;
	EVP_PKEY_get_raw_public_key(key.get(), nullptr, &keyLen);
	keyData.resize(keyLen);
	EVP_PKEY_get_raw_public_key(key.get(), keyData.data(), &keyLen);
	items.emplace_back("pubkey", keyData);

	return st.storeObject(Record(std::move(items)));
}

SecretKey SecretKey::generate(const Storage & st)
{
	unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)>
		pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL), &EVP_PKEY_CTX_free);
	if (!pctx)
		throw runtime_error("failed to generate key");

	if (EVP_PKEY_keygen_init(pctx.get()) != 1)
		throw runtime_error("failed to generate key");

	EVP_PKEY *pkey = NULL;
	if (EVP_PKEY_keygen(pctx.get(), &pkey) != 1)
		throw runtime_error("failed to generate key");
	shared_ptr<EVP_PKEY> seckey(pkey, EVP_PKEY_free);

	vector<uint8_t> keyData;
	size_t keyLen;

	EVP_PKEY_get_raw_public_key(seckey.get(), nullptr, &keyLen);
	keyData.resize(keyLen);
	EVP_PKEY_get_raw_public_key(seckey.get(), keyData.data(), &keyLen);
	auto pubkey = st.store(PublicKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
					keyData.data(), keyData.size())));

	EVP_PKEY_get_raw_private_key(seckey.get(), nullptr, &keyLen);
	keyData.resize(keyLen);
	EVP_PKEY_get_raw_private_key(seckey.get(), keyData.data(), &keyLen);
	st.storeKey(pubkey.ref, keyData);

	return SecretKey(std::move(seckey), pubkey);
}

optional<SecretKey> SecretKey::load(const Stored<PublicKey> & pub)
{
	auto keyData = pub.ref.storage().loadKey(pub.ref);
	if (!keyData)
		return nullopt;

	EVP_PKEY * key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
				keyData->data(), keyData->size());
	if (!key)
		throw runtime_error("falied to parse secret key");
	return SecretKey(key, pub);
}

vector<uint8_t> SecretKey::sign(const Digest & dgst) const
{
	unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>
		mdctx(EVP_MD_CTX_create(), &EVP_MD_CTX_free);
	if (!mdctx)
		throw runtime_error("failed to create EVP_MD_CTX");

	if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_md_null(),
				nullptr, key.get()) != 1)
		throw runtime_error("failed to initialize EVP_MD_CTX");

	size_t sigLen;
	if (EVP_DigestSign(mdctx.get(), nullptr, &sigLen,
			dgst.arr().data(), Digest::size) != 1)
		throw runtime_error("failed to sign data");

	vector<uint8_t> sigData(sigLen);
	if (EVP_DigestSign(mdctx.get(), sigData.data(), &sigLen,
			dgst.arr().data(), Digest::size) != 1)
		throw runtime_error("failed to sign data");

	return sigData;
}

optional<Signature> Signature::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	auto key = rec->item("key").as<PublicKey>();
	auto sig = rec->item("sig").asBinary();

	if (!key || !sig)
		return nullopt;

	return Signature {
		.key = key.value(),
		.sig = sig.value(),
	};
}

Ref Signature::store(const Storage & st) const
{
	vector<Record::Item> items;

	items.emplace_back("key", key);
	items.emplace_back("sig", sig);

	return st.storeObject(Record(std::move(items)));
}

bool Signature::verify(const Ref & ref) const
{
	unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>
		mdctx(EVP_MD_CTX_create(), &EVP_MD_CTX_free);
	if (!mdctx)
		throw runtime_error("failed to create EVP_MD_CTX");

	if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_md_null(),
				nullptr, key->key.get()) != 1)
		throw runtime_error("failed to initialize EVP_MD_CTX");

	return EVP_DigestVerify(mdctx.get(), sig.data(), sig.size(),
			ref.digest().arr().data(), Digest::size) == 1;
}


optional<PublicKexKey> PublicKexKey::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	if (auto ktype = rec->item("type").asText())
		if (ktype.value() != "x25519")
			throw runtime_error("unsupported key type " + ktype.value());

	if (auto pubkey = rec->item("pubkey").asBinary())
		return PublicKexKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
					pubkey.value().data(), pubkey.value().size()));

	return nullopt;
}

Ref PublicKexKey::store(const Storage & st) const
{
	vector<Record::Item> items;

	items.emplace_back("type", "x25519");

	vector<uint8_t> keyData;
	size_t keyLen;
	EVP_PKEY_get_raw_public_key(key.get(), nullptr, &keyLen);
	keyData.resize(keyLen);
	EVP_PKEY_get_raw_public_key(key.get(), keyData.data(), &keyLen);
	items.emplace_back("pubkey", keyData);

	return st.storeObject(Record(std::move(items)));
}

SecretKexKey SecretKexKey::generate(const Storage & st)
{
	unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)>
		pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL), &EVP_PKEY_CTX_free);
	if (!pctx)
		throw runtime_error("failed to generate key");

	if (EVP_PKEY_keygen_init(pctx.get()) != 1)
		throw runtime_error("failed to generate key");

	EVP_PKEY *pkey = NULL;
	if (EVP_PKEY_keygen(pctx.get(), &pkey) != 1)
		throw runtime_error("failed to generate key");
	shared_ptr<EVP_PKEY> seckey(pkey, EVP_PKEY_free);

	vector<uint8_t> keyData;
	size_t keyLen;

	EVP_PKEY_get_raw_public_key(seckey.get(), nullptr, &keyLen);
	keyData.resize(keyLen);
	EVP_PKEY_get_raw_public_key(seckey.get(), keyData.data(), &keyLen);
	auto pubkey = st.store(PublicKexKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
					keyData.data(), keyData.size())));

	EVP_PKEY_get_raw_private_key(seckey.get(), nullptr, &keyLen);
	keyData.resize(keyLen);
	EVP_PKEY_get_raw_private_key(seckey.get(), keyData.data(), &keyLen);
	st.storeKey(pubkey.ref, keyData);

	return SecretKexKey(std::move(seckey), pubkey);
}

optional<SecretKexKey> SecretKexKey::load(const Stored<PublicKexKey> & pub)
{
	auto keyData = pub.ref.storage().loadKey(pub.ref);
	if (!keyData)
		return nullopt;

	EVP_PKEY * key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
				keyData->data(), keyData->size());
	if (!key)
		throw runtime_error("falied to parse secret key");
	return SecretKexKey(key, pub);
}

vector<uint8_t> SecretKexKey::dh(const PublicKexKey & pubkey) const
{
	unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)>
		pctx(EVP_PKEY_CTX_new(key.get(), nullptr), &EVP_PKEY_CTX_free);
	if (!pctx)
		throw runtime_error("failed to derive shared secret");

	if (EVP_PKEY_derive_init(pctx.get()) <= 0)
		throw runtime_error("failed to derive shared secret");

	if (EVP_PKEY_derive_set_peer(pctx.get(), pubkey.key.get()) <= 0)
		throw runtime_error("failed to derive shared secret");

	size_t dhlen;
	if (EVP_PKEY_derive(pctx.get(), NULL, &dhlen) <= 0)
		throw runtime_error("failed to derive shared secret");

	vector<uint8_t> dhsecret(dhlen);

	if (EVP_PKEY_derive(pctx.get(), dhsecret.data(), &dhlen) <= 0)
		throw runtime_error("failed to derive shared secret");

	return dhsecret;
}
