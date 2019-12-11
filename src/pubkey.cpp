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
