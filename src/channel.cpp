#include "channel.h"

#include <algorithm>
#include <stdexcept>

#include <openssl/rand.h>

using std::remove_const;
using std::runtime_error;

using namespace erebos;

Ref ChannelRequestData::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto p : peers)
		items.emplace_back("peer", p);
	items.emplace_back("enc", "aes-128-gcm");
	items.emplace_back("key", key);

	return st.storeObject(Record(std::move(items)));
}

optional<ChannelRequestData> ChannelRequestData::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	remove_const<decltype(peers)>::type peers;
	for (const auto & i : rec->items("peer"))
		if (auto p = i.as<Signed<IdentityData>>())
			peers.push_back(*p);

	auto enc = rec->item("enc").asText();
	if (!enc || enc != "aes-128-gcm")
		return nullopt;

	auto key = rec->item("key").as<PublicKexKey>();
	if (!key)
		return nullopt;

	return ChannelRequestData {
		.peers = std::move(peers),
		.key = *key,
	};
}

Ref ChannelAcceptData::store(const Storage & st) const
{
	vector<Record::Item> items;

	items.emplace_back("req", request);
	items.emplace_back("enc", "aes-128-gcm");
	items.emplace_back("key", key);

	return st.storeObject(Record(std::move(items)));
}

optional<ChannelAcceptData> ChannelAcceptData::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	auto request = rec->item("req").as<ChannelRequest>();
	if (!request)
		return nullopt;

	auto enc = rec->item("enc").asText();
	if (!enc || enc != "aes-128-gcm")
		return nullopt;

	auto key = rec->item("key").as<PublicKexKey>();
	if (!key)
		return nullopt;

	return ChannelAcceptData {
		.request = *request,
		.key = *key,
	};
}

Stored<Channel> ChannelAcceptData::channel() const
{
	const auto & st = request.ref().storage();

	if (auto secret = SecretKexKey::load(key))
		return st.store(Channel(
			request->data->peers,
			secret->dh(*request->data->key)
		));

	if (auto secret = SecretKexKey::load(request->data->key))
		return st.store(Channel(
			request->data->peers,
			secret->dh(*key)
		));

	throw runtime_error("failed to load secret DH key");
}


Ref Channel::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto p : peers)
		items.emplace_back("peer", p);
	items.emplace_back("enc", "aes-128-gcm");
	items.emplace_back("key", key);

	return st.storeObject(Record(std::move(items)));
}

optional<Channel> Channel::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return nullopt;

	remove_const<decltype(peers)>::type peers;
	for (const auto & i : rec->items("peer"))
		if (auto p = i.as<Signed<IdentityData>>())
			peers.push_back(*p);

	auto enc = rec->item("enc").asText();
	if (!enc || enc != "aes-128-gcm")
		return nullopt;

	auto key = rec->item("key").asBinary();
	if (!key)
		return nullopt;

	return Channel(peers, std::move(*key));
}

Stored<ChannelRequest> Channel::generateRequest(const Storage & st,
		const Identity & self, const Identity & peer)
{
	auto signKey = SecretKey::load(self.keyMessage());
	if (!signKey)
		throw runtime_error("failed to load own message key");

	return signKey->sign(st.store(ChannelRequestData {
		.peers = self.ref()->digest() < peer.ref()->digest() ?
			vector<Stored<Signed<IdentityData>>> {
				*Stored<Signed<IdentityData>>::load(*self.ref()),
				*Stored<Signed<IdentityData>>::load(*peer.ref()),
			} :
			vector<Stored<Signed<IdentityData>>> {
				*Stored<Signed<IdentityData>>::load(*peer.ref()),
				*Stored<Signed<IdentityData>>::load(*self.ref()),
			},
		.key = SecretKexKey::generate(st).pub(),
	}));
}

optional<Stored<ChannelAccept>> Channel::acceptRequest(const Identity & self,
		const Identity & peer, const Stored<ChannelRequest> & request)
{
	if (!request->isSignedBy(peer.keyMessage()))
		return nullopt;

	auto & peers = request->data->peers;
	if (peers.size() != 2 ||
			std::none_of(peers.begin(), peers.end(), [&self](const auto & x)
				{ return x.ref().digest() == self.ref()->digest(); }) ||
			std::none_of(peers.begin(), peers.end(), [&peer](const auto & x)
				{ return x.ref().digest() == peer.ref()->digest(); }))
		return nullopt;

	auto & st = request.ref().storage();

	auto signKey = SecretKey::load(self.keyMessage());
	if (!signKey)
		throw runtime_error("failed to load own message key");

	return signKey->sign(st.store(ChannelAcceptData {
		.request = request,
		.key = SecretKexKey::generate(st).pub(),
	}));
}

vector<uint8_t> Channel::encrypt(const vector<uint8_t> & plain) const
{
	vector<uint8_t> res(plain.size() + 12 + 16 + 16);

	if (RAND_bytes(res.data(), 12) != 1)
		throw runtime_error("failed to generate random IV");

	const unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
		ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(),
			nullptr, key.data(), res.data());

	int outl = 0;
	uint8_t * cur = res.data() + 12;

	if (EVP_EncryptUpdate(ctx.get(), cur, &outl, plain.data(), plain.size()) != 1)
		throw runtime_error("failed to encrypt data");
	cur += outl;

	if (EVP_EncryptFinal(ctx.get(), cur, &outl) != 1)
		throw runtime_error("failed to encrypt data");
	cur += outl;

	EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, cur);
	cur += 16;

	res.resize(cur - res.data());
	return res;
}

optional<vector<uint8_t>> Channel::decrypt(const vector<uint8_t> & ctext) const
{
	vector<uint8_t> res(ctext.size());

	const unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
		ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(),
			nullptr, key.data(), ctext.data());

	int outl = 0;
	uint8_t * cur = res.data();

	if (EVP_DecryptUpdate(ctx.get(), cur, &outl,
				ctext.data() + 12, ctext.size() - 12 - 16) != 1)
		return nullopt;
	cur += outl;

	if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
				(void *) (ctext.data() + ctext.size() - 16)))
		return nullopt;

	if (EVP_DecryptFinal_ex(ctx.get(), cur, &outl) != 1)
		return nullopt;
	cur += outl;

	res.resize(cur - res.data());
	return res;
}
