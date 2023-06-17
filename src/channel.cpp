#include "channel.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <endian.h>

using std::remove_const;
using std::runtime_error;

using namespace erebos;

Ref ChannelRequestData::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto & p : peers)
		items.emplace_back("peer", p);
	items.emplace_back("enc", "aes-128-gcm");
	items.emplace_back("key", key);

	return st.storeObject(Record(std::move(items)));
}

ChannelRequestData ChannelRequestData::load(const Ref & ref)
{
	if (auto rec = ref->asRecord()) {
		if (rec->item("enc").asText() == "aes-128-gcm")
			if (auto key = rec->item("key").as<PublicKexKey>())
				return ChannelRequestData {
					.peers = rec->items("peer").as<Signed<IdentityData>>(),
					.key = *key,
				};
	}

	return ChannelRequestData {
		.peers = {},
		.key = Stored<PublicKexKey>::load(ref.storage().zref()),
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

ChannelAcceptData ChannelAcceptData::load(const Ref & ref)
{
	if (auto rec = ref->asRecord())
		if (rec->item("enc").asText() == "aes-128-gcm")
			return ChannelAcceptData {
				.request = *rec->item("req").as<ChannelRequest>(),
				.key = *rec->item("key").as<PublicKexKey>(),
			};

	return ChannelAcceptData {
		.request = Stored<ChannelRequest>::load(ref.storage().zref()),
		.key = Stored<PublicKexKey>::load(ref.storage().zref()),
	};
}

unique_ptr<Channel> ChannelAcceptData::channel() const
{
	if (auto secret = SecretKexKey::load(key))
		return make_unique<Channel>(
			request->data->peers,
			secret->dh(*request->data->key),
			false
		);

	if (auto secret = SecretKexKey::load(request->data->key))
		return make_unique<Channel>(
			request->data->peers,
			secret->dh(*key),
			true
		);

	throw runtime_error("failed to load secret DH key");
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
				Stored<Signed<IdentityData>>::load(*self.ref()),
				Stored<Signed<IdentityData>>::load(*peer.ref()),
			} :
			vector<Stored<Signed<IdentityData>>> {
				Stored<Signed<IdentityData>>::load(*peer.ref()),
				Stored<Signed<IdentityData>>::load(*self.ref()),
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

vector<uint8_t> Channel::encrypt(const vector<uint8_t> & plain)
{
	vector<uint8_t> res(plain.size() + 8 + 16 + 16);
	array<uint8_t, 12> iv;

	uint64_t beCount = htobe64(nonceCounter++);
	std::memcpy(res.data(), &beCount, 8);
	std::copy_n(nonceFixedOur.begin(), 6, iv.begin());
	std::copy_n(res.begin() + 2, 6, iv.begin() + 6);

	const unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
		ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(),
			nullptr, key.data(), iv.data());

	int outl = 0;
	uint8_t * cur = res.data() + 8;

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

optional<vector<uint8_t>> Channel::decrypt(const vector<uint8_t> & ctext)
{
	vector<uint8_t> res(ctext.size());
	array<uint8_t, 12> iv;

	std::copy_n(nonceFixedPeer.begin(), 6, iv.begin());
	std::copy_n(ctext.begin() + 2, 6, iv.begin() + 6);

	const unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
		ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(),
			nullptr, key.data(), iv.data());

	int outl = 0;
	uint8_t * cur = res.data();

	if (EVP_DecryptUpdate(ctx.get(), cur, &outl,
				ctext.data() + 8, ctext.size() - 8 - 16) != 1)
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
