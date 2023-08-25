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
	items.emplace_back("key", key);

	return st.storeObject(Record(std::move(items)));
}

ChannelRequestData ChannelRequestData::load(const Ref & ref)
{
	if (auto rec = ref->asRecord()) {
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
	items.emplace_back("key", key);

	return st.storeObject(Record(std::move(items)));
}

ChannelAcceptData ChannelAcceptData::load(const Ref & ref)
{
	if (auto rec = ref->asRecord())
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

uint64_t Channel::encrypt(BufferCIt plainBegin, BufferCIt plainEnd,
		Buffer & encBuffer, size_t encOffset)
{
	auto plainSize = plainEnd - plainBegin;
	encBuffer.resize(encOffset + plainSize + 1 /* counter */ + 16 /* tag */);
	array<uint8_t, 12> iv;

	uint64_t count = counterNextOut.fetch_add(1);
	uint64_t beCount = htobe64(count);
	encBuffer[encOffset] = count % 0x100;

	constexpr size_t nonceFixedSize = std::tuple_size_v<decltype(nonceFixedOur)>;
	static_assert(nonceFixedSize + sizeof beCount == iv.size());

	std::copy_n(nonceFixedOur.begin(), nonceFixedSize, iv.begin());
	std::memcpy(iv.data() + nonceFixedSize, &beCount, sizeof beCount);

	const unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
		ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
			nullptr, key.data(), iv.data());

	int outl = 0;
	uint8_t * cur = encBuffer.data() + encOffset + 1;

	if (EVP_EncryptUpdate(ctx.get(), cur, &outl, &*plainBegin, plainSize) != 1)
		throw runtime_error("failed to encrypt data");
	cur += outl;

	if (EVP_EncryptFinal(ctx.get(), cur, &outl) != 1)
		throw runtime_error("failed to encrypt data");
	cur += outl;

	EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, cur);
	return count;
}

optional<uint64_t> Channel::decrypt(BufferCIt encBegin, BufferCIt encEnd,
			Buffer & decBuffer, const size_t decOffset)
{
	auto encSize = encEnd - encBegin;
	decBuffer.resize(decOffset + encSize);
	array<uint8_t, 12> iv;

	if (encBegin + 1 /* counter */ + 16 /* tag */ > encEnd)
		return nullopt;

	uint64_t expectedCount = counterNextIn.load();
	uint64_t guessedCount = expectedCount - 0x80u + ((0x80u + encBegin[0] - expectedCount) % 0x100u);
	uint64_t beCount = htobe64(guessedCount);

	constexpr size_t nonceFixedSize = std::tuple_size_v<decltype(nonceFixedPeer)>;
	static_assert(nonceFixedSize + sizeof beCount == iv.size());

	std::copy_n(nonceFixedPeer.begin(), nonceFixedSize, iv.begin());
	std::memcpy(iv.data() + nonceFixedSize, &beCount, sizeof beCount);

	const unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
		ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
			nullptr, key.data(), iv.data());

	int outl = 0;
	uint8_t * cur = decBuffer.data() + decOffset;

	if (EVP_DecryptUpdate(ctx.get(), cur, &outl,
				&*encBegin + 1, encSize - 1 - 16) != 1)
		return nullopt;
	cur += outl;

	if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16,
				(void *) (&*encEnd - 16)))
		return nullopt;

	if (EVP_DecryptFinal_ex(ctx.get(), cur, &outl) != 1)
		return nullopt;
	cur += outl;

	while (expectedCount < guessedCount + 1 &&
			not counterNextIn.compare_exchange_weak(expectedCount, guessedCount + 1))
		; // empty loop body

	decBuffer.resize(cur - decBuffer.data());
	return guessedCount;
}
