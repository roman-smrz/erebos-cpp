#include <erebos/attach.h>

#include "identity.h"
#include "pubkey.h"

#include <erebos/network.h>

#include <stdexcept>

using namespace erebos;
using std::lock_guard;
using std::nullopt;
using std::runtime_error;

static const UUID myUUID("4995a5f9-2d4d-48e9-ad3b-0bf1c2a1be7f");

AttachService::AttachService() = default;
AttachService::~AttachService() = default;

UUID AttachService::uuid() const
{
	return myUUID;
}

void AttachService::attachTo(const Peer & peer)
{
	requestPairing(myUUID, peer);
}

Stored<AttachIdentity> AttachService::handlePairingComplete(const Peer & peer)
{
	auto owner = peer.server().identity().finalOwner();
	auto id = peer.identity()->ref();
	auto prev = Stored<Signed<IdentityData>>::load(*peer.identity()->ref());

	auto idata = peer.tempStorage().store(IdentityData {
		.prev = { prev },
		.name = nullopt,
		.owner = Stored<Signed<IdentityData>>::load(*owner.ref()),
		.keyIdentity = prev->data->keyIdentity,
		.keyMessage = nullopt,
	});

	auto key = SecretKey::load(owner.keyIdentity());
	if (!key)
		throw runtime_error("failed to load secret key");

	auto mkey = SecretKey::load(owner.keyMessage());
	if (!mkey)
		throw runtime_error("failed to load secret key");

	auto sdata = key->sign(idata);

	return peer.tempStorage().store(AttachIdentity {
		.identity = sdata,
		.keys = { key->getData(), mkey->getData() },
	});
}

void AttachService::handlePairingResult(Context & ctx, Stored<AttachIdentity> att)
{
	if (att->identity->data->prev.size() != 1 ||
			att->identity->data->prev[0].ref().digest() !=
			ctx.local()->identity()->ref()->digest())
		return;

	if (att->identity->data->keyIdentity.ref().digest() !=
			ctx.local()->identity()->keyIdentity().ref().digest())
		return;

	auto key = SecretKey::load(ctx.peer().server().identity().keyIdentity());
	if (!key)
		throw runtime_error("failed to load secret key");

	auto id = Identity::load(key->signAdd(att->identity).ref());
	if (!id)
		printf("New identity validation failed\n");

	auto rid = ctx.local().ref().storage().copy(*id->ref());
	id = Identity::load(rid);

	auto owner = id->owner();
	if (!owner)
		printf("New identity without owner\n");

	// Store the keys
	for (const auto & k : att->keys) {
		SecretKey::fromData(owner->keyIdentity(), k);
		SecretKey::fromData(owner->keyMessage(), k);
	}

	ctx.local(ctx.local()->identity(*id));
}

AttachIdentity AttachIdentity::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return AttachIdentity {
			.identity = Stored<Signed<IdentityData>>::load(ref.storage().zref()),
			.keys = {},
		};

	vector<vector<uint8_t>> keys;
	for (auto s : rec->items("skey"))
		if (const auto & b = s.asBinary())
			keys.push_back(*b);

	return AttachIdentity {
		.identity = *rec->item("identity").as<Signed<IdentityData>>(),
		.keys = keys,
	};
}

Ref AttachIdentity::store(const Storage & st) const
{
	vector<Record::Item> items;

	items.emplace_back("identity", identity.ref());
	for (const auto & key : keys)
		items.emplace_back("skey", key);

	return st.storeObject(Record(std::move(items)));
}
