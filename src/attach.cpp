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

AttachService::AttachService(Config && config, const Server &):
	PairingService(move(config))
{
}

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
	auto pid = peer.identity();

	auto idata = peer.tempStorage().store(IdentityData {
		.prev = pid->data(),
		.name = nullopt,
		.owner = owner.data()[0],
		.keyIdentity = pid->keyIdentity(),
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

	vector<StoredIdentityPart> parts = ctx.local()->identity()->extData();
	parts.emplace_back(key->signAdd(att->identity));
	filterAncestors(parts);

	auto id = Identity::load(parts);
	if (!id)
		printf("New identity validation failed\n");

	optional<Ref> tmpref = id->extRef();
	if (not tmpref)
		tmpref = id->modify().commit().extRef();

	auto rid = ctx.local().ref().storage().copy(*tmpref);
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

	return AttachIdentity {
		.identity = *rec->item("identity").as<Signed<IdentityData>>(),
		.keys = rec->items("skey").asBinary(),
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
