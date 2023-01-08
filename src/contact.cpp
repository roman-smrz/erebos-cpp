#include "contact.h"

#include "identity.h"

#include <array>

using namespace erebos;

using std::array;
using std::move;

DEFINE_SHARED_TYPE(Set<Contact>,
		"34fbb61e-6022-405f-b1b3-a5a1abecd25e",
		&Set<Contact>::load,
		[](const Set<Contact> & set) {
			return set.store();
		})

static const UUID serviceUUID("d9c37368-0da1-4280-93e9-d9bd9a198084");

Contact::Contact(vector<Stored<ContactData>> data):
	p(shared_ptr<Priv>(new Priv {
		.data = data,
	}))
{
}

optional<Identity> Contact::identity() const
{
	p->init();
	return p->identity;
}

optional<string> Contact::customName() const
{
	p->init();
	return p->name;
}

Contact Contact::customName(const Storage & st, const string & name) const
{
	auto cdata = st.store(ContactData {
		.prev = p->data,
		.identity = {},
		.name = name,
	});

	return Contact(shared_ptr<Contact::Priv>(new Contact::Priv {
		.data = { cdata },
	}));
}

string Contact::name() const
{
	if (auto cust = customName())
		return *cust;
	if (auto id = p->identity)
		if (auto idname = id->name())
			return *idname;
	return "";
}

bool Contact::operator==(const Contact & other) const
{
	return p->data == other.p->data;
}

bool Contact::operator!=(const Contact & other) const
{
	return p->data != other.p->data;
}

vector<Stored<ContactData>> Contact::data() const
{
	return p->data;
}

Digest Contact::leastRoot() const
{
	if (p->data.empty())
		return Digest(array<uint8_t, Digest::size> {});

	vector<Digest> roots;
	for (const auto & d : p->data)
		for (const auto & r : d.ref().roots())
			roots.push_back(r);
	roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
	return roots[0];
}

void Contact::Priv::init()
{
	std::call_once(initFlag, [this]() {
		vector<Stored<Signed<IdentityData>>> idata;
		for (const auto & c : findPropertyComponents<Contact>(data, "identity"))
			for (const auto & i : c->identity)
				idata.push_back(i);

		identity = Identity::load(idata);
		if (identity)
			name = identity->name();

		if (auto opt = findPropertyComponent<Contact>(data, "name"))
			name = (*opt)->name;
	});
}

ContactData ContactData::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return ContactData();

	vector<Stored<ContactData>> prev;
	for (const auto & x : rec->items("PREV"))
		if (const auto & p = x.as<ContactData>())
			prev.push_back(*p);

	vector<Stored<Signed<IdentityData>>> identity;
	for (const auto & x : rec->items("identity"))
		if (const auto & i = x.asRef())
			identity.push_back(*i);

	return ContactData {
		.prev = std::move(prev),
		.identity = std::move(identity),
		.name = rec->item("name").asText(),
	};
}

Ref ContactData::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto & prev : prev)
		items.emplace_back("PREV", prev.ref());
	for (const auto & idt : identity)
		items.emplace_back("identity", idt);
	if (name)
		items.emplace_back("name", *name);

	return st.storeObject(Record(std::move(items)));
}

ContactService::ContactService() = default;
ContactService::~ContactService() = default;

UUID ContactService::uuid() const
{
	return serviceUUID;
}

void ContactService::serverStarted(const Server & s)
{
	PairingService<ContactAccepted>::serverStarted(s);
	server = &s;
}

void ContactService::request(const Peer & peer)
{
	requestPairing(serviceUUID, peer);
}

Stored<ContactAccepted> ContactService::handlePairingComplete(const Peer & peer)
{
	server->localHead().update([&] (const Stored<LocalState> & local) {
		auto cdata = local.ref().storage().store(ContactData {
			.prev = {},
			.identity = peer.identity()->finalOwner().data(),
			.name = std::nullopt,
		});

		Contact contact(shared_ptr<Contact::Priv>(new Contact::Priv {
			.data = { cdata },
		}));

		auto contacts = local->shared<Set<Contact>>();

		return local.ref().storage().store(local->shared<Set<Contact>>(
			contacts.add(local.ref().storage(), contact)));
	});

	return peer.tempStorage().store(ContactAccepted {});
}

void ContactService::handlePairingResult(Context & ctx, Stored<ContactAccepted>)
{
	auto cdata = ctx.local().ref().storage().store(ContactData {
		.prev = {},
		.identity = ctx.peer().identity()->finalOwner().data(),
		.name = std::nullopt,
	});

	Contact contact(shared_ptr<Contact::Priv>(new Contact::Priv {
		.data = { cdata },
	}));

	auto contacts = ctx.local()->shared<Set<Contact>>();

	ctx.local(ctx.local()->shared<Set<Contact>>(
		contacts.add(ctx.local().ref().storage(), contact)));
}

ContactAccepted ContactAccepted::load(const Ref &)
{
	return ContactAccepted {};
}

Ref ContactAccepted::store(const Storage & st) const
{
	vector<Record::Item> items;
	items.emplace_back("accept", "");
	return st.storeObject(Record(std::move(items)));
}
