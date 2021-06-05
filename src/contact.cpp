#include "contact.h"

#include "identity.h"

using namespace erebos;

using std::move;

DEFINE_SHARED_TYPE(List<Contact>,
		"34fbb61e-6022-405f-b1b3-a5a1abecd25e",
		&Contact::loadList,
		[](const List<Contact> & list) {
			if (list.empty())
				return vector<Ref>();
			return list.front().refs();
		})


List<Contact> Contact::prepend(const Storage & st, Identity id, List<Contact> list)
{
	auto cd = st.store(ContactData {
		.prev = list.empty() ? vector<Stored<ContactData>>() : list.front().p->data,
		.identity = id.data(),
		.name = nullopt,
	});
	return list.push_front(
			Contact(shared_ptr<Priv>(new Priv {
				.data = { cd },
				.identity = move(id),
			}))
	);
}

Identity Contact::identity() const
{
	return p->identity;
}

optional<string> Contact::name() const
{
	p->init();
	return p->name;
}

bool Contact::operator==(const Contact & other) const
{
	return p->data == other.p->data;
}

bool Contact::operator!=(const Contact & other) const
{
	return p->data != other.p->data;
}

List<Contact> Contact::loadList(const vector<Ref> & refs)
{
	vector<Stored<ContactData>> cdata;
	cdata.reserve(refs.size());

	for (const auto & r : refs)
		cdata.push_back(Stored<ContactData>::load(r));
	return Priv::loadList(move(cdata), {});
}

List<Contact> Contact::Priv::loadList(vector<Stored<ContactData>> && cdata, vector<Identity> && seen)
{
	if (cdata.empty())
		return {};

	filterAncestors(cdata);

	for (size_t i = 0; i < cdata.size(); i++) {
		auto id = Identity::load(cdata[i]->identity);
		if (!id)
			continue;

		bool skip = false;
		for (const auto & sid : seen) {
			if (id->sameAs(sid)) {
				skip = true;
				break;
			}
		}
		if (skip)
			continue;

		vector<Stored<ContactData>> next;
		next.reserve(cdata.size() - i - 1 + cdata[i]->prev.size());
		for (size_t j = i + 1; j < cdata.size(); j++)
			next.push_back(cdata[j]);
		for (const auto & x : cdata[i]->prev)
			next.push_back(x);

		seen.push_back(*id);
		auto p = shared_ptr<Priv>(new Priv { .data = move(cdata), .identity = move(*id) });
		return List(Contact(p), loadList(move(next), move(seen)));
	}

	return {};
}

vector<Ref> Contact::refs() const
{
	vector<Ref> res;
	res.reserve(p->data.size());
	for (const auto & x : p->data)
		res.push_back(x.ref());
	return res;
}

void Contact::Priv::init()
{
	std::call_once(initFlag, [this]() {
		name = identity.name();
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
