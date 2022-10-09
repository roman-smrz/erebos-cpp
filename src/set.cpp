#include "set.h"

#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace erebos {

using std::pair;
using std::unordered_map;
using std::unordered_set;
using std::move;

SetBase::SetBase():
	p(make_shared<Priv>())
{
}

SetBase::SetBase(const vector<Ref> & refs)
{
	vector<Stored<SetItem>> items;
	for (const auto & r : refs)
		items.push_back(Stored<SetItem>::load(r));

	p = shared_ptr<Priv>(new Priv {
		.items = move(items),
	});
}

SetBase::SetBase(shared_ptr<const Priv> p_):
	p(move(p_))
{
}

shared_ptr<const SetBase::Priv> SetBase::add(Storage & st, const vector<Ref> & refs) const
{
	auto item = st.store(SetItem {
		.prev = p->items,
		.item = refs,
	});

	return shared_ptr<const Priv>(new Priv {
		.items = { move(item) },
	});
}

static void gatherSetItems(unordered_set<Digest> & seenSet, unordered_set<Digest> & seenElem,
		vector<Ref> & res, const Stored<SetItem> & item)
{
	if (!seenElem.insert(item.ref().digest()).second)
		return;

	for (const auto & r : item->item)
		if (seenSet.insert(r.digest()).second)
			res.push_back(r);

	for (const auto & p : item->prev)
		gatherSetItems(seenSet, seenElem, res, p);
}

vector<vector<Ref>> SetBase::toList() const
{
	/* Splits the graph starting from all set item refs into connected
	 * components (partitions), each such partition makes one set item,
	 * merged together in the templated SetView constructor. */

	// Gather all item references
	vector<Ref> items;
	{
		unordered_set<Digest> seenSet, seenElem;
		for (const auto & i : p->items)
			gatherSetItems(seenSet, seenElem, items, i);
	}

	unordered_map<Digest, unsigned> partMap; // maps item ref to partition number
	vector<unsigned> partMerge; // maps partitions to resulting one after partition merge

	// Use (cached) root set for assigning partition numbers
	for (const auto & item : items) {
		const auto roots = item.roots();
		unsigned part = partMerge.size();

		// If any root has partition number already, pick the smallest one
		for (const auto & rdgst : roots) {
			auto it = partMap.find(rdgst);
			if (it != partMap.end() && it->second < part)
				part = it->second;
		}

		// Update partition number for the roots and if this item
		// merges some partitions, also update the merge info
		for (const auto & rdgst : roots) {
			auto it = partMap.find(rdgst);
			if (it == partMap.end()) {
				partMap.emplace(rdgst, part);
			} else if (it->second != part) {
				partMerge[it->second] = part;
				it->second = part;
			}
		}

		// If no existing partition has been touched, mark a new one
		if (part == partMerge.size())
			partMerge.push_back(part);

		// And store resulting partition number
		partMap.emplace(item.digest(), part);
	}

	// Get all the refs for each partition
	vector<vector<Ref>> res(partMerge.size());
	for (const auto & item : items) {
		unsigned part = partMap[item.digest()];
		for (unsigned p = partMerge[part]; p != part; p = partMerge[p])
			part = p;
		res[part].push_back(item);
	}

	// Remove empty elements (merged partitions) from result list
	res.erase(std::remove(res.begin(), res.end(), vector<Ref>()), res.end());

	return res;
}

vector<Digest> SetBase::digests() const
{
	vector<Digest> res;
	res.reserve(p->items.size());
	for (const auto & i : p->items)
		res.push_back(i.ref().digest());
	return res;
}

SetItem SetItem::load(const Ref & ref)
{
	if (auto rec = ref->asRecord()) {
		vector<Stored<SetItem>> prev;
		for (auto p : rec->items("PREV"))
			if (const auto & x = p.as<SetItem>())
				prev.push_back(*x);

		vector<Ref> item;
		for (auto i : rec->items("item"))
			if (const auto & x = i.asRef())
				item.push_back(*x);

		return SetItem {
			.prev = std::move(prev),
			.item = std::move(item),
		};
	}

	return SetItem {
		.prev = {},
		.item = {},
	};
}

Ref SetItem::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto & p : prev)
		items.emplace_back("PREV", p.ref());
	for (const auto & r : item)
		items.emplace_back("item", r);

	return st.storeObject(Record(std::move(items)));
}

}
