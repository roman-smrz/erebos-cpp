#include <erebos/merge.h>

namespace erebos {

static void findPropertyObjects(vector<Stored<Object>> & candidates, const Stored<Object> & obj, const string & prop)
{
	if (auto rec = obj->asRecord()) {
		if (rec->item(prop)) {
			candidates.push_back(obj);
		} else {
			for (const auto & r : obj.ref().previous())
				findPropertyObjects(candidates, Stored<Object>::load(r), prop);
		}
	}
}

vector<Stored<Object>> findPropertyObjects(const vector<Stored<Object>> & leaves, const string & prop)
{
	vector<Stored<Object>> candidates;
	for (const auto & obj : leaves)
		findPropertyObjects(candidates, obj, prop);
	filterAncestors(candidates);
	return candidates;
}

}
