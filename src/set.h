#include <erebos/set.h>

namespace erebos {

struct SetItem
{
	static SetItem load(const Ref &);
	Ref store(const Storage & st) const;

	const vector<Stored<SetItem>> prev;
	const vector<Ref> item;
};

struct SetBase::Priv
{
	vector<Stored<SetItem>> items;
};

}
