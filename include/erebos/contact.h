#pragma once

#include <erebos/identity.h>
#include <erebos/list.h>
#include <erebos/state.h>
#include <erebos/storage.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace erebos {

using std::optional;
using std::shared_ptr;
using std::string;
using std::vector;

class Contact
{
public:
	Contact(const Contact &) = default;
	Contact(Contact &&) = default;
	Contact & operator=(const Contact &) = default;
	Contact & operator=(Contact &&) = default;

	static List<Contact> prepend(const Storage &, Identity, List<Contact>);

	Identity identity() const;
	optional<string> name() const;

	bool operator==(const Contact &) const;
	bool operator!=(const Contact &) const;

	static List<Contact> loadList(const vector<Ref> &);
	vector<Ref> refs() const;

private:
	struct Priv;
	shared_ptr<Priv> p;
	Contact(shared_ptr<Priv> p): p(p) {}
};

DECLARE_SHARED_TYPE(List<Contact>)

}
