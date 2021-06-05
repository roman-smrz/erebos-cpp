#pragma once

#include <erebos/contact.h>

#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace erebos {

using std::optional;
using std::string;
using std::vector;

struct ContactData;
struct IdentityData;

struct Contact::Priv
{
	vector<Stored<ContactData>> data;
	Identity identity;

	void init();
	std::once_flag initFlag {};

	optional<string> name {};

	static List<Contact> loadList(vector<Stored<ContactData>> &&, vector<Identity> &&);
};

struct ContactData
{
	static ContactData load(const Ref &);
	Ref store(const Storage &) const;

	vector<Stored<ContactData>> prev;
	vector<Stored<Signed<IdentityData>>> identity;
	optional<string> name;
};

}
