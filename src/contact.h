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

	void init();
	std::once_flag initFlag {};

	optional<Identity> identity {};
	optional<string> name {};
};

}
