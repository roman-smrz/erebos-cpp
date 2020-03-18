#include <erebos/uuid.h>

#include <stdexcept>

using namespace erebos;

using std::runtime_error;
using std::string;

UUID::UUID(string str)
{
	if (uuid_parse(str.c_str(), uuid) != 0)
		throw runtime_error("invalid UUID");
}

UUID::operator string() const
{
	string str(UUID_STR_LEN - 1, '\0');
	uuid_unparse_lower(uuid, str.data());
	return str;
}

bool UUID::operator==(const UUID & other) const
{
	return std::equal(std::begin(uuid), std::end(uuid), std::begin(other.uuid));
}

bool UUID::operator!=(const UUID & other) const
{
	return !(*this == other);
}
