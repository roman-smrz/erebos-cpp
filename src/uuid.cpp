#include <erebos/uuid.h>

#include <stdexcept>

using namespace erebos;

using std::runtime_error;
using std::string;

static const size_t UUID_STR_LEN = 36;

static const char * FORMAT_STRING = "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-"
	"%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx";

UUID::UUID(string str)
{
	if (str.size() != UUID_STR_LEN)
		throw runtime_error("invalid UUID");

	if (sscanf(str.c_str(), FORMAT_STRING,
				&uuid[0], &uuid[1], &uuid[2], &uuid[3], &uuid[4], &uuid[5], &uuid[6], &uuid[7],
				&uuid[8], &uuid[9], &uuid[10], &uuid[11], &uuid[12], &uuid[13], &uuid[14], &uuid[15])
			!= 16)
		throw runtime_error("invalid UUID");
}

UUID::operator string() const
{
	string str(UUID_STR_LEN, '\0');
	snprintf(str.data(), UUID_STR_LEN + 1, FORMAT_STRING,
			uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
			uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
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
