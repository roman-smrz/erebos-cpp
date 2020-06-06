#include <erebos/uuid.h>

#include <stdexcept>

#include <openssl/rand.h>

using namespace erebos;

using std::nullopt;
using std::optional;
using std::runtime_error;
using std::string;

static const size_t UUID_STR_LEN = 36;

static const char * FORMAT_STRING = "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-"
	"%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx";

UUID::UUID(const string & str)
{
	if (!fromString(str, *this))
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

optional<UUID> UUID::fromString(const string & str)
{
	UUID u;
	if (fromString(str, u))
		return u;
	return nullopt;
}

bool UUID::fromString(const string & str, UUID & u)
{
	if (str.size() != UUID_STR_LEN)
		return false;

	if (sscanf(str.c_str(), FORMAT_STRING,
				&u.uuid[0], &u.uuid[1], &u.uuid[2], &u.uuid[3], &u.uuid[4], &u.uuid[5], &u.uuid[6], &u.uuid[7],
				&u.uuid[8], &u.uuid[9], &u.uuid[10], &u.uuid[11], &u.uuid[12], &u.uuid[13], &u.uuid[14], &u.uuid[15])
			!= 16)
		return false;

	return true;
}

UUID UUID::generate()
{
	UUID u;
	if (RAND_bytes(u.uuid.data(), u.uuid.size()) != 1)
		throw runtime_error("failed to generate random UUID");

	u.uuid[6] = (u.uuid[6] & 0x0f) | 0x40;
	u.uuid[8] = (u.uuid[8] & 0x3f) | 0x80;
	return u;
}

bool UUID::operator==(const UUID & other) const
{
	return std::equal(std::begin(uuid), std::end(uuid), std::begin(other.uuid));
}

bool UUID::operator!=(const UUID & other) const
{
	return !(*this == other);
}
