#pragma once

#include <uuid/uuid.h>

#include <string>

namespace erebos {

struct UUID
{
	explicit UUID(std::string);
	explicit operator std::string() const;

	bool operator==(const UUID &) const;
	bool operator!=(const UUID &) const;

	uuid_t uuid;
};

}
