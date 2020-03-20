#pragma once

#include <array>
#include <string>

namespace erebos {

struct UUID
{
	explicit UUID(std::string);
	explicit operator std::string() const;

	bool operator==(const UUID &) const;
	bool operator!=(const UUID &) const;

	std::array<uint8_t, 16> uuid;
};

}
