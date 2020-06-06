#pragma once

#include <array>
#include <cstring>
#include <optional>
#include <string>

namespace erebos {

struct UUID
{
	UUID(): uuid({}) {}
	explicit UUID(const std::string &);
	explicit operator std::string() const;

	static std::optional<UUID> fromString(const std::string &);
	static bool fromString(const std::string &, UUID &);

	static UUID generate();

	bool operator==(const UUID &) const;
	bool operator!=(const UUID &) const;

	std::array<uint8_t, 16> uuid;
};

}

namespace std
{
	template<> struct hash<erebos::UUID>
	{
		std::size_t operator()(const erebos::UUID & uuid) const noexcept
		{
			std::size_t res;
			std::memcpy(&res, uuid.uuid.data(), sizeof res);
			return res;
		}
	};
}
