#pragma once

#include <chrono>
#include <string>

namespace erebos {

struct ZonedTime
{
	explicit ZonedTime(std::string);
	ZonedTime(std::chrono::system_clock::time_point t): time(t), zone(0) {}
	explicit operator std::string() const;

	static ZonedTime now();

	std::chrono::system_clock::time_point time;
	std::chrono::minutes zone; // zone offset
};

}
