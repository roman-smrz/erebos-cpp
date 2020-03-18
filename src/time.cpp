#include <erebos/time.h>

#include <stdexcept>

using namespace erebos;

using std::runtime_error;
using std::string;

ZonedTime::ZonedTime(string str)
{
	intmax_t t;
	unsigned int h, m;
	char sign[2];
	if (sscanf(str.c_str(), "%jd %1[+-]%2u%2u", &t, sign, &h, &m) != 4)
		throw runtime_error("invalid zoned time");

	time = std::chrono::system_clock::time_point(std::chrono::seconds(t));
	zone = std::chrono::minutes((sign[0] == '-' ? -1 : 1) * (60 * h + m));
}

ZonedTime::operator string() const
{
	char buf[32];
	unsigned int az = std::chrono::abs(zone).count();
	snprintf(buf, sizeof(buf), "%jd %c%02u%02u",
			(intmax_t) std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count(),
			zone < decltype(zone)::zero() ? '-' : '+', az / 60, az % 60);
	return string(buf);
}

ZonedTime ZonedTime::now()
{
	return ZonedTime(std::chrono::system_clock::now());
}
