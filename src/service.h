#pragma once

#include <erebos/network.h>
#include <erebos/service.h>

namespace erebos {

struct Service::Context::Priv
{
	Ref ref;
	Peer peer;
};

}
