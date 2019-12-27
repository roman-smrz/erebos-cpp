#pragma once

#include <erebos/identity.h>

namespace erebos {

class Server
{
public:
	Server(const Identity &);
	~Server();

private:
	struct Priv;
	const std::shared_ptr<Priv> p;
};

};
