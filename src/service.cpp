#include "service.h"

using namespace erebos;

Service::Service() = default;
Service::~Service() = default;

Service::Context::Context(Priv * p):
	p(p)
{}

Service::Context::Priv & Service::Context::priv()
{
	return *p;
}

const Ref & Service::Context::ref() const
{
	return p->ref;
}

const Peer & Service::Context::peer() const
{
	return p->peer;
}

const Stored<LocalState> & Service::Context::local() const
{
	return p->local;
}

void Service::Context::local(const LocalState & ls)
{
	p->local = p->local.ref().storage().store(ls);
}
