#include "service.h"

#include <erebos/network.h>

using namespace erebos;

static const UUID myUUID("cb46b92c-9203-4694-8370-8742d8ac9dc8");

TestService::TestService( Config && c, const Server & ):
	config( move(c) )
{
}

TestService::~TestService() = default;

UUID TestService::uuid() const
{
	return myUUID;
}

void TestService::handle( Context & ctx )
{
	auto msg = Stored< Object >::load( ctx.ref() );
	for (const auto & w : config.watchers)
		w( msg );
}

void TestService::send( const Peer & peer, const Ref & msg )
{
	peer.send( myUUID, msg );
}

TestService::Config & TestService::Config::onMessage( MessageWatcher w )
{
	watchers.push_back(w);
	return *this;
}
