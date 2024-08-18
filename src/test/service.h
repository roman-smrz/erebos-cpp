#pragma once

#include <erebos/service.h>

namespace erebos
{

class TestService : public Service
{
public:
	using MessageWatcher = std::function<void( const Stored< Object > & )>;

	class Config
	{
	public:
		Config & onMessage( MessageWatcher );

	private:
		friend class TestService;
		vector< MessageWatcher > watchers;
	};

	TestService( Config &&, const Server & );
	virtual ~TestService();

	UUID uuid() const override;
	void handle( Context & ) override;

	static void send( const Peer &, const Ref & );

private:
	const Config config;
};

}
