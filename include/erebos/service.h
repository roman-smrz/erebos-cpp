#pragma once

#include <erebos/state.h>
#include <erebos/uuid.h>

#include <memory>

namespace erebos {

class Service
{
public:
	Service();
	virtual ~Service();

	class Context
	{
	public:
		struct Priv;
		Context(Priv *);
		Priv & priv();

		const class Ref & ref() const;
		const class Peer & peer() const;

		const Stored<LocalState> & local() const;
		void local(const LocalState &);

	private:
		std::unique_ptr<Priv> p;
	};

	virtual UUID uuid() const = 0;
	virtual void handle(Context &) = 0;

	virtual void serverStarted(const class Server &);
};

}
