#pragma once

#include <erebos/storage.h>

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

		const Ref & ref() const;
		const class Peer & peer() const;

	private:
		std::unique_ptr<Priv> p;
	};

	virtual UUID uuid() const = 0;
	virtual void handle(Context &) const = 0;
};

}
