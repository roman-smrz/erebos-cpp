#pragma once

#include <erebos/identity.h>

#include <functional>

namespace erebos {

class Server
{
public:
	Server(const Identity &);
	~Server();

	class PeerList & peerList() const;

	struct Peer;
private:
	struct Priv;
	const std::shared_ptr<Priv> p;
};

class Peer
{
public:
	struct Priv;
	Peer(const std::shared_ptr<Priv> & p);
	~Peer();

	std::string name() const;
	std::optional<Identity> identity() const;

private:
	std::shared_ptr<Priv> p;
};

class PeerList
{
public:
	struct Priv;
	PeerList();
	PeerList(const std::shared_ptr<Priv> & p);
	~PeerList();

	size_t size() const;
	Peer at(size_t n) const;

	void onUpdate(std::function<void(size_t, const Peer *)>);

private:
	friend Server;
	const std::shared_ptr<Priv> p;
};

}
