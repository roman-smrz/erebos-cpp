#pragma once

#include <erebos/service.h>
#include <erebos/state.h>

#include <functional>
#include <typeinfo>

struct sockaddr_in;

namespace erebos {

class Server
{
	struct Priv;
public:
	Server(const Head<LocalState> &, std::vector<std::unique_ptr<Service>> &&);
	Server(const std::shared_ptr<Priv> &);
	~Server();

	Server(const Server &) = delete;
	Server & operator=(const Server &) = delete;

	const Head<LocalState> & localHead() const;
	const Bhv<LocalState> & localState() const;

	const Identity & identity() const;
	template<class S> S & svc();

	class PeerList & peerList() const;

	struct Peer;
private:
	Service & svcHelper(const std::type_info &);

	const std::shared_ptr<Priv> p;
};

template<class S>
S & Server::svc()
{
	return dynamic_cast<S&>(svcHelper(typeid(S)));
}

class Peer
{
public:
	struct Priv;
	Peer(const std::shared_ptr<Priv> & p);
	~Peer();

	Server server() const;

	const Storage & tempStorage() const;
	const PartialStorage & partialStorage() const;

	std::string name() const;
	std::optional<Identity> identity() const;
	const struct sockaddr_in & address() const;

	bool hasChannel() const;
	bool send(UUID, const Ref &) const;
	bool send(UUID, const Object &) const;

	bool operator==(const Peer & other) const;
	bool operator!=(const Peer & other) const;
	bool operator<(const Peer & other) const;
	bool operator<=(const Peer & other) const;
	bool operator>(const Peer & other) const;
	bool operator>=(const Peer & other) const;

private:
	bool send(UUID, const Ref &, const Object &) const;
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
