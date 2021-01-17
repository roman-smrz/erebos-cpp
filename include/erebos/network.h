#pragma once

#include <erebos/service.h>
#include <erebos/state.h>

#include <functional>
#include <typeinfo>

namespace erebos {

class Server
{
public:
	Server(const Head<LocalState> &, std::vector<std::unique_ptr<Service>> &&);
	~Server();

	template<class S> S & svc();

	class PeerList & peerList() const;

	struct Peer;
private:
	Service & svcHelper(const std::type_info &);

	struct Priv;
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

	std::string name() const;
	std::optional<Identity> identity() const;

	bool hasChannel() const;
	bool send(UUID, const Ref &) const;

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
