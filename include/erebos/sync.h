#pragma once

#include <erebos/service.h>
#include <erebos/state.h>
#include <erebos/storage.h>

#include <optional>
#include <mutex>
#include <vector>

namespace erebos {

using std::vector;

class SyncService : public Service
{
public:
	SyncService();
	virtual ~SyncService();

	UUID uuid() const override;
	void handle(Context &) override;

	void serverStarted(const class Server &) override;

private:
	void peerWatcher(size_t, const class Peer *);
	void localStateWatcher(const vector<Ref> &);

	const class Server * server;
	std::optional<Watched<vector<Ref>>> watchedLocal;
};

}
