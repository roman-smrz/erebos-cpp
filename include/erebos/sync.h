#pragma once

#include <erebos/service.h>
#include <erebos/state.h>
#include <erebos/storage.h>

#include <optional>
#include <mutex>

namespace erebos {

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
	void localStateWatcher(const Head<LocalState> &);

	const class Server * server;
	std::mutex headMutex;
	std::optional<WatchedHead<LocalState>> watchedHead;
};

}
