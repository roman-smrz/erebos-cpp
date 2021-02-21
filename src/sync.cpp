#include <erebos/sync.h>

#include <erebos/network.h>

using namespace erebos;

using std::scoped_lock;

static const UUID myUUID("a4f538d0-4e50-4082-8e10-7e3ec2af175d");

SyncService::SyncService() = default;
SyncService::~SyncService() = default;

UUID SyncService::uuid() const
{
	return myUUID;
}

void SyncService::handle(Context & ctx)
{
	auto pid = ctx.peer().identity();
	if (!pid)
		return;

	const auto & powner = pid->finalOwner();
	const auto & owner = ctx.peer().server().identity().finalOwner();

	if (!powner.sameAs(owner))
		return;

	ctx.local(
		ctx.local()->sharedRefAdd(ctx.ref())
	);
}

void SyncService::serverStarted(const Server & s)
{
	server = &s;
	server->peerList().onUpdate(std::bind(&SyncService::peerWatcher, this,
				std::placeholders::_1, std::placeholders::_2));
	watchedHead = server->localHead().watch(std::bind(&SyncService::localStateWatcher, this,
				std::placeholders::_1));
}

void SyncService::peerWatcher(size_t, const Peer * peer)
{
	if (peer && peer->identity()->finalOwner().sameAs(
				server->identity().finalOwner())) {
		scoped_lock lock(headMutex);
		for (const auto & r : (*watchedHead)->sharedRefs())
			peer->send(myUUID, r);
	}
}

void SyncService::localStateWatcher(const Head<LocalState> & head)
{
	scoped_lock lock(headMutex);

	bool same = head->sharedRefs().size() ==
		(*watchedHead)->sharedRefs().size();
	if (same) {
		for (size_t i = 0; i < head->sharedRefs().size(); i++)
			if (head->sharedRefs()[i].digest() !=
					(*watchedHead)->sharedRefs()[i].digest()) {
				same = false;
				break;
			}
	}

	if (!same) {
		*watchedHead = head;
		const auto & plist = server->peerList();
		for (size_t i = 0; i < plist.size(); i++)
			for (const auto & r : (*watchedHead)->sharedRefs())
				plist.at(i).send(myUUID, r);
	}
}
