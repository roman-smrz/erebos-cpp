#include <erebos/frp.h>

#include <condition_variable>
#include <mutex>
#include <thread>

using namespace erebos;

using std::condition_variable;
using std::move;
using std::mutex;
using std::nullopt;
using std::thread;
using std::unique_lock;

namespace {

mutex bhvTimeMutex;
condition_variable bhvTimeCond;
optional<thread::id> bhvTimeRunning = nullopt;
uint64_t bhvTimeCount = 0;
uint64_t bhvTimeLast = 0;

}

BhvTime::BhvTime(const BhvCurTime & ct):
	BhvTime(ct.time())
{}

BhvCurTime::BhvCurTime()
{
	auto tid = std::this_thread::get_id();
	unique_lock lock(bhvTimeMutex);
	bhvTimeCond.wait(lock, [tid]{
		return !bhvTimeRunning || bhvTimeRunning == tid;
	});

	if (bhvTimeRunning != tid) {
		bhvTimeRunning = tid;
		bhvTimeLast++;
	}
	t = BhvTime(bhvTimeLast);
	bhvTimeCount++;
}

BhvCurTime::~BhvCurTime()
{
	if (t) {
		unique_lock lock(bhvTimeMutex);
		bhvTimeCount--;

		if (bhvTimeCount == 0) {
			bhvTimeRunning.reset();
			lock.unlock();
			bhvTimeCond.notify_one();
		}
	}
}

BhvCurTime::BhvCurTime(BhvCurTime && other)
{
	t = other.t;
	other.t = nullopt;
}

BhvCurTime & BhvCurTime::operator=(BhvCurTime && other)
{
	t = other.t;
	other.t = nullopt;
	return *this;
}


BhvImplBase::~BhvImplBase() = default;

void BhvImplBase::dependsOn(const BhvCurTime &, shared_ptr<BhvImplBase> other)
{
	depends.push_back(other);
	other->rdepends.push_back(shared_from_this());
}

void BhvImplBase::updated(const BhvCurTime & ctime)
{
	vector<shared_ptr<BhvImplBase>> toUpdate;
	markDirty(ctime, toUpdate);

	for (auto & bhv : toUpdate)
		bhv->updateDirty(ctime);
}

void BhvImplBase::markDirty(const BhvCurTime & ctime, vector<shared_ptr<BhvImplBase>> & toUpdate)
{
	if (dirty)
		return;

	if (!needsUpdate(ctime))
		return;

	dirty = true;
	toUpdate.push_back(shared_from_this());

	bool prune = false;
	for (const auto & w : rdepends) {
		if (auto b = w.lock())
			b->markDirty(ctime, toUpdate);
		else
			prune = true;
	}

	if (prune) {
		decltype(rdepends) pruned;
		for (const auto & w : rdepends)
			if (!w.expired())
				pruned.push_back(move(w));
		rdepends = move(pruned);
	}
}

void BhvImplBase::updateDirty(const BhvCurTime & ctime)
{
	if (!dirty)
		return;

	for (auto & d : depends)
		d->updateDirty(ctime);

	doUpdate(ctime);
	dirty = false;

	bool prune = false;
	for (const auto & wcb : watchers) {
		if (auto cb = wcb.lock())
			(*cb)(ctime);
		else
			prune = true;
	}

	if (prune) {
		decltype(watchers) pruned;
		for (const auto & w : watchers)
			if (!w.expired())
				pruned.push_back(move(w));
		watchers = move(pruned);
	}
}

bool BhvImplBase::needsUpdate(const BhvCurTime &) const
{
	return true;
}

void BhvImplBase::doUpdate(const BhvCurTime &)
{
}
