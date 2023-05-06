#include "message.h"

#include <erebos/network.h>

using namespace erebos;
using std::nullopt;
using std::scoped_lock;
using std::unique_lock;

static const UUID myUUID("c702076c-4928-4415-8b6b-3e839eafcb0d");

static vector<DirectMessageThread> threadList;
static mutex threadLock;

DirectMessageThread DirectMessageThread::Priv::getThreadLocked(const Identity & peer)
{
	for (const auto & t : threadList)
		if (t.p->peer.sameAs(peer))
			return t;

	DirectMessageThread t(new DirectMessageThread::Priv {
		.peer = peer,
		.head = {},
	});
	threadList.push_back(t);
	return t;
}

DirectMessageThread DirectMessageThread::Priv::updateThreadLocked(const Identity & peer, vector<Stored<DirectMessageData>> && head)
{
	DirectMessageThread nt(new DirectMessageThread::Priv {
		.peer = peer,
		.head = std::move(head),
	});

	for (auto & t : threadList)
		if (t.p->peer.sameAs(peer)) {
			t = nt;
			return nt;
		}

	threadList.push_back(nt);
	return nt;
}


DirectMessage::DirectMessage(Priv * p):
	p(p)
{}

DirectMessageData DirectMessageData::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return DirectMessageData();

	vector<Stored<DirectMessageData>> prev;
	for (auto p : rec->items("PREV"))
		if (const auto & x = p.as<DirectMessageData>())
			prev.push_back(*x);

	auto fref = rec->item("from").asRef();

	return DirectMessageData {
		.prev = std::move(prev),
		.from = fref ? Identity::load(*fref) : nullopt,
		.time = *rec->item("time").asDate(),
		.text = rec->item("text").asText().value(),
	};
}

Ref DirectMessageData::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto & prev : prev)
		items.emplace_back("PREV", prev.ref());
	if (from)
		items.emplace_back("from", from->ref().value());
	if (time)
		items.emplace_back("time", *time);
	if (text)
		items.emplace_back("text", *text);

	return st.storeObject(Record(std::move(items)));
}


const optional<Identity> & DirectMessage::from() const
{
	return p->data->from;
}

const optional<ZonedTime> & DirectMessage::time() const
{
	return p->data->time;
}

string DirectMessage::text() const
{
	if (p->data->text)
		return p->data->text.value();
	return "";
}


DirectMessageThread::DirectMessageThread(Priv * p):
	p(p)
{}

DirectMessageThread::Iterator::Iterator(Priv * p):
	p(p)
{}

DirectMessageThread::Iterator::Iterator(const Iterator & other):
	Iterator(new Priv(*other.p))
{}

DirectMessageThread::Iterator::~Iterator() = default;

DirectMessageThread::Iterator & DirectMessageThread::Iterator::operator=(const Iterator & other)
{
	p.reset(new Priv(*other.p));
	return *this;
}

DirectMessageThread::Iterator & DirectMessageThread::Iterator::operator++()
{
	if (p->current)
		for (const auto & m : p->current->p->data->prev)
			p->next.push_back(m);

	if (p->next.empty()) {
		p->current.reset();
	} else {
		filterAncestors(p->next);
		auto ncur = p->next[0];

		for (const auto & m : p->next)
			if (!ncur->time || (m->time && m->time->time >= ncur->time->time))
				ncur = m;

		p->current.emplace(DirectMessage(new DirectMessage::Priv {
			.data = ncur,
		}));

		p->next.erase(std::remove(p->next.begin(), p->next.end(), p->current->p->data));
	}

	return *this;
}

DirectMessage DirectMessageThread::Iterator::operator*() const
{
	return *p->current;
}

bool DirectMessageThread::Iterator::operator==(const Iterator & other) const
{
	if (p->current && other.p->current)
		return p->current->p->data == other.p->current->p->data;
	return bool(p->current) == bool(other.p->current);
}

bool DirectMessageThread::Iterator::operator!=(const Iterator & other) const
{
	return !(*this == other);
}

DirectMessageThread::Iterator DirectMessageThread::begin() const
{
	return ++Iterator(new Iterator::Priv {
		.current = {},
		.next = p->head,
	});
}

DirectMessageThread::Iterator DirectMessageThread::end() const
{
	return Iterator(new Iterator::Priv {
		.current = {},
		.next = {},
	});
}

size_t DirectMessageThread::size() const
{
	size_t c = 0;
	for (auto it = begin(); it != end(); ++it)
		c++;
	return c;
}

DirectMessage DirectMessageThread::at(size_t i) const
{
	return *std::next(begin(), i);
}

const Identity & DirectMessageThread::peer() const
{
	return p->peer;
}


DirectMessageService::Config & DirectMessageService::Config::onUpdate(ThreadWatcher w)
{
	watchers.push_back(w);
	return *this;
}

DirectMessageService::DirectMessageService(Config && c, const Server & s):
	config(move(c)),
	server(s)
{}

DirectMessageService::~DirectMessageService() = default;

UUID DirectMessageService::uuid() const
{
	return myUUID;
}

void DirectMessageService::handle(Context & ctx)
{
	auto pid = ctx.peer().identity();
	if (!pid)
		return;
	auto powner = pid->finalOwner();

	unique_lock lock(threadLock);

	vector<Stored<DirectMessageData>> head(DirectMessageThread::Priv::getThreadLocked(powner).p->head);
	head.push_back(Stored<DirectMessageData>::load(ctx.ref()));
	filterAncestors(head);
	auto dmt = DirectMessageThread::Priv::updateThreadLocked(powner, std::move(head));

	lock.unlock();

	for (const auto & w : config.watchers)
		w(dmt, -1, -1);
}

DirectMessageThread DirectMessageService::thread(const Identity & peer)
{
	scoped_lock lock(threadLock);
	return DirectMessageThread::Priv::getThreadLocked(peer.finalOwner());
}

DirectMessage DirectMessageService::send(const Peer & peer, const string & text)
{
	auto pid = peer.identity();
	if (!pid)
		throw std::runtime_error("Peer without known identity");
	auto powner = pid->finalOwner();

	scoped_lock lock(threadLock);

	auto msg = server.localHead().ref().storage().store(DirectMessageData {
		.prev = DirectMessageThread::Priv::getThreadLocked(powner).p->head,
		.from = server.identity().finalOwner(),
		.time = ZonedTime::now(),
		.text = text,
	});

	DirectMessageThread::Priv::updateThreadLocked(powner, { msg });
	peer.send(myUUID, msg.ref());

	return DirectMessage(new DirectMessage::Priv {
		.data = msg,
	});
}
