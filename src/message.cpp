#include "message.h"

#include <erebos/contact.h>
#include <erebos/network.h>

using namespace erebos;
using std::nullopt;
using std::scoped_lock;

static const UUID myUUID("c702076c-4928-4415-8b6b-3e839eafcb0d");

DEFINE_SHARED_TYPE(DirectMessageThreads,
		"ee793681-5976-466a-b0f0-4e1907d3fade",
		&DirectMessageThreads::load,
		[](const DirectMessageThreads & threads) {
			return threads.store();
		})


static void findThreadComponents(vector<Stored<DirectMessageState>> & candidates,
		const Stored<DirectMessageState> & cur,
		const Identity & peer,
		vector<Stored<DirectMessageData>> DirectMessageState::* sel)
{
	if (cur->peer && cur->peer->sameAs(peer) && not ((*cur).*sel).empty())
		candidates.push_back(cur);
	else
		for (const auto & p : cur->prev)
			findThreadComponents(candidates, p, peer, sel);
}

static vector<Stored<DirectMessageState>> findThreadComponents(
		const vector<Stored<DirectMessageState>> & leaves,
		const Identity & peer,
		vector<Stored<DirectMessageData>> DirectMessageState::* sel)
{
	vector<Stored<DirectMessageState>> candidates;
	for (const auto & obj : leaves)
		findThreadComponents(candidates, obj, peer, sel);
	filterAncestors(candidates);
	return candidates;
}


DirectMessage::DirectMessage(Priv * p):
	p(p)
{}

DirectMessageData DirectMessageData::load(const Ref & ref)
{
	auto rec = ref->asRecord();
	if (!rec)
		return DirectMessageData();

	auto fref = rec->item("from").asRef();

	return DirectMessageData {
		.prev = rec->items("PREV").as<DirectMessageData>(),
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
		items.emplace_back("from", from->extRef().value());
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


DirectMessageState DirectMessageState::load(const Ref & ref)
{
	if (auto rec = ref->asRecord()) {
		return DirectMessageState {
			.prev = rec->items("PREV").as<DirectMessageState>(),
			.peer = Identity::load(rec->items("peer").asRef()),

			.ready = rec->items("ready").as<DirectMessageData>(),
			.sent = rec->items("sent").as<DirectMessageData>(),
			.received = rec->items("received").as<DirectMessageData>(),
			.seen = rec->items("seen").as<DirectMessageData>(),
		};
	}

	return DirectMessageState();
}

Ref DirectMessageState::store(const Storage & st) const
{
	vector<Record::Item> items;

	for (const auto & prev : prev)
		items.emplace_back("PREV", prev.ref());
	if (peer)
		for (const auto & ref : peer->refs())
			items.emplace_back("peer", ref);

	for (const auto & x : ready)
		items.emplace_back("ready", x.ref());
	for (const auto & x : sent)
		items.emplace_back("sent", x.ref());
	for (const auto & x : received)
		items.emplace_back("received", x.ref());
	for (const auto & x : seen)
		items.emplace_back("seen", x.ref());

	return st.storeObject(Record(std::move(items)));
}


DirectMessageThreads::DirectMessageThreads() = default;

DirectMessageThreads::DirectMessageThreads(Stored<DirectMessageState> s):
	DirectMessageThreads(vector<Stored<DirectMessageState>> { move(s) })
{
}

DirectMessageThreads::DirectMessageThreads(vector<Stored<DirectMessageState>> s):
	state(move(s))
{
}

DirectMessageThreads DirectMessageThreads::load(const vector<Ref> & refs)
{
	DirectMessageThreads res;
	res.state.reserve(refs.size());
	for (const auto & ref : refs)
		res.state.push_back(Stored<DirectMessageState>::load(ref));
	return res;
}

vector<Ref> DirectMessageThreads::store() const
{
	vector<Ref> refs;
	refs.reserve(state.size());
	for (const auto & x : state)
		refs.push_back(x.ref());
	return refs;
}

vector<Stored<DirectMessageState>> DirectMessageThreads::data() const
{
	return state;
}

bool DirectMessageThreads::operator==(const DirectMessageThreads & other) const
{
	return state == other.state;
}

bool DirectMessageThreads::operator!=(const DirectMessageThreads & other) const
{
	return state != other.state;
}

DirectMessageThread DirectMessageThreads::thread(const Identity & peer) const
{
	vector<Stored<DirectMessageData>> head;
	for (const auto & c : findThreadComponents(state, peer, &DirectMessageState::ready))
		for (const auto & m : c->ready)
			head.push_back(m);
	for (const auto & c : findThreadComponents(state, peer, &DirectMessageState::received))
		for (const auto & m : c->received)
			head.push_back(m);
	filterAncestors(head);

	return new DirectMessageThread::Priv {
		.peer = peer,
		.head = move(head),
	};
}

vector<Stored<DirectMessageState>> Mergeable<DirectMessageThreads>::components(const DirectMessageThreads & threads)
{
	return threads.data();
}


DirectMessageService::Config & DirectMessageService::Config::onUpdate(ThreadWatcher w)
{
	watchers.push_back(w);
	return *this;
}

DirectMessageService::DirectMessageService(Config && c, const Server & s):
	config(move(c)),
	server(s),
	watched(server.localState().lens<SharedState>().lens<DirectMessageThreads>().watch(
				std::bind(&DirectMessageService::updateHandler, this, std::placeholders::_1)))
{
	server.peerList().onUpdate(std::bind(&DirectMessageService::peerWatcher, this,
				std::placeholders::_1, std::placeholders::_2));
}

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

	auto msg = Stored<DirectMessageData>::load(ctx.ref());

	server.localHead().update([&](const Stored<LocalState> & loc) {
		auto st = loc.ref().storage();
		auto threads = loc->shared<DirectMessageThreads>();

		vector<Stored<DirectMessageData>> receivedOld;
		for (const auto & c : findThreadComponents(threads.state, powner, &DirectMessageState::received))
			for (const auto & m : c->received)
				receivedOld.push_back(m);
		auto receivedNew = receivedOld;
		receivedNew.push_back(msg);
		filterAncestors(receivedNew);

		if (receivedNew != receivedOld) {
			auto state = st.store(DirectMessageState {
				.prev = threads.data(),
				.peer = powner,
				.received = { msg },
			});

			auto res = st.store(loc->shared<DirectMessageThreads>(DirectMessageThreads(state)));
			return res;
		} else {
			return loc;
		}
	});
}

DirectMessageThread DirectMessageService::thread(const Identity & peer)
{
	return server.localState().get().shared<DirectMessageThreads>().thread(peer);
}

DirectMessage DirectMessageService::send(const Head<LocalState> & head, const Identity & to, const string & text)
{
	Stored<DirectMessageData> msg;

	head.update([&](const Stored<LocalState> & loc) {
		auto st = loc.ref().storage();

		auto threads = loc->shared<DirectMessageThreads>();
		msg = st.store(DirectMessageData {
			.prev = threads.thread(to).p->head,
			.from = loc->identity()->finalOwner(),
			.time = ZonedTime::now(),
			.text = text,
		});

		auto state = st.store(DirectMessageState {
			.prev = threads.data(),
			.peer = to,
			.ready = { msg },
		});

		return st.store(loc->shared<DirectMessageThreads>(DirectMessageThreads(state)));
	});

	return DirectMessage(new DirectMessage::Priv {
		.data = move(msg),
	});
}

DirectMessage DirectMessageService::send(const Head<LocalState> & head, const Contact & to, const string & text)
{
	if (auto id = to.identity())
		return send(head, *id, text);
	throw std::runtime_error("contact without erebos identity");
}

DirectMessage DirectMessageService::send(const Head<LocalState> & head, const Peer & to, const string & text)
{
	if (auto id = to.identity())
		return send(head, id->finalOwner(), text);
	throw std::runtime_error("peer without known identity");
}

DirectMessage DirectMessageService::send(const Identity & to, const string & text)
{
	return send(server.localHead(), to, text);
}

DirectMessage DirectMessageService::send(const Contact & to, const string & text)
{
	if (auto id = to.identity())
		return send(*id, text);
	throw std::runtime_error("contact without erebos identity");
}

DirectMessage DirectMessageService::send(const Peer & to, const string & text)
{
	if (auto id = to.identity())
		return send(id->finalOwner(), text);
	throw std::runtime_error("peer without known identity");
}

void DirectMessageService::updateHandler(const DirectMessageThreads & threads)
{
	scoped_lock lock(stateMutex);

	auto state = prevState;
	for (const auto & s : threads.state)
		state.push_back(s);
	filterAncestors(state);

	if (state != prevState) {
		auto queue = state;
		vector<Identity> peers;

		while (not queue.empty()) {
			auto cur = move(queue.back());
			queue.pop_back();

			if (auto peer = cur->peer) {
				bool found = false;
				for (const auto & p : peers) {
					if (p.sameAs(*peer)) {
						found = true;
						break;
					}
				}

				if (not found)
					peers.push_back(*peer);

				for (const auto & prev : cur->prev)
					queue.push_back(prev);
			}
		}

		for (const auto & peer : peers) {
			auto dmt = threads.thread(peer);
			for (const auto & w : config.watchers)
				w(dmt, -1, -1);

			if (auto netPeer = server.peer(peer))
				syncWithPeer(server.localHead(), dmt, *netPeer);
		}

		prevState = move(state);
	}
}

void DirectMessageService::peerWatcher(size_t, const class Peer * peer)
{
	if (peer) {
		if (auto pid = peer->identity()) {
			syncWithPeer(server.localHead(),
					thread(pid->finalOwner()), *peer);
		}
	}
}

void DirectMessageService::syncWithPeer(const Head<LocalState> & head, const DirectMessageThread & thread, const Peer & peer)
{
	for (const auto & msg : thread.p->head)
		peer.send(myUUID, msg.ref());

	head.update([&](const Stored<LocalState> & loc) {
		auto st = head.storage();

		auto threads = loc->shared<DirectMessageThreads>();

		vector<Stored<DirectMessageData>> oldSent;
		for (const auto & c : findThreadComponents(threads.data(), thread.peer(), &DirectMessageState::sent))
			for (const auto & m : c->sent)
				oldSent.push_back(m);
		filterAncestors(oldSent);

		auto newSent = oldSent;
		for (const auto & msg : thread.p->head)
			newSent.push_back(msg);
		filterAncestors(newSent);

		if (newSent != oldSent) {
			auto state = st.store(DirectMessageState {
				.prev = threads.data(),
				.peer = thread.peer(),
				.sent = move(newSent),
			});

			return st.store(loc->shared<DirectMessageThreads>(DirectMessageThreads(state)));
		}

		return loc;
	});
}
