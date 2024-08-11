#include <erebos/attach.h>
#include <erebos/contact.h>
#include <erebos/identity.h>
#include <erebos/message.h>
#include <erebos/network.h>
#include <erebos/set.h>
#include <erebos/storage.h>
#include <erebos/sync.h>

#include "storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <filesystem>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using std::cerr;
using std::cout;
using std::endl;
using std::function;
using std::future;
using std::invalid_argument;
using std::make_unique;
using std::map;
using std::mutex;
using std::optional;
using std::ostringstream;
using std::promise;
using std::scoped_lock;
using std::string;
using std::thread;
using std::to_string;
using std::unique_ptr;
using std::vector;

namespace fs = std::filesystem;

using namespace erebos;

namespace {

fs::path getErebosDir()
{
	const char * value = getenv("EREBOS_DIR");
	if (value)
		return value;
	return "./.erebos";
}

mutex outputMutex;
void printLine(const string & line)
{
	scoped_lock lock(outputMutex);
	cout << line << std::endl;
}

Storage st(getErebosDir());
optional<Head<LocalState>> testHead;
mutex testHeadMutex; // for updates from main and reading from other threads
optional<Server> server;

struct TestPeer
{
	Peer peer;
	size_t id;
	bool deleted = false;
	promise<bool> pairingAnswer {};
};
vector<TestPeer> testPeers;

TestPeer & getPeer(const string & name)
{
	try {
		return testPeers.at(std::stoi(name) - 1);
	}
	catch (const std::invalid_argument &) {}

	for (auto & p : testPeers)
		if (p.peer.name() == name)
			return p;

	ostringstream ss;
	ss << "peer '" << name << "' not found";
	throw invalid_argument(ss.str().c_str());
}

TestPeer & getPeer(const Peer & peer)
{
	for (auto & p : testPeers)
		if (p.peer == peer)
			return p;
	throw invalid_argument("peer not found");
}

Contact getContact(const string & id)
{
	auto cmp = [](const Contact & x, const Contact & y) {
		return x.data() < y.data();
	};
	for (const auto & c : testHead->behavior().lens<SharedState>().lens<Set<Contact>>().get().view(cmp)) {
		if (string(c.leastRoot()) == id) {
			return c;
		}
	}

	ostringstream ss;
	ss << "contact '" << id << "' not found";
	throw invalid_argument(ss.str().c_str());
}

struct Command
{
	string name;
	function<void(const vector<string> &)> action;
};

void store(const vector<string> & args)
{
	auto type = args.at(0);

	vector<uint8_t> inner, data;

	char * line = nullptr;
	size_t size = 0;

	while (getline(&line, &size, stdin) > 0 && strlen(line) > 1)
		copy(line, line + strlen(line), std::back_inserter(inner));

	free(line);

	auto inserter = std::back_inserter(data);
	copy(type.begin(), type.end(), inserter);
	inserter = ' ';

	auto slen = to_string(inner.size());
	copy(slen.begin(), slen.end(), inserter);
	inserter = '\n';

	copy(inner.begin(), inner.end(), inserter);

	auto digest = st.priv().storeBytes(data);

	ostringstream ss;
	ss << "store-done " << string(digest);
	printLine(ss.str());
}

void storedGeneration(const vector<string> & args)
{
	auto ref = st.ref(Digest(args.at(0)));
	if (!ref)
		throw invalid_argument("ref " + args.at(0) + " not found");

	ostringstream ss;
	ss << "stored-generation " << string(ref->digest()) << " " << string(ref->generation());
	printLine(ss.str());
}

void storedRoots(const vector<string> & args)
{
	auto ref = st.ref(Digest(args.at(0)));
	if (!ref)
		throw invalid_argument("ref " + args.at(0) + " not found");

	ostringstream ss;
	ss << "stored-roots " << string(ref->digest());
	for (const auto & dgst : ref->roots())
		ss << " " << string(dgst);
	printLine(ss.str());
}

void storedSetAdd(const vector<string> & args)
{
	auto iref = st.ref(Digest(args.at(0)));
	if (!iref)
		throw invalid_argument("ref " + args.at(0) + " not found");

	auto set = args.size() > 1 ?
		Set<vector<Stored<Object>>>::load({ *st.ref(Digest(args.at(1))) }) :
		Set<vector<Stored<Object>>>();

	ostringstream ss;
	ss << "stored-set-add";
	for (const auto & d : set.add(st, { Stored<Object>::load(*iref) }).digests())
		ss << " " << string(d);
	printLine(ss.str());
}

void storedSetList(const vector<string> & args)
{
	auto ref = st.ref(Digest(args.at(0)));
	if (!ref)
		throw invalid_argument("ref " + args.at(0) + " not found");

	for (const auto & vec : Set<vector<Stored<Object>>>::load({ *ref }).view(std::less{})) {
		ostringstream ss;
		ss << "stored-set-item";
		for (const auto & x : vec)
			ss << " " << string(x.ref().digest());
		printLine(ss.str());
	}
	printLine("stored-set-done");
}

void createIdentity(const vector<string> & args)
{
	optional<Identity> identity;
	for (ssize_t i = args.size() - 1; i >= 0; i--) {
		const auto & name = args[i];
		auto builder = Identity::create(st);
		builder.name(name);
		if (identity)
			builder.owner(*identity);
		identity = builder.commit();
	}

	if (identity) {
		auto nh = testHead->update([&identity] (const auto & loc) {
			auto ret = loc->identity(*identity);
			if (identity->owner())
				ret = ret.template shared<optional<Identity>>(identity->finalOwner());
			return st.store(ret);
		});
		if (nh) {
			scoped_lock lock(testHeadMutex);
			*testHead = *nh;
		}
	}
}

void printPairingResult(string prefix, Peer peer, future<PairingServiceBase::Outcome> && future)
{
	auto outcome = future.get();
	ostringstream ss;
	ss << prefix <<
		(outcome == PairingServiceBase::Outcome::Success ? "-done " : "-failed ") <<
		getPeer(peer).id;
	switch (outcome)
	{
	case PairingServiceBase::Outcome::Success: break;
	case PairingServiceBase::Outcome::PeerRejected: ss << " rejected"; break;
	case PairingServiceBase::Outcome::UserRejected: ss << " user"; break;
	case PairingServiceBase::Outcome::UnexpectedMessage: ss << " unexpected"; break;
	case PairingServiceBase::Outcome::NonceMismatch: ss << " nonce"; break;
	case PairingServiceBase::Outcome::Stale: ss << " stale"; break;
	}
	printLine(ss.str());
}

future<bool> confirmPairing(string prefix, const Peer & peer, string confirm, future<PairingServiceBase::Outcome> && outcome)
{
	thread(printPairingResult, prefix, peer, move(outcome)).detach();

	promise<bool> promise;
	auto input = promise.get_future();
	getPeer(peer).pairingAnswer = move(promise);

	ostringstream ss;
	ss << prefix << " " << getPeer(peer).id << " " << confirm;
	printLine(ss.str());
	return input;
}

void startServer(const vector<string> &)
{
	using namespace std::placeholders;

	ServerConfig config;

	config.service<AttachService>()
		.onRequest(bind(confirmPairing, "attach-request", _1, _2, _3))
		.onResponse(bind(confirmPairing, "attach-response", _1, _2, _3))
		;

	config.service<ContactService>()
		.onRequest(bind(confirmPairing, "contact-request", _1, _2, _3))
		.onResponse(bind(confirmPairing, "contact-response", _1, _2, _3))
		;

	config.service<DirectMessageService>()
		.onUpdate([](const DirectMessageThread & thread, ssize_t, ssize_t) {
			{
				scoped_lock lock(testHeadMutex);
				if (auto locIdentity = testHead.value()->identity())
					if (thread.at(0).from()->sameAs(locIdentity->finalOwner()))
						return;
			}

			ostringstream ss;

			string name = "<unnamed>";
			if (auto from = thread.at(0).from())
				if (auto fname = from->name())
					name = *fname;

			ss << "dm-received"
				<< " from " << name
				<< " text " << thread.at(0).text()
				;
			printLine(ss.str());
		})
		;

	config.service<SyncService>();

	server.emplace(*testHead, move(config));

	server->peerList().onUpdate([](size_t idx, const Peer * peer) {
		size_t i = 0;
		while (idx > 0 && i < testPeers.size()) {
			if (!testPeers[i].deleted)
				idx--;
			i++;
		}

		string prefix = "peer " + to_string(i + 1);
		if (peer) {
			if (i >= testPeers.size()) {
				testPeers.push_back(TestPeer { .peer = *peer, .id = i + 1 });

				ostringstream ss;
				ss << prefix << " addr " << peer->addressStr() << " " << peer->port();
				printLine(ss.str());
			}

			if (peer->identity()) {
				ostringstream ss;
				ss << prefix << " id";
				for (auto idt = peer->identity(); idt; idt = idt->owner())
					ss << " " << (idt->name() ? *idt->name() : "<unnamed>");
				printLine(ss.str());
			}
		} else {
			testPeers[i].deleted = true;
			printLine(prefix + " deleted");
		}
	});
}

void stopServer(const vector<string> &)
{
	server.reset();
	testPeers.clear();
	printLine("stop-server-done");
}

void peerAdd(const vector<string> & args)
{
	if (args.size() == 1)
		server->addPeer(args.at(0));
	else if (args.size() == 2)
		server->addPeer(args.at(0), args.at(1));
	else
		throw invalid_argument("usage: peer-add <node> [<port>]");
}

void sharedStateGet(const vector<string> &)
{
	ostringstream ss;
	ss << "shared-state-get";
	for (const auto & r : testHead->behavior().lens<vector<Ref>>().get())
		ss << " " << string(r.digest());
	printLine(ss.str());
}

void sharedStateWait(const vector<string> & args)
{
	struct SharedStateWait
	{
		mutex lock;
		bool done { false };
		optional<Watched<vector<Ref>>> watched;
	};
	auto watchedPtr = make_shared<SharedStateWait>();

	auto watched = testHead->behavior().lens<vector<Ref>>().watch([args, watchedPtr] (const vector<Ref> & refs) {
		vector<Stored<Object>> objs;
		objs.reserve(refs.size());
		for (const auto & r : refs)
			objs.push_back(Stored<Object>::load(r));

		auto objs2 = objs;
		for (const auto & a : args)
			if (auto ref = st.ref(Digest(a)))
				objs2.push_back(Stored<Object>::load(*ref));
			else
				return;

		filterAncestors(objs2);
		if (objs2 == objs) {
			ostringstream ss;
			ss << "shared-state-wait";
			for (const auto & a : args)
				ss << " " << a;
			printLine(ss.str());

			scoped_lock lock(watchedPtr->lock);
			watchedPtr->done = true;
			watchedPtr->watched = std::nullopt;
		}
	});

	scoped_lock lock(watchedPtr->lock);
	if (!watchedPtr->done)
		watchedPtr->watched = move(watched);
}

void watchLocalIdentity(const vector<string> &)
{
	auto bhv = testHead->behavior().lens<optional<Identity>>();
	static auto watchedLocalIdentity = bhv.watch([] (const optional<Identity> & idt) {
		if (idt) {
			ostringstream ss;
			ss << "local-identity";
			for (optional<Identity> i = idt; i; i = i->owner()) {
				if (auto name = i->name())
					ss << " " << i->name().value();
				else
					ss << " <unnamed>";
			}
			printLine(ss.str());
		}
	});
}

void watchSharedIdentity(const vector<string> &)
{
	auto bhv = testHead->behavior().lens<SharedState>().lens<optional<Identity>>();
	static auto watchedSharedIdentity = bhv.watch([] (const optional<Identity> & idt) {
		if (idt) {
			ostringstream ss;
			ss << "shared-identity";
			for (optional<Identity> i = idt; i; i = i->owner())
				ss << " " << i->name().value();
			printLine(ss.str());
		}
	});
}

void updateLocalIdentity(const vector<string> & params)
{
	if (params.size() != 1) {
		throw invalid_argument("usage: update-local-identity <name>");
	}

	auto nh = testHead->update([&params] (const Stored<LocalState> & loc) {
		auto st = loc.ref().storage();

		auto b = loc->identity()->modify();
		b.name(params[0]);
		return st.store(loc->identity(b.commit()));
	});
	if (nh) {
		scoped_lock lock(testHeadMutex);
		*testHead = *nh;
	}
}

void updateSharedIdentity(const vector<string> & params)
{
	if (params.size() != 1) {
		throw invalid_argument("usage: update-shared-identity <name>");
	}

	auto nh = testHead->update([&params] (const Stored<LocalState> & loc) {
		auto st = loc.ref().storage();
		auto mbid = loc->shared<optional<Identity>>();
		if (!mbid)
			return loc;

		auto b = mbid->modify();
		b.name(params[0]);
		return st.store(loc->shared<optional<Identity>>(optional(b.commit())));
	});
	if (nh) {
		scoped_lock lock(testHeadMutex);
		*testHead = *nh;
	}
}

void attachTo(const vector<string> & params)
{
	server->svc<AttachService>().attachTo(getPeer(params.at(0)).peer);
}

void attachAccept(const vector<string> & params)
{
	getPeer(params.at(0)).pairingAnswer.set_value(true);
}

void attachReject(const vector<string> & params)
{
	getPeer(params.at(0)).pairingAnswer.set_value(false);
}

void contactRequest(const vector<string> & params)
{
	server->svc<ContactService>().request(getPeer(params.at(0)).peer);
}

void contactAccept(const vector<string> & params)
{
	getPeer(params.at(0)).pairingAnswer.set_value(true);
}

void contactReject(const vector<string> & params)
{
	getPeer(params.at(0)).pairingAnswer.set_value(false);
}

void contactList(const vector<string> &)
{
	auto cmp = [](const Contact & x, const Contact & y) {
		return x.data() < y.data();
	};
	for (const auto & c : testHead->behavior().lens<SharedState>().lens<Set<Contact>>().get().view(cmp)) {
		ostringstream ss;
		ss << "contact-list-item " << string(c.leastRoot()) << " " << c.name();
		if (auto id = c.identity())
			if (auto iname = id->name())
				ss << " " << *iname;
		printLine(ss.str());
	}
	printLine("contact-list-done");
}

void contactSetName(const vector<string> & args)
{
	auto id = args.at(0);
	auto name = args.at(1);

	auto c = getContact(id);
	auto nh = testHead->update([&] (const Stored<LocalState> & loc) {
		auto st = loc.ref().storage();
		auto cc = c.customName(st, name);
		auto contacts = loc->shared<Set<Contact>>();
		return st.store(loc->shared<Set<Contact>>(contacts.add(st, cc)));
	});
	if (nh) {
		scoped_lock lock(testHeadMutex);
		*testHead = *nh;
	}

	printLine("contact-set-name-done");
}

void dmSendPeer(const vector<string> & args)
{
	DirectMessageService::send(
			*testHead,
			getPeer(args.at(0)).peer,
			args.at(1));
}

void dmSendContact(const vector<string> & args)
{
	DirectMessageService::send(
			*testHead,
			getContact(args.at(0)),
			args.at(1));
}

template<class T>
static void dmList(const T & peer)
{
	if (auto id = peer.identity())
		for (const auto & msg : testHead->behavior().get().shared<DirectMessageThreads>().thread(*id)) {
			string name = "<unnamed>";
			if (const auto & from = msg.from())
				if (const auto & opt = from->name())
					name = *opt;

			ostringstream ss;
			ss << "dm-list-item"
				<< " from " << name
				<< " text " << msg.text()
				;
			printLine(ss.str());
		}
	printLine("dm-list-done");
}

void dmListPeer(const vector<string> & args)
{
	dmList(getPeer(args.at(0)).peer);
}

void dmListContact(const vector<string> & args)
{
	dmList(getContact(args.at(0)));
}

vector<Command> commands = {
	{ "store", store },
	{ "stored-generation", storedGeneration },
	{ "stored-roots", storedRoots },
	{ "stored-set-add", storedSetAdd },
	{ "stored-set-list", storedSetList },
	{ "create-identity", createIdentity },
	{ "start-server", startServer },
	{ "stop-server", stopServer },
	{ "peer-add", peerAdd },
	{ "shared-state-get", sharedStateGet },
	{ "shared-state-wait", sharedStateWait },
	{ "watch-local-identity", watchLocalIdentity },
	{ "watch-shared-identity", watchSharedIdentity },
	{ "update-local-identity", updateLocalIdentity },
	{ "update-shared-identity", updateSharedIdentity },
	{ "attach-to", attachTo },
	{ "attach-accept", attachAccept },
	{ "attach-reject", attachReject },
	{ "contact-request", contactRequest },
	{ "contact-accept", contactAccept },
	{ "contact-reject", contactReject },
	{ "contact-list", contactList },
	{ "contact-set-name", contactSetName },
	{ "dm-send-peer", dmSendPeer },
	{ "dm-send-contact", dmSendContact },
	{ "dm-list-peer", dmListPeer },
	{ "dm-list-contact", dmListContact },
};

}

int main(int argc, char * argv[])
{
	testHead.emplace([] {
		auto hs = st.heads<LocalState>();
		if (!hs.empty())
			return hs[0];
		else
			return st.storeHead(LocalState());
	}());

	char * line = nullptr;
	size_t size = 0;

	if (argc > 1) {
		vector<string> args;
		for (int i = 2; i < argc; i++)
			args.emplace_back(argv[i]);

		for (const auto & cmd : commands) {
			if (cmd.name == argv[1]) {
				cmd.action(args);
				return 0;
			}
		}

		cerr << "Unknown command: '" << argv[1] << "'" << endl;
		return 1;
	}

	while (getline(&line, &size, stdin) > 0) {
		optional<string> command;
		vector<string> args;

		const char * last = line;
		for (const char * cur = line;; cur++) {
			if (isspace(*cur) || *cur == '\0') {
				if (last < cur) {
					if (!command)
						command.emplace(last, cur);
					else
						args.emplace_back(last, cur);
				}
				last = cur + 1;

				if (*cur == '\0')
					break;
			}
		}

		if (!command)
			continue;

		bool found = false;
		for (const auto & cmd : commands) {
			if (cmd.name == *command) {
				found = true;
				cmd.action(args);
				break;
			}
		}

		if (!found)
			cerr << "Unknown command: '" << *command << "'" << endl;
	}

	free(line);
	server.reset();
	return 0;
}
