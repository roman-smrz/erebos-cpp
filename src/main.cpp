#include <erebos/attach.h>
#include <erebos/identity.h>
#include <erebos/network.h>
#include <erebos/storage.h>
#include <erebos/sync.h>

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
optional<Head<LocalState>> h;
optional<Server> server;

struct TestPeer
{
	Peer peer;
	size_t id;
	bool deleted = false;
	promise<bool> attachAnswer {};
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

struct Command
{
	string name;
	function<void(const vector<string> &)> action;
};

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
		auto nh = h->update([&identity] (const auto & loc) {
			auto ret = loc->identity(*identity);
			if (identity->owner())
				ret = ret.template shared<optional<Identity>>(identity->finalOwner());
			return st.store(ret);
		});
		if (nh)
			*h = *nh;
	}
}

void printAttachResult(string prefix, Peer peer, future<bool> && success)
{
	ostringstream ss;
	ss << prefix <<
		(success.get() ? "-done " : "-failed ") <<
		getPeer(peer).id;
	printLine(ss.str());
}

future<bool> confirmPairing(string prefix, const Peer & peer, string confirm, future<bool> && success)
{
	thread(printAttachResult, prefix, peer, move(success)).detach();

	promise<bool> promise;
	auto input = promise.get_future();
	getPeer(peer).attachAnswer = move(promise);

	ostringstream ss;
	ss << prefix << " " << getPeer(peer).id << " " << confirm;
	printLine(ss.str());
	return input;
}

void startServer(const vector<string> &)
{
	vector<unique_ptr<Service>> services;

	using namespace std::placeholders;

	auto atts = make_unique<AttachService>();
	atts->onRequest(bind(confirmPairing, "attach-request", _1, _2, _3));
	atts->onResponse(bind(confirmPairing, "attach-response", _1, _2, _3));
	services.push_back(move(atts));

	services.push_back(make_unique<SyncService>());

	server.emplace(*h, move(services));

	server->peerList().onUpdate([](size_t idx, const Peer * peer) {
		size_t i = 0;
		while (idx > 0 && i < testPeers.size() && testPeers[i].deleted) {
			if (!testPeers[i].deleted)
				idx--;
			i++;
		}

		ostringstream ss;
		ss << "peer " << i + 1;
		if (peer) {
			if (i >= testPeers.size())
				testPeers.push_back(TestPeer { .peer = *peer, .id = i + 1 });

			if (peer->identity()) {
				ss << " id";
				for (auto idt = peer->identity(); idt; idt = idt->owner())
					ss << " " << (idt->name() ? *idt->name() : "<unnamed>");
			} else {
				const auto & paddr = peer->address();
				ss << " addr " << inet_ntoa(paddr.sin_addr) << " " << ntohs(paddr.sin_port);
			}
		} else {
			testPeers[i].deleted = true;
			ss << " deleted";
		}
		printLine(ss.str());
	});
}

void stopServer(const vector<string> &)
{
	server.reset();
}

void watchLocalIdentity(const vector<string> &)
{
	auto bhv = h->behavior().lens<optional<Identity>>();
	static auto watchedLocalIdentity = bhv.watch([] (const optional<Identity> & idt) {
		if (idt) {
			ostringstream ss;
			ss << "local-identity";
			for (optional<Identity> i = idt; i; i = i->owner())
				ss << " " << i->name().value();
			printLine(ss.str());
		}
	});
}

void watchSharedIdentity(const vector<string> &)
{
	auto bhv = h->behavior().lens<SharedState>().lens<optional<Identity>>();
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

void updateSharedIdentity(const vector<string> & params)
{
	if (params.size() != 1) {
		throw invalid_argument("usage: update-shared-identity <name>");
	}

	auto nh = h->update([&params] (const Stored<LocalState> & loc) {
		auto st = loc.ref().storage();
		auto mbid = loc->shared<optional<Identity>>();
		if (!mbid)
			return loc;

		auto b = mbid->modify();
		b.name(params[0]);
		return st.store(loc->shared<optional<Identity>>(optional(b.commit())));
	});
	if (nh)
		*h = *nh;
}

void attachTo(const vector<string> & params)
{
	server->svc<AttachService>().attachTo(getPeer(params.at(0)).peer);
}

void attachAccept(const vector<string> & params)
{
	getPeer(params.at(0)).attachAnswer.set_value(true);
}

void attachReject(const vector<string> & params)
{
	getPeer(params.at(0)).attachAnswer.set_value(false);
}

vector<Command> commands = {
	{ "create-identity", createIdentity },
	{ "start-server", startServer },
	{ "stop-server", stopServer },
	{ "watch-local-identity", watchLocalIdentity },
	{ "watch-shared-identity", watchSharedIdentity },
	{ "update-shared-identity", updateSharedIdentity },
	{ "attach-to", attachTo },
	{ "attach-accept", attachAccept },
	{ "attach-reject", attachReject },
};

}

int main(int argc, char * argv[])
{
	h.emplace([] {
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
