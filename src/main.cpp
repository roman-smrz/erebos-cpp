#include <erebos/attach.h>
#include <erebos/identity.h>
#include <erebos/network.h>
#include <erebos/storage.h>

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
map<Peer, promise<bool>> attachAnswer;

Peer getPeer(const string & name)
{
	auto & plist = server->peerList();
	for (size_t i = 0; i < plist.size(); i++)
		if (plist.at(i).name() == name)
			return plist.at(i);
	ostringstream ss;
	ss << "peer '" << name << "' not found";
	throw invalid_argument(ss.str().c_str());
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
			return st.store(loc->identity(*identity));
		});
		if (nh)
			*h = *nh;
	}
}

void printAttachResult(Peer peer, future<bool> && success)
{
	bool s = success.get();
	ostringstream ss;
	ss << "attach-result " << peer.name() << " " << s;
	printLine(ss.str());
}

future<bool> confirmAttach(const Peer & peer, string confirm, future<bool> && success)
{
	thread(printAttachResult, peer, move(success)).detach();

	promise<bool> promise;
	auto input = promise.get_future();
	attachAnswer[peer] = move(promise);

	ostringstream ss;
	ss << "attach-confirm " << peer.name() << " " << confirm;
	printLine(ss.str());
	return input;
}

void startServer(const vector<string> &)
{
	vector<unique_ptr<Service>> services;

	auto atts = make_unique<AttachService>();
	atts->onRequest(confirmAttach);
	atts->onResponse(confirmAttach);
	services.push_back(move(atts));

	server.emplace(*h, move(services));

	server->peerList().onUpdate([](size_t idx, const Peer * peer) {
		ostringstream ss;
		ss << "peer " << idx;
		if (peer) {
			ss << " " << peer->name();
			if (peer->identity() && peer->identity()->name())
				ss << " " << *peer->identity()->name();
		} else {
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

void attach(const vector<string> & params)
{
	server->svc<AttachService>().attachTo(getPeer(params.at(0)));
}

void attachAccept(const vector<string> & params)
{
	attachAnswer.extract(getPeer(params[0]))
		.mapped().set_value(params[1] == "1");
}

vector<Command> commands = {
	{ "create-identity", createIdentity },
	{ "start-server", startServer },
	{ "stop-server", stopServer },
	{ "watch-local-identity", watchLocalIdentity },
	{ "attach", attach },
	{ "attach-accept", attachAccept },
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
