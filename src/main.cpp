#include <erebos/identity.h>
#include <erebos/network.h>
#include <erebos/storage.h>

#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using std::cerr;
using std::cout;
using std::endl;
using std::function;
using std::optional;
using std::ostringstream;
using std::string;
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

Storage st(getErebosDir());
optional<Head<LocalState>> h;
optional<Server> server;

struct Command
{
	string name;
	function<void(const vector<string> &)> action;
};

void createIdentity(const vector<string> & args)
{
	optional<Identity> identity;
	for (const auto & name : args) {
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

void startServer(const vector<string> &)
{
	vector<unique_ptr<Service>> services;

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
		cout << ss.str() << endl;
	});
}

void stopServer(const vector<string> &)
{
	server.reset();
}

vector<Command> commands = {
	{ "create-identity", createIdentity },
	{ "start-server", startServer },
	{ "stop-server", stopServer },
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
