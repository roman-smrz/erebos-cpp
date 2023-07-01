#pragma once

#include <erebos/identity.h>
#include <erebos/message.h>
#include <erebos/storage.h>
#include <erebos/time.h>

#include <mutex>
#include <vector>

namespace chrono = std::chrono;
using chrono::system_clock;
using std::mutex;
using std::optional;
using std::string;
using std::vector;

namespace erebos {

struct DirectMessageData
{
	static DirectMessageData load(const Ref &);
	Ref store(const Storage &) const;

	vector<Stored<DirectMessageData>> prev;
	optional<Identity> from;
	optional<ZonedTime> time;
	optional<string> text;
};

struct DirectMessage::Priv
{
	Stored<DirectMessageData> data;
};

struct DirectMessageThread::Priv
{
	const Identity peer;
	const vector<Stored<DirectMessageData>> head;
};

struct DirectMessageThread::Iterator::Priv
{
	optional<DirectMessage> current;
	vector<Stored<DirectMessageData>> next;
};

struct DirectMessageState
{
	static DirectMessageState load(const Ref &);
	Ref store(const Storage &) const;

	vector<Stored<DirectMessageState>> prev;
	optional<Identity> peer;

	vector<Stored<DirectMessageData>> sent;
	vector<Stored<DirectMessageData>> received;
	vector<Stored<DirectMessageData>> seen;
};

}
