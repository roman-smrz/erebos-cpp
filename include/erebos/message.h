#pragma once

#include <erebos/merge.h>
#include <erebos/service.h>

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace erebos {

using std::mutex;
using std::unique_ptr;

class Contact;
class Identity;
struct DirectMessageState;

class DirectMessage
{
public:
	const std::optional<Identity> & from() const;
	const std::optional<struct ZonedTime> & time() const;
	std::string text() const;

private:
	friend class DirectMessageThread;
	friend class DirectMessageService;
	struct Priv;
	DirectMessage(Priv *);
	std::shared_ptr<Priv> p;
};

class DirectMessageThread
{
public:
	class Iterator
	{
		struct Priv;
		Iterator(Priv *);
	public:
		using iterator_category = std::forward_iterator_tag;
		using value_type = DirectMessage;
		using difference_type = ssize_t;
		using pointer = const DirectMessage *;
		using reference = const DirectMessage &;

		Iterator(const Iterator &);
		~Iterator();
		Iterator & operator=(const Iterator &);
		Iterator & operator++();
		value_type operator*() const;
		bool operator==(const Iterator &) const;
		bool operator!=(const Iterator &) const;

	private:
		friend DirectMessageThread;
		std::unique_ptr<Priv> p;
	};

	Iterator begin() const;
	Iterator end() const;

	size_t size() const;
	DirectMessage at(size_t) const;

	const Identity & peer() const;

private:
	friend class DirectMessageService;
	friend class DirectMessageThreads;
	struct Priv;
	DirectMessageThread(Priv *);
	std::shared_ptr<Priv> p;
};

class DirectMessageThreads
{
public:
	DirectMessageThreads();
	DirectMessageThreads(Stored<DirectMessageState>);
	DirectMessageThreads(vector<Stored<DirectMessageState>>);

	static DirectMessageThreads load(const vector<Ref> & refs);
	vector<Ref> store() const;
	vector<Stored<DirectMessageState>> data() const;

	bool operator==(const DirectMessageThreads &) const;
	bool operator!=(const DirectMessageThreads &) const;

	DirectMessageThread thread(const Identity &) const;

private:
	vector<Stored<DirectMessageState>> state;

	friend class DirectMessageService;
};

DECLARE_SHARED_TYPE(DirectMessageThreads)

template<> struct Mergeable<DirectMessageThreads>
{
	using Component = DirectMessageState;
	static vector<Stored<DirectMessageState>> components(const DirectMessageThreads &);
	static Contact merge(vector<Stored<DirectMessageState>>);
};

class DirectMessageService : public Service
{
public:
	using ThreadWatcher = std::function<void(const DirectMessageThread &, ssize_t, ssize_t)>;

	class Config
	{
	public:
		Config & onUpdate(ThreadWatcher);

	private:
		friend class DirectMessageService;
		vector<ThreadWatcher> watchers;
	};

	DirectMessageService(Config &&, const Server &);
	virtual ~DirectMessageService();

	UUID uuid() const override;
	void handle(Context &) override;

	DirectMessageThread thread(const Identity &);

	static DirectMessage send(const Head<LocalState> &, const Identity &, const std::string &);
	static DirectMessage send(const Head<LocalState> &, const Contact &, const std::string &);
	static DirectMessage send(const Head<LocalState> &, const Peer &, const std::string &);

	DirectMessage send(const Identity &, const std::string &);
	DirectMessage send(const Contact &, const std::string &);
	DirectMessage send(const Peer &, const std::string &);

private:
	void updateHandler(const DirectMessageThreads &);
	void peerWatcher(size_t, const class Peer *);
	static void syncWithPeer(const Head<LocalState> &, const DirectMessageThread &, const Peer &);

	const Config config;
	const Server & server;

	vector<Stored<DirectMessageState>> prevState;
	mutex stateMutex;

	Watched<DirectMessageThreads> watched;
};

}
