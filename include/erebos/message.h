#pragma once

#include <erebos/service.h>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace erebos {

using std::unique_ptr;

class Contact;
class Identity;

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
	struct Priv;
	DirectMessageThread(Priv *);
	std::shared_ptr<Priv> p;
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

	DirectMessage send(const Identity &, const std::string &);
	DirectMessage send(const Contact &, const std::string &);
	DirectMessage send(const Peer &, const std::string &);

private:
	const Config config;
	const Server & server;
};

}
