#pragma once

#include <erebos/identity.h>
#include <erebos/list.h>
#include <erebos/pairing.h>
#include <erebos/set.h>
#include <erebos/state.h>
#include <erebos/storage.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace erebos {

using std::optional;
using std::shared_ptr;
using std::string;
using std::vector;

struct ContactData;

class Contact
{
public:
	Contact(vector<Stored<ContactData>> data);
	Contact(const Contact &) = default;
	Contact(Contact &&) = default;
	Contact & operator=(const Contact &) = default;
	Contact & operator=(Contact &&) = default;

	optional<Identity> identity() const;
	optional<string> customName() const;
	Contact customName(const Storage & st, const string & name) const;
	string name() const;

	bool operator==(const Contact &) const;
	bool operator!=(const Contact &) const;

	vector<Stored<ContactData>> data() const;
	Digest leastRoot() const;

private:
	struct Priv;
	shared_ptr<Priv> p;
	Contact(shared_ptr<Priv> p): p(p) {}

	friend class ContactService;
};

DECLARE_SHARED_TYPE(Set<Contact>)

struct ContactData
{
	static ContactData load(const Ref &);
	Ref store(const Storage &) const;

	vector<Stored<ContactData>> prev;
	vector<Stored<Signed<IdentityData>>> identity;
	optional<string> name;
};

template<> struct Mergeable<Contact>
{
	using Component = ContactData;
	static vector<Stored<ContactData>> components(const Contact & c) { return c.data(); }
	static Contact merge(vector<Stored<ContactData>> x) { return Contact(move(x)); }
};

struct ContactAccepted;

class ContactService : public PairingService<ContactAccepted>
{
public:
	ContactService();
	virtual ~ContactService();

	UUID uuid() const override;

	void serverStarted(const class Server &) override;

	void request(const Peer &);

protected:
	virtual Stored<ContactAccepted> handlePairingComplete(const Peer &) override;
	virtual void handlePairingResult(Context &, Stored<ContactAccepted>) override;

	const class Server * server;
};

template<class T> class Signed;

struct ContactAccepted
{
	static ContactAccepted load(const Ref &);
	Ref store(const Storage &) const;
};

}
