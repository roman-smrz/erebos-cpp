#pragma once

#include <erebos/state.h>
#include <erebos/storage.h>

namespace erebos {

using std::optional;
using std::vector;

template<class T> class Signed;
struct IdentityData;
struct StoredIdentityPart;

class Identity
{
public:
	Identity(const Identity &) = default;
	Identity(Identity &&) = default;
	Identity & operator=(const Identity &) = default;
	Identity & operator=(Identity &&) = default;

	static std::optional<Identity> load(const Ref &);
	static std::optional<Identity> load(const std::vector<Ref> &);
	static std::optional<Identity> load(const std::vector<Stored<Signed<IdentityData>>> &);
	static std::optional<Identity> load(const std::vector<StoredIdentityPart> &);
	std::vector<Ref> store() const;
	std::vector<Ref> store(const Storage & st) const;
	vector<Stored<Signed<IdentityData>>> data() const;
	vector<StoredIdentityPart> extData() const;

	std::optional<std::string> name() const;
	std::optional<Identity> owner() const;
	const Identity & finalOwner() const;

	Stored<class PublicKey> keyIdentity() const;
	Stored<class PublicKey> keyMessage() const;

	bool sameAs(const Identity &) const;
	bool operator==(const Identity & other) const;
	bool operator!=(const Identity & other) const;

	std::optional<Ref> ref() const;
	std::vector<Ref> refs() const;
	std::vector<Ref> updates() const;

	class Builder
	{
	public:
		Identity commit() const;

		void name(const std::string &);
		void owner(const Identity &);

	private:
		friend class Identity;
		struct Priv;
		const std::shared_ptr<Priv> p;
		Builder(Priv * p);
	};

	static Builder create(const Storage &);
	Builder modify() const;
	Identity update(const vector<Stored<Signed<IdentityData>>> &) const;
	Identity update(const vector<StoredIdentityPart> &) const;

private:
	struct Priv;
	std::shared_ptr<const Priv> p;
	Identity(const Priv * p);
	Identity(std::shared_ptr<const Priv> && p);
};

DECLARE_SHARED_TYPE(optional<Identity>)

}
