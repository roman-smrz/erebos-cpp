#pragma once

#include <erebos/storage.h>

namespace erebos {

class Identity
{
public:
	static std::optional<Identity> load(const Ref &);
	static std::optional<Identity> load(const std::vector<Ref> &);

	std::optional<std::string> name() const;
	std::optional<Identity> owner() const;
	std::optional<Ref> ref() const;

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
		Builder(Priv * p): p(p) {}
	};

	static Builder create(const Storage &);
	Builder modify() const;

private:
	struct Priv;
	const std::shared_ptr<const Priv> p;
	Identity(const Priv * p): p(p) {}
	Identity(std::shared_ptr<const Priv> && p): p(std::move(p)) {}
};

}
