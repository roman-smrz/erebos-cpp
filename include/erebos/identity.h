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

private:
	struct Priv;
	const std::shared_ptr<const Priv> p;
	Identity(const Priv * p): p(p) {}
	Identity(std::shared_ptr<const Priv> && p): p(std::move(p)) {}
};

}
