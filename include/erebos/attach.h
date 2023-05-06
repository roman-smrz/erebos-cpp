#pragma once

#include <erebos/pairing.h>

#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace erebos {

using std::mutex;
using std::optional;
using std::promise;
using std::string;
using std::vector;

struct AttachIdentity;

class AttachService : public PairingService<AttachIdentity>
{
public:
	AttachService(Config &&, const Server &);
	virtual ~AttachService();

	UUID uuid() const override;

	void attachTo(const Peer &);

protected:
	virtual Stored<AttachIdentity> handlePairingComplete(const Peer &) override;
	virtual void handlePairingResult(Context &, Stored<AttachIdentity>) override;

	mutex handlerLock;
};

template<class T> class Signed;

struct AttachIdentity
{
	Stored<Signed<struct IdentityData>> identity;
	vector<vector<uint8_t>> keys;

	static AttachIdentity load(const Ref &);
	Ref store(const Storage &) const;
};

}
