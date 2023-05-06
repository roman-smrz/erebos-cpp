#pragma once

#include <erebos/identity.h>
#include <erebos/network.h>
#include <erebos/service.h>

#include <future>
#include <map>
#include <mutex>
#include <string>
#include <variant>
#include <vector>

namespace erebos {

using std::function;
using std::future;
using std::map;
using std::mutex;
using std::promise;
using std::string;
using std::variant;
using std::vector;

/**
 * Template-less base class for the paring functionality that does not depend
 * on the result parameter.
 */
class PairingServiceBase : public Service
{
public:
	enum class Outcome
	{
		Success,
		PeerRejected,
		UserRejected,
		UnexpectedMessage,
		NonceMismatch,
		Stale,
	};

	using RequestInitHook = function<void(const Peer &)>;
	using ConfirmHook = function<future<bool>(const Peer &, string, future<Outcome> &&)>;
	using RequestNonceFailedHook = function<void(const Peer &)>;

	class Config
	{
	public:
		Config & onRequestInit(RequestInitHook);
		Config & onResponse(PairingServiceBase::ConfirmHook);
		Config & onRequest(PairingServiceBase::ConfirmHook);
		Config & onRequestNonceFailed(RequestNonceFailedHook);

	private:
		friend class PairingServiceBase;
		RequestInitHook requestInitHook;
		ConfirmHook responseHook;
		ConfirmHook requestHook;
		RequestNonceFailedHook requestNonceFailedHook;
	};

	PairingServiceBase(Config &&);
	virtual ~PairingServiceBase();

protected:
	void requestPairing(UUID serviceId, const Peer & peer);
	virtual void handle(Context &) override;
	virtual Ref handlePairingCompleteRef(const Peer &) = 0;
	virtual void handlePairingResult(Context &) = 0;

private:
	static vector<uint8_t> nonceDigest(const Identity & id1, const Identity & id2,
			const vector<uint8_t> & nonce1, const vector<uint8_t> & nonce2);
	static string confirmationNumber(const vector<uint8_t> &);

	const Config config;
	optional<Ref> result;

	enum class StatePhase {
		NoPairing,
		OurRequest,
		OurRequestConfirm,
		OurRequestReady,
		PeerRequest,
		PeerRequestConfirm,
		PairingDone,
		PairingFailed
	};

	struct State {
		mutex lock;
		StatePhase phase;
		optional<Identity> idReq;
		optional<Identity> idRsp;
		vector<uint8_t> nonce;
		vector<uint8_t> peerCheck;
		promise<Outcome> outcome;
	};

	map<Peer, shared_ptr<State>> peerStates;
	mutex stateLock;

	void waitForConfirmation(Peer peer, weak_ptr<State> state, string confirm, ConfirmHook hook);
};

template<class Result>
class PairingService : public PairingServiceBase
{
public:
	PairingService(Config && config):
		PairingServiceBase(move(config)) {}

protected:
	virtual Stored<Result> handlePairingComplete(const Peer &) = 0;
	virtual void handlePairingResult(Context &, Stored<Result>) = 0;

	virtual Ref handlePairingCompleteRef(const Peer &) override final;
	virtual void handlePairingResult(Context &) override final;
};

template<class Result>
Ref PairingService<Result>::handlePairingCompleteRef(const Peer & peer)
{
	return handlePairingComplete(peer).ref();
}

template<class Result>
void PairingService<Result>::handlePairingResult(Context & ctx)
{
	handlePairingResult(ctx, Stored<Result>::load(ctx.ref()));
}

}
