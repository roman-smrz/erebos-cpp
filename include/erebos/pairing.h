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
	typedef function<void(const Peer &)> RequestInitHook;
	void onRequestInit(RequestInitHook);

	typedef function<future<bool>(const Peer &, string, future<bool> &&)> ConfirmHook;
	void onResponse(ConfirmHook);
	void onRequest(ConfirmHook);

	typedef function<void(const Peer &)> RequestNonceFailedHook;
	void onRequestNonceFailed(RequestNonceFailedHook);

protected:
	void requestPairing(UUID serviceId, const Peer & peer);
	virtual void handle(Context &) override;
	virtual Ref handlePairingCompleteRef(const Peer &) = 0;
	virtual void handlePairingResult(Context &) = 0;

private:
	static vector<uint8_t> nonceDigest(const Identity & id1, const Identity & id2,
			const vector<uint8_t> & nonce1, const vector<uint8_t> & nonce2);
	static string confirmationNumber(const vector<uint8_t> &);
	void waitForConfirmation(Peer peer, string confirm);

	RequestInitHook requestInitHook;
	ConfirmHook responseHook;
	ConfirmHook requestHook;
	RequestNonceFailedHook requestNonceFailedHook;

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
		StatePhase phase;
		vector<uint8_t> nonce;
		vector<uint8_t> peerCheck;
		promise<bool> success;
	};

	map<Peer, State> peerStates;
	mutex stateLock;
};

template<class Result>
class PairingService : public PairingServiceBase
{
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
