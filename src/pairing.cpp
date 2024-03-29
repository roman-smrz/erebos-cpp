#include <erebos/pairing.h>

#include "service.h"

#include <future>
#include <openssl/rand.h>

#include <arpa/inet.h>

#include <algorithm>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace erebos;

using std::lock_guard;
using std::make_shared;
using std::runtime_error;
using std::scoped_lock;
using std::thread;
using std::unique_lock;

PairingServiceBase::PairingServiceBase(Config && c):
	config(move(c))
{
}

PairingServiceBase::~PairingServiceBase()
{
	// There may be some threads in waitForConfirmation waiting on client
	// promise, so make sure they do not touch the service state anymore:
	for (auto & [peer, state] : peerStates) {
		scoped_lock lock(state->lock);
		if (state->phase != StatePhase::PairingDone &&
				state->phase != StatePhase::PairingFailed) {
			state->outcome.set_value(Outcome::Stale);
			state->phase = StatePhase::PairingFailed;
		}
	}
}

PairingServiceBase::Config & PairingServiceBase::Config::onRequestInit(RequestInitHook hook)
{
	requestInitHook = hook;
	return *this;
}

PairingServiceBase::Config & PairingServiceBase::Config::onResponse(ConfirmHook hook)
{
	responseHook = hook;
	return *this;
}

PairingServiceBase::Config & PairingServiceBase::Config::onRequest(ConfirmHook hook)
{
	requestHook = hook;
	return *this;
}

PairingServiceBase::Config & PairingServiceBase::Config::onRequestNonceFailed(RequestNonceFailedHook hook)
{
	requestNonceFailedHook = hook;
	return *this;
}

void PairingServiceBase::handle(Context & ctx)
{
	auto rec = ctx.ref()->asRecord();
	if (!rec)
		return;

	auto pid = ctx.peer().identity();
	if (!pid)
		throw runtime_error("Pairing request for peer without known identity");

	lock_guard lock(stateLock);
	auto & state = peerStates.try_emplace(ctx.peer(), new State()).first->second;
	unique_lock lock_state(state->lock);

	if (auto request = rec->item("request").asBinary()) {
		auto idReqRef = rec->item("id-req").asRef();
		if (!idReqRef)
			return;
		auto idReq = Identity::load(*idReqRef);
		if (!idReq)
			return;
		if (!idReq->sameAs(*pid))
			return;

		auto idRspRef = rec->item("id-rsp").asRef();
		if (!idRspRef)
			return;
		auto idRsp = Identity::load(*idRspRef);
		if (!idRsp)
			return;
		if (!idRsp->sameAs(ctx.peer().server().identity()))
			return;

		if (state->phase >= StatePhase::PairingDone) {
			auto nstate = make_shared<State>();
			lock_state = unique_lock(nstate->lock);
			state = move(nstate);
		} else if (state->phase != StatePhase::NoPairing)
			return;

		if (config.requestInitHook)
			config.requestInitHook(ctx.peer());

		state->phase = StatePhase::PeerRequest;
		state->idReq = idReq;
		state->idRsp = idRsp;
		state->peerCheck = *request;
		state->nonce.resize(32);
		RAND_bytes(state->nonce.data(), state->nonce.size());

		ctx.peer().send(uuid(), Object(Record({
			{ "response", state->nonce },
		})));
	}

	else if (auto response = rec->item("response").asBinary()) {
		if (state->phase != StatePhase::OurRequest) {
			fprintf(stderr, "Unexpected pairing response.\n"); // TODO
			return;
		}

		if (config.responseHook) {
			string confirm = confirmationNumber(nonceDigest(
				*state->idReq, *state->idRsp,
				state->nonce, *response));
			std::thread(&PairingServiceBase::waitForConfirmation,
					this, ctx.peer(), state, confirm, config.responseHook).detach();
		}

		state->phase = StatePhase::OurRequestConfirm;

		ctx.peer().send(uuid(), Object(Record({
			{ "reqnonce", state->nonce },
		})));
	}

	else if (auto reqnonce = rec->item("reqnonce").asBinary()) {
		if (state->phase != StatePhase::PeerRequest)
			return;

		auto check = nonceDigest(
				*state->idReq, *state->idRsp,
				*reqnonce, vector<uint8_t>());
		if (check != state->peerCheck) {
			if (config.requestNonceFailedHook)
				config.requestNonceFailedHook(ctx.peer());
			if (state->phase < StatePhase::PairingDone) {
				state->phase = StatePhase::PairingFailed;
				ctx.afterCommit([&]() {
					state->outcome.set_value(Outcome::NonceMismatch);
				});
			}
			return;
		}

		if (config.requestHook) {
			string confirm = confirmationNumber(nonceDigest(
				*state->idReq, *state->idRsp,
				*reqnonce, state->nonce));
			std::thread(&PairingServiceBase::waitForConfirmation,
					this, ctx.peer(), state, confirm, config.requestHook).detach();
		}

		state->phase = StatePhase::PeerRequestConfirm;
	}

	else if (rec->item("reject")) {
		if (state->phase < StatePhase::PairingDone) {
			state->phase = StatePhase::PairingFailed;
			ctx.afterCommit([&]() {
				state->outcome.set_value(Outcome::PeerRejected);
			});
		}
	}

	else {
		if (state->phase == StatePhase::OurRequestReady) {
			handlePairingResult(ctx);
			state->phase = StatePhase::PairingDone;
			ctx.afterCommit([&]() {
				state->outcome.set_value(Outcome::Success);
			});
		} else {
			result = ctx.ref();
		}
	}
}

void PairingServiceBase::requestPairing(UUID serviceId, const Peer & peer)
{
	auto pid = peer.identity();
	if (!pid)
		throw runtime_error("Pairing request for peer without known identity");

	unique_lock lock(stateLock);
	auto & state = peerStates.try_emplace(peer, new State()).first->second;

	if (state->phase != StatePhase::NoPairing) {
		auto nstate = make_shared<State>();
		lock = unique_lock(nstate->lock);
		state = move(nstate);
	}

	state->phase = StatePhase::OurRequest;
	state->idReq = peer.server().identity();
	state->idRsp = pid;
	state->nonce.resize(32);
	RAND_bytes(state->nonce.data(), state->nonce.size());

	vector<Record::Item> items;
	items.emplace_back("id-req", state->idReq->ref().value());
	items.emplace_back("id-rsp", state->idRsp->ref().value());
	items.emplace_back("request", nonceDigest(
				*state->idReq, *state->idRsp,
				state->nonce, vector<uint8_t>()));

	peer.send(serviceId, Object(Record(std::move(items))));
}

vector<uint8_t> PairingServiceBase::nonceDigest(const Identity & idReq, const Identity & idRsp,
	const vector<uint8_t> & nonceReq, const vector<uint8_t> & nonceRsp)
{
	vector<Record::Item> items;
	items.emplace_back("id-req", idReq.ref().value());
	items.emplace_back("id-rsp", idRsp.ref().value());
	items.emplace_back("nonce-req", nonceReq);
	items.emplace_back("nonce-rsp", nonceRsp);

	const auto arr = Digest::of(Object(Record(std::move(items)))).arr();
	vector<uint8_t> ret(arr.size());
	std::copy_n(arr.begin(), arr.size(), ret.begin());
	return ret;
}

string PairingServiceBase::confirmationNumber(const vector<uint8_t> & digest)
{
	uint32_t confirm;
	memcpy(&confirm, digest.data(), sizeof(confirm));
	string ret(6, '\0');
	snprintf(ret.data(), ret.size() + 1, "%06d", ntohl(confirm) % 1000000);
	return ret;
}

void PairingServiceBase::waitForConfirmation(Peer peer, weak_ptr<State> wstate, string confirm, ConfirmHook hook)
{
	future<Outcome> outcome;
	if (auto state = wstate.lock()) {
		outcome = state->outcome.get_future();
	} else {
		return;
	}

	bool ok;
	try {
		ok = hook(peer, confirm, std::move(outcome)).get();
	}
	catch (const std::future_error & e) {
		if (e.code() == std::future_errc::broken_promise)
			ok = false;
		else
			throw;
	}

	auto state = wstate.lock();
	if (!state)
		return; // Server was closed

	scoped_lock lock(state->lock);

	if (ok) {
		if (state->phase == StatePhase::OurRequestConfirm) {
			if (result) {
				peer.server().localHead().update([&] (const Stored<LocalState> & local) {
					Service::Context ctx(new Service::Context::Priv {
						.ref = *result,
						.peer = peer,
						.local = local,
					});

					handlePairingResult(ctx);
					return ctx.local();
				});
				state->phase = StatePhase::PairingDone;
				state->outcome.set_value(Outcome::Success);
			} else {
				state->phase = StatePhase::OurRequestReady;
			}
		} else if (state->phase == StatePhase::PeerRequestConfirm) {
			peer.send(uuid(), handlePairingCompleteRef(peer));
			state->phase = StatePhase::PairingDone;
			state->outcome.set_value(Outcome::Success);
		}
	} else {
		if (state->phase != StatePhase::PairingFailed) {
			peer.send(uuid(), Object(Record({{ "reject", Record::Item::Empty {} }})));
			state->phase = StatePhase::PairingFailed;
			state->outcome.set_value(Outcome::UserRejected);
		}
	}
}
