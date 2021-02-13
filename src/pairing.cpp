#include <erebos/pairing.h>

#include "service.h"

#include <openssl/rand.h>

#include <arpa/inet.h>

#include <algorithm>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace erebos;

using std::lock_guard;
using std::runtime_error;

void PairingServiceBase::onRequestInit(RequestInitHook hook)
{
	lock_guard lock(stateLock);
	requestInitHook = hook;
}

void PairingServiceBase::onResponse(ConfirmHook hook)
{
	lock_guard lock(stateLock);
	responseHook = hook;
}

void PairingServiceBase::onRequest(ConfirmHook hook)
{
	lock_guard lock(stateLock);
	requestHook = hook;
}

void PairingServiceBase::onRequestNonceFailed(RequestNonceFailedHook hook)
{
	lock_guard lock(stateLock);
	requestNonceFailedHook = hook;
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
	auto & state = peerStates.try_emplace(ctx.peer(), State()).first->second;

	if (auto request = rec->item("request").asBinary()) {
		if (state.phase != StatePhase::NoPairing)
			return;

		if (requestInitHook)
			requestInitHook(ctx.peer());

		state.phase = StatePhase::PeerRequest;
		state.peerCheck = *request;
		state.nonce.resize(32);
		RAND_bytes(state.nonce.data(), state.nonce.size());

		ctx.peer().send(uuid(), Object(Record({
			{ "response", state.nonce },
		})));
	}

	else if (auto response = rec->item("response").asBinary()) {
		if (state.phase != StatePhase::OurRequest) {
			fprintf(stderr, "Unexpected pairing response.\n"); // TODO
			return;
		}

		if (responseHook) {
			string confirm = confirmationNumber(nonceDigest(
				ctx.peer().server().identity(), *pid, 
				state.nonce, *response));
			std::thread(&PairingServiceBase::waitForConfirmation,
					this, ctx.peer(), confirm).detach();
		}

		state.phase = StatePhase::OurRequestConfirm;

		ctx.peer().send(uuid(), Object(Record({
			{ "reqnonce", state.nonce },
		})));
	}

	else if (auto reqnonce = rec->item("reqnonce").asBinary()) {
		auto check = nonceDigest(
				*pid, ctx.peer().server().identity(),
				*reqnonce, vector<uint8_t>());
		if (check != state.peerCheck) {
			if (requestNonceFailedHook)
				requestNonceFailedHook(ctx.peer());
			if (state.phase < StatePhase::PairingDone) {
				state.phase = StatePhase::PairingFailed;
				state.success.set_value(false);
			}
			return;
		}

		if (requestHook) {
			string confirm = confirmationNumber(nonceDigest(
				*pid, ctx.peer().server().identity(),
				*reqnonce, state.nonce));
			std::thread(&PairingServiceBase::waitForConfirmation,
					this, ctx.peer(), confirm).detach();
		}

		state.phase = StatePhase::PeerRequestConfirm;
	}

	else if (auto decline = rec->item("decline").asText()) {
		if (state.phase < StatePhase::PairingDone) {
			state.phase = StatePhase::PairingFailed;
			state.success.set_value(false);
		}
	}

	else {
		if (state.phase == StatePhase::OurRequestReady) {
			handlePairingResult(ctx);
			state.phase = StatePhase::PairingDone;
			state.success.set_value(true);
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

	lock_guard lock(stateLock);
	auto & state = peerStates.try_emplace(peer, State()).first->second;

	state.phase = StatePhase::OurRequest;
	state.nonce.resize(32);
	RAND_bytes(state.nonce.data(), state.nonce.size());

	vector<Record::Item> items;
	items.emplace_back("request", nonceDigest(
				peer.server().identity(), *pid,
				state.nonce, vector<uint8_t>()));

	peer.send(serviceId, Object(Record(std::move(items))));
}

vector<uint8_t> PairingServiceBase::nonceDigest(const Identity & id1, const Identity & id2,
	const vector<uint8_t> & nonce1, const vector<uint8_t> & nonce2)
{
	vector<Record::Item> items;
	items.emplace_back("id", id1.ref().value());
	items.emplace_back("id", id2.ref().value());
	items.emplace_back("nonce", nonce1);
	items.emplace_back("nonce", nonce2);

	const auto arr = Digest::of(Object(Record(std::move(items)))).arr();
	vector<uint8_t> ret(arr.size());
	std::copy_n(arr.begin(), arr.size(), ret.begin());
	return ret;
}

string PairingServiceBase::confirmationNumber(const vector<uint8_t> & digest)
{
	uint32_t confirm;
	memcpy(&confirm, digest.data(), sizeof(confirm));
	string ret(7, '\0');
	snprintf(ret.data(), ret.size(), "%06d", ntohl(confirm) % 1000000);
	return ret;
}

void PairingServiceBase::waitForConfirmation(Peer peer, string confirm)
{
	ConfirmHook hook;
	future<bool> success;
	{
		lock_guard lock(stateLock);
		auto & state = peerStates.try_emplace(peer, State()).first->second;
		if (state.phase == StatePhase::OurRequestConfirm)
			hook = responseHook;
		if (state.phase == StatePhase::PeerRequestConfirm)
			hook = requestHook;

		success = state.success.get_future();
	}

	bool ok = hook(peer, confirm, std::move(success)).get();

	lock_guard lock(stateLock);
	auto & state = peerStates.try_emplace(peer, State()).first->second;

	if (ok) {
		if (state.phase == StatePhase::OurRequestConfirm) {
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
				state.phase = StatePhase::PairingDone;
				state.success.set_value(true);
			} else {
				state.phase = StatePhase::OurRequestReady;
			}
		} else if (state.phase == StatePhase::PeerRequestConfirm) {
			peer.send(uuid(), handlePairingCompleteRef(peer));
			state.phase = StatePhase::PairingDone;
			state.success.set_value(true);
		}
	} else {
		if (state.phase != StatePhase::PairingFailed) {
			peer.send(uuid(), Object(Record({{ "decline", string() }})));
			state.phase = StatePhase::PairingFailed;
			state.success.set_value(false);
		}
	}
}
