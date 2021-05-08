#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <functional>
#include <tuple>
#include <variant>

namespace erebos {

using std::enable_if_t;
using std::function;
using std::is_same_v;
using std::make_shared;
using std::monostate;
using std::optional;
using std::shared_ptr;
using std::static_pointer_cast;
using std::vector;
using std::weak_ptr;

class BhvCurTime;

class BhvTime
{
	BhvTime(uint64_t t): t(t) {}
	friend BhvCurTime;
public:
	BhvTime(const BhvCurTime &);

	bool operator==(const BhvTime & other) const { return t == other.t; }
	bool operator!=(const BhvTime & other) const { return t != other.t; }
	bool operator<(const BhvTime & other) const { return t < other.t; }
	bool operator<=(const BhvTime & other) const { return t <= other.t; }
	bool operator>(const BhvTime & other) const { return t > other.t; }
	bool operator>=(const BhvTime & other) const { return t >= other.t; }

private:
	uint64_t t;
};

class BhvCurTime
{
public:
	BhvCurTime();
	~BhvCurTime();
	BhvCurTime(const BhvCurTime &) = delete;
	BhvCurTime(BhvCurTime &&);

	BhvCurTime & operator=(const BhvCurTime &) = delete;
	BhvCurTime & operator=(BhvCurTime &&);

	BhvTime time() const { return t.value(); }

private:
	optional<BhvTime> t;
};

template<typename T>
class Watched
{
public:
	Watched(shared_ptr<function<void(const BhvCurTime &)>> && cb):
		cb(move(cb)) {}
	~Watched();

private:
	shared_ptr<function<void(const BhvCurTime &)>> cb;
};

template<typename T>
Watched<T>::~Watched()
{
	BhvCurTime ctime;
	cb.reset();
}

class BhvImplBase : public std::enable_shared_from_this<BhvImplBase>
{
public:
	virtual ~BhvImplBase();

protected:
	void dependsOn(shared_ptr<BhvImplBase> other);
	void updated(const BhvCurTime &);
	virtual bool needsUpdate(const BhvCurTime &) const;
	virtual void doUpdate(const BhvCurTime &);

	bool isDirty(const BhvCurTime &) const { return dirty; }

	vector<weak_ptr<function<void(const BhvCurTime &)>>> watchers;
private:
	void markDirty(const BhvCurTime &, vector<shared_ptr<BhvImplBase>> &);
	void updateDirty(const BhvCurTime &);

	bool dirty = false;
	vector<shared_ptr<BhvImplBase>> depends;
	vector<weak_ptr<BhvImplBase>> rdepends;

	template<typename A, typename B> friend class BhvFun;
};

template<typename A, typename B>
class BhvImpl : public BhvImplBase
{
public:
	virtual B get(const BhvCurTime &, const A &) const = 0;
};

template<typename A>
using BhvSource = BhvImpl<monostate, A>;

template<typename A, typename B>
class BhvFun
{
public:
	BhvFun(shared_ptr<BhvImpl<A, B>> impl):
		impl(move(impl)) {}

	template<typename T> BhvFun(shared_ptr<T> impl):
		BhvFun(static_pointer_cast<BhvImpl<A, B>>(impl)) {}

	B get(const A & x) const
	{
		BhvCurTime ctime;
		return impl->get(ctime, x);
	}

	template<typename C> BhvFun<A, C> lens() const;

	const shared_ptr<BhvImpl<A, B>> impl;
};

template<typename A>
class BhvFun<monostate, A>
{
public:
	BhvFun(shared_ptr<BhvSource<A>> impl):
		impl(move(impl)) {}

	template<typename T> BhvFun(shared_ptr<T> impl):
		BhvFun(static_pointer_cast<BhvSource<A>>(impl)) {}

	A get() const
	{
		BhvCurTime ctime;
		return impl->get(ctime, monostate());
	}
	Watched<A> watch(function<void(const A &)>);

	template<typename C> BhvFun<monostate, C> lens() const;

	const shared_ptr<BhvSource<A>> impl;
};

template<typename A>
using Bhv = BhvFun<monostate, A>;

template<typename A>
Watched<A> Bhv<A>::watch(function<void(const A &)> f)
{
	BhvCurTime ctime;
	auto & impl = BhvFun<monostate, A>::impl;
	if (impl->needsUpdate(ctime))
		impl->doUpdate(ctime);

	auto cb = make_shared<function<void(const BhvCurTime &)>>(
			[impl = BhvFun<monostate, A>::impl, f] (const BhvCurTime & ctime) {
				f(impl->get(ctime, monostate()));
			});

	impl->watchers.push_back(cb);
	f(impl->get(ctime, monostate()));
	return Watched<A>(move(cb));
}


template<typename A, typename B>
class BhvLambda : public BhvImpl<A, B>
{
public:
	BhvLambda(function<B(const A &)> f): f(f) {}

	B get(const BhvCurTime &, const A & x) const override
	{ return f(x); }

private:
	function<B(const A &)> f;
};

template<typename A, typename B>
BhvFun<A, B> bfun(function<B(const A &)> f)
{
	return make_shared<BhvLambda<A, B>>(f);
}


template<typename A, typename B, typename C> class BhvComp;
template<typename A, typename B, typename C>
BhvFun<A, C> operator>>(const BhvFun<A, B> & f, const BhvFun<B, C> & g);

template<typename A, typename B, typename C>
class BhvComp : public BhvImpl<A, C>
{
public:
	BhvComp(const BhvFun<A, B> & f, const BhvFun<B, C>):
		f(f), g(g) {}

	C get(const BhvCurTime & ctime, const A & x) const override
	{ return g.impl.get(ctime, f.impl.get(ctime, x)); }

private:
	BhvFun<A, B> f;
	BhvFun<B, C> g;

	friend BhvFun<A, C> operator>> <A, B, C>(const BhvFun<A, B> &, const BhvFun<B, C> &);
};

template<typename B, typename C>
class BhvComp<monostate, B, C> : public BhvSource<C>
{
public:
	BhvComp(const BhvFun<monostate, B> & f, const BhvFun<B, C> & g):
		f(f), g(g) {}

	bool needsUpdate(const BhvCurTime & ctime) const override
	{ return !x || g.impl->get(ctime, f.impl->get(ctime, monostate())) != x.value(); }

	void doUpdate(const BhvCurTime & ctime) override
	{ x = g.impl->get(ctime, f.impl->get(ctime, monostate())); }

	C get(const BhvCurTime & ctime, const monostate & m) const override
	{ return x && !BhvImplBase::isDirty(ctime) ? x.value() : g.impl->get(ctime, f.impl->get(ctime, m)); }

private:
	BhvFun<monostate, B> f;
	BhvFun<B, C> g;
	optional<C> x;

	friend BhvFun<monostate, C> operator>> <monostate, B, C>(const BhvFun<monostate, B> &, const BhvFun<B, C> &);
};

template<typename A, typename B, typename C>
BhvFun<A, C> operator>>(const BhvFun<A, B> & f, const BhvFun<B, C> & g)
{
	auto impl = make_shared<BhvComp<A, B, C>>(f, g);
	impl->dependsOn(f.impl);
	impl->dependsOn(g.impl);
	return impl;
}


template<typename A, typename B>
class BhvLens : public BhvImpl<A, B>
{
public:
	B get(const BhvCurTime &, const A & x) const override
	{ return A::template lens<B>(x); }
};

template<typename A, typename B>
template<typename C>
BhvFun<A, C> BhvFun<A, B>::lens() const
{
	return *this >> BhvFun<B, C>(make_shared<BhvLens<B, C>>());
}

template<typename A>
template<typename C>
BhvFun<monostate, C> BhvFun<monostate, A>::lens() const
{
	return *this >> BhvFun<A, C>(make_shared<BhvLens<A, C>>());
}

}
