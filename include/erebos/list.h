#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <variant>

namespace erebos {

using std::function;
using std::make_shared;
using std::make_unique;
using std::move;
using std::shared_ptr;
using std::unique_ptr;
using std::variant;

template<typename T>
class List
{
public:
	struct Nil { bool operator==(const Nil &) const { return true; } };
	struct Cons {
		T head; List<T> tail;
		bool operator==(const Cons & x) const { return head == x.head && tail == x.tail; }
	};

	List();
	List(const T head, List<T> tail);

	const T & front() const;
	const List & tail() const;

	bool empty() const;

	bool operator==(const List<T> &) const;
	bool operator!=(const List<T> &) const;

	List push_front(T x) const;

private:
	struct Priv;
	shared_ptr<Priv> p;
};

template<typename T>
struct List<T>::Priv
{
	variant<Nil, Cons> value;

	function<void()> eval = {};
	mutable std::once_flag once = {};
};

template<typename T>
List<T>::List():
	p(shared_ptr<Priv>(new Priv { Nil() }))
{
	std::call_once(p->once, [](){});
}

template<typename T>
List<T>::List(T head, List<T> tail):
	p(shared_ptr<Priv>(new Priv {
		Cons { move(head), move(tail) }
	}))
{
	std::call_once(p->once, [](){});
}

template<typename T>
const T & List<T>::front() const
{
	std::call_once(p->once, p->eval);
	return std::get<Cons>(p->value).head;
}

template<typename T>
const List<T> & List<T>::tail() const
{
	std::call_once(p->once, p->eval);
	return std::get<Cons>(p->value).tail;
}

template<typename T>
bool List<T>::empty() const
{
	std::call_once(p->once, p->eval);
	return std::holds_alternative<Nil>(p->value);
}

template<typename T>
bool List<T>::operator==(const List<T> & other) const
{
	if (p == other.p)
		return true;

	std::call_once(p->once, p->eval);
	std::call_once(other.p->once, other.p->eval);
	return p->value == other.p->value;

}

template<typename T>
bool List<T>::operator!=(const List<T> & other) const
{
	return !(*this == other);
}

template<typename T>
List<T> List<T>::push_front(T x) const
{
	return List<T>(move(x), *this);
}

}
