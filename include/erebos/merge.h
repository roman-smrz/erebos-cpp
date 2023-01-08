#pragma once

#include <erebos/storage.h>

#include <optional>
#include <vector>

namespace erebos
{

using std::nullopt;
using std::optional;
using std::vector;

template<class T> struct Mergeable
{
};

template<> struct Mergeable<vector<Stored<Object>>>
{
	using Component = Object;

	static vector<Stored<Object>> components(const vector<Stored<Object>> & x) { return x; }
	static vector<Stored<Object>> merge(const vector<Stored<Object>> & x) { return x; }
};

vector<Stored<Object>> findPropertyObjects(const vector<Stored<Object>> & leaves, const string & prop);

template<typename T>
optional<Stored<typename Mergeable<T>::Component>> findPropertyComponent(const vector<Stored<typename Mergeable<T>::Component>> & components, const string & prop)
{
	vector<Stored<Object>> leaves;
	leaves.reserve(components.size());

	for (const auto & c : components)
		leaves.push_back(Stored<Object>::load(c.ref()));

	auto candidates = findPropertyObjects(leaves, prop);
	if (!candidates.empty())
		return Stored<typename Mergeable<T>::Component>::load(candidates[0].ref());
	return nullopt;
}

template<typename T>
optional<Stored<typename Mergeable<T>::Component>> findPropertyComponent(const T & x, const string & prop)
{
	return findPropertyComponent(x.components(), prop);
}

template<typename T>
vector<Stored<typename Mergeable<T>::Component>> findPropertyComponents(const vector<Stored<typename Mergeable<T>::Component>> & components, const string & prop)
{
	vector<Stored<Object>> leaves;
	leaves.reserve(components.size());

	for (const auto & c : components)
		leaves.push_back(Stored<Object>::load(c.ref()));

	auto candidates = findPropertyObjects(leaves, prop);
	vector<Stored<typename Mergeable<T>::Component>> result;
	result.reserve(candidates.size());
	for (const auto & obj : candidates)
		result.push_back(Stored<typename Mergeable<T>::Component>::load(obj.ref()));
	return result;
}

template<typename T>
vector<Stored<typename Mergeable<T>::Component>> findPropertyComponents(const T & x, const string & prop)
{
	return findPropertyComponents(x.components(), prop);
}

}
