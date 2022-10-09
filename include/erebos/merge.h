#pragma once

#include <erebos/storage.h>

namespace erebos
{

template<class T> struct Mergeable
{
};

template<> struct Mergeable<vector<Stored<Object>>>
{
	using Component = Object;

	static vector<Stored<Object>> components(const vector<Stored<Object>> & x) { return x; }
	static vector<Stored<Object>> merge(const vector<Stored<Object>> & x) { return x; }
};

}
