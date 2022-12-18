#pragma once

#include <erebos/merge.h>
#include <erebos/storage.h>

namespace erebos
{

class SetViewBase;
template<class T> class SetView;

class SetBase
{
protected:
	struct Priv;

	SetBase();
	SetBase(const vector<Ref> &);
	SetBase(shared_ptr<const Priv>);

	shared_ptr<const Priv> add(const Storage &, const vector<Ref> &) const;

	vector<vector<Ref>> toList() const;

public:
	bool operator==(const SetBase &) const;
	bool operator!=(const SetBase &) const;

	vector<Digest> digests() const;
	vector<Ref> store() const;

protected:
	shared_ptr<const Priv> p;
};

template<class T>
class Set : public SetBase
{
	Set(shared_ptr<const Priv> p): SetBase(p) {};
public:
	Set() = default;
	Set(const vector<Ref> & refs): SetBase(move(refs)) {}
	Set(const Set<T> &) = default;
	Set(Set<T> &&) = default;
	Set & operator=(const Set<T> &) = default;
	Set & operator=(Set<T> &&) = default;

	static Set<T> load(const vector<Ref> & refs) { return Set<T>(move(refs)); }

	Set<T> add(const Storage &, const T &) const;

	template<class F>
	SetView<T> view(F && cmp) const;
};

template<class T>
class SetView
{
public:
	template<class F>
	SetView(F && cmp, const vector<vector<Ref>> & refs);

	size_t size() const { return items.size(); }
	typename vector<T>::const_iterator begin() const { return items.begin(); }
	typename vector<T>::const_iterator end() const { return items.end(); }

private:
	vector<T> items;
};

template<class T>
Set<T> Set<T>::add(const Storage & st, const T & x) const
{
	return Set<T>(SetBase::add(st, storedRefs(Mergeable<T>::components(x))));
}

template<class T>
template<class F>
SetView<T> Set<T>::view(F && cmp) const
{
	return SetView<T>(std::move(cmp), toList());
}

template<class T>
template<class F>
SetView<T>::SetView(F && cmp, const vector<vector<Ref>> & refs)
{
	items.reserve(refs.size());
	for (const auto & crefs : refs) {
		vector<Stored<typename Mergeable<T>::Component>> comps;
		comps.reserve(crefs.size());
		for (const auto & r : crefs)
			comps.push_back(Stored<typename Mergeable<T>::Component>::load(r));

		filterAncestors(comps);
		items.push_back(Mergeable<T>::merge(comps));
	}
	std::sort(items.begin(), items.end(), cmp);
}

}
