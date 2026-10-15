package rds

import (
	"maps"
	"slices"
	"strings"
)

func cloneGlobalCluster(v GlobalCluster) GlobalCluster {
	v.Tags = maps.Clone(v.Tags)
	return v
}

func (r memoryReader) GlobalCluster(k GlobalKey) (GlobalCluster, error) {
	if err := r.tx.Check(false); err != nil {
		return GlobalCluster{}, err
	}
	v, ok := r.s.globalClusters[k]
	if !ok {
		return GlobalCluster{}, ErrNotFound
	}
	return cloneGlobalCluster(v), nil
}

func (r memoryReader) GlobalClusters(scope GlobalScope) ([]GlobalCluster, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []GlobalCluster{}
	for k, v := range r.s.globalClusters {
		if k.GlobalScope == scope {
			out = append(out, cloneGlobalCluster(v))
		}
	}
	slices.SortFunc(out, func(a, b GlobalCluster) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	return out, nil
}

func (w memoryWriter) PutGlobalCluster(v GlobalCluster) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.globalClusters[v.Key] = cloneGlobalCluster(v)
	return nil
}

func (w memoryWriter) DeleteGlobalCluster(k GlobalKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.globalClusters, k)
	return nil
}
