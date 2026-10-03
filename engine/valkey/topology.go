package valkey

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func infoField(info, name string) string {
	for _, line := range strings.Split(info, "\r\n") {
		if v, ok := strings.CutPrefix(line, name+":"); ok {
			return v
		}
	}
	return ""
}
func (d *Docker) topology(ctx context.Context, m manifest) error {
	if !m.ClusterMode {
		for i := 1; i < len(m.Nodes); i++ {
			c := d.clientFor(m, i)
			err := c.SlaveOf(ctx, "127.0.0.1", strconv.Itoa(int(m.Nodes[0].Port))).Err()
			c.Close()
			if err != nil {
				return err
			}
		}
		return d.waitReplication(ctx, m)
	}
	root := d.clientFor(m, 0)
	defer root.Close()
	info, err := root.ClusterInfo(ctx).Result()
	if err != nil {
		return err
	}
	if infoField(info, "cluster_slots_assigned") != "16384" {
		ids := make([]string, len(m.Nodes))
		for i, n := range m.Nodes {
			c := d.clientFor(m, i)
			ids[i], err = c.ClusterMyID(ctx).Result()
			c.Close()
			if err != nil {
				return err
			}
			if i > 0 {
				if err = root.Do(ctx, "CLUSTER", "MEET", "127.0.0.1", n.Port, n.BusPort).Err(); err != nil {
					return err
				}
			}
		}
		if err = waitCondition(ctx, func() (bool, error) {
			for i := range m.Nodes {
				c := d.clientFor(m, i)
				v, e := c.ClusterNodes(ctx).Result()
				c.Close()
				if e != nil {
					return false, e
				}
				known := make(map[string]bool, len(ids))
				for _, line := range strings.Split(v, "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 8 && !strings.Contains(fields[2], "handshake") && fields[7] == "connected" {
						known[fields[0]] = true
					}
				}
				for _, id := range ids {
					if !known[id] {
						return false, nil
					}
				}
			}
			return true, nil
		}); err != nil {
			return err
		}
		for shard := int32(0); shard < m.Shards; shard++ {
			primary := int(shard * (m.Replicas + 1))
			c := d.clientFor(m, primary)
			start := int64(shard) * 16384 / int64(m.Shards)
			end := int64(shard+1)*16384/int64(m.Shards) - 1
			// Inspect the local slots before assigning so recovery after partial
			// provisioning does not discard data or reset an established cluster.
			nodes, e := c.ClusterNodes(ctx).Result()
			if e == nil {
				var owned [16384]bool
				for _, line := range strings.Split(nodes, "\n") {
					fields := strings.Fields(line)
					if len(fields) < 9 || !strings.Contains(fields[2], "myself") {
						continue
					}
					for _, part := range fields[8:] {
						low, high, _ := strings.Cut(part, "-")
						first, parseErr := strconv.Atoi(low)
						last := first
						if high != "" {
							last, parseErr = strconv.Atoi(high)
						}
						if parseErr != nil || first < int(start) || last > int(end) || last < first {
							e = errors.New("native slot ownership conflicts with retained shard range")
							break
						}
						for slot := first; slot <= last; slot++ {
							owned[slot] = true
						}
					}
				}
				// Loading a restored RDB claims slots containing keys before
				// cluster formation. Complete that same shard's empty slots,
				// rather than mistaking one claimed slot for its entire range.
				for first := int(start); e == nil && first <= int(end); {
					if owned[first] {
						first++
						continue
					}
					last := first
					for last < int(end) && !owned[last+1] {
						last++
					}
					e = c.Do(ctx, "CLUSTER", "ADDSLOTSRANGE", first, last).Err()
					first = last + 1
				}
			}
			c.Close()
			if e != nil {
				return e
			}
			for replica := int32(1); replica <= m.Replicas; replica++ {
				c = d.clientFor(m, primary+int(replica))
				e = c.ClusterReplicate(ctx, ids[primary]).Err()
				c.Close()
				if e != nil {
					return e
				}
			}
		}
	}
	if err = waitCondition(ctx, func() (bool, error) {
		for i := range m.Nodes {
			c := d.clientFor(m, i)
			v, e := c.ClusterInfo(ctx).Result()
			c.Close()
			if e != nil {
				return false, e
			}
			if infoField(v, "cluster_state") != "ok" || infoField(v, "cluster_slots_assigned") != "16384" {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		return err
	}
	return d.waitReplication(ctx, m)
}
func (d *Docker) waitReplication(ctx context.Context, m manifest) error {
	return waitCondition(ctx, func() (bool, error) {
		masters := 0
		for i := range m.Nodes {
			c := d.clientFor(m, i)
			info, err := c.Info(ctx, "replication").Result()
			c.Close()
			if err != nil {
				return false, err
			}
			role := infoField(info, "role")
			if role == "master" {
				masters++
			} else if role == "slave" {
				if infoField(info, "master_link_status") != "up" || infoField(info, "master_sync_in_progress") != "0" {
					return false, nil
				}
			} else {
				return false, fmt.Errorf("unexpected native Valkey role %q", role)
			}
		}
		if masters != int(m.Shards) {
			return false, nil
		}
		return true, nil
	})
}
func (d *Docker) currentDeployment(ctx context.Context, m manifest) (Deployment, error) {
	out := deployment(m)
	for shard := int32(0); shard < m.Shards; shard++ {
		found := false
		replica := int32(1)
		for i := int(shard * (m.Replicas + 1)); i < int((shard+1)*(m.Replicas+1)); i++ {
			c := d.clientFor(m, i)
			v, err := c.Info(ctx, "replication").Result()
			c.Close()
			if err != nil {
				return Deployment{}, err
			}
			if infoField(v, "role") == "master" {
				if found {
					return Deployment{}, errors.New("multiple native primaries in one shard")
				}
				found = true
				out.Nodes[i].Replica = 0
				if shard == 0 {
					out.Endpoint = out.Nodes[i].Endpoint
				}
			} else {
				out.Nodes[i].Replica = replica
				replica++
			}
		}
		if !found {
			return Deployment{}, errors.New("native shard has no available primary")
		}
	}
	return out, nil
}
func (d *Docker) Statistics(ctx context.Context, spec Specification) (Statistics, error) {
	if err := d.lock(ctx); err != nil {
		return Statistics{}, err
	}
	defer d.unlock()
	s, err := d.inspect(ctx, spec.ID)
	if err != nil {
		return Statistics{}, err
	}
	if err = d.checkContainer(s, spec.ID); err != nil {
		return Statistics{}, err
	}
	m, err := d.readManifest(ctx, s, spec)
	if err != nil {
		return Statistics{}, err
	}
	var out Statistics
	for i := range m.Nodes {
		c := d.clientFor(m, i)
		info, e := c.Info(ctx, "clients", "memory", "stats").Result()
		c.Close()
		if e != nil {
			return Statistics{}, e
		}
		for name, target := range map[string]*int64{"connected_clients": &out.Connections, "used_memory": &out.UsedMemory, "keyspace_hits": &out.KeyspaceHits, "keyspace_misses": &out.KeyspaceMisses, "total_commands_processed": &out.Commands} {
			n, e := strconv.ParseInt(infoField(info, name), 10, 64)
			if e != nil {
				return Statistics{}, fmt.Errorf("invalid measured native statistic %s", name)
			}
			*target += n
		}
	}
	return out, nil
}
