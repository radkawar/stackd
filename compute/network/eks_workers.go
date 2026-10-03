package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// ReconcileEKSWorkerPeers admits overlay UDP and kubelet HTTPS between exact-owned
// Kubernetes containers and real EC2 TAPs. The existing netdev anti-spoof and
// bridge-family EC2 public-route, NACL and security-group policies remain in the
// packet path; no ACCEPT is installed in those AWS enforcement chains.
func (b *Bridges) ReconcileEKSWorkerPeers(ctx context.Context, clusterID, groupID, ownerToken string, port int, containerIDs []string, workerAddresses map[string]string) error {
	if clusterID == "" || groupID == "" || len(ownerToken) != 64 || port < 1 || port > 65535 {
		return errors.New("invalid EKS overlay ownership")
	}
	for arn, address := range workerAddresses {
		ip, e := netip.ParseAddr(address)
		if e != nil || !ip.Is4() || !strings.Contains(arn, ":instance/i-") {
			return errors.New("EKS overlay requires current EC2 instance ARN and IPv4 address")
		}
	}
	data, e := json.Marshal(struct {
		ClusterID, GroupID, OwnerToken string
		Port                           int
		ContainerIDs                   []string
		Workers                        map[string]string
	}{clusterID, groupID, ownerToken, port, containerIDs, workerAddresses})
	if e != nil {
		return e
	}
	sum := sha256.Sum256([]byte(clusterID + "/" + groupID))
	owner := "stackd_eks_workers_" + hex.EncodeToString(sum[:12])
	_, e = b.runNativeOperation(ctx, owner, []string{"EKS_WORKER_PEERS=" + string(data), "OWNER=" + owner}, false)
	return e
}
func (b *Bridges) DeleteEKSWorkerPeers(ctx context.Context, clusterID, groupID, ownerToken string) error {
	return b.ReconcileEKSWorkerPeers(ctx, clusterID, groupID, ownerToken, 1, nil, nil)
}

// This runs under the same daemon-host flock and Engine-identity handshake as
// ordinary EC2 network admission. Comments are the native cleanup witness, not
// a parallel resource ledger. All native tuple verification precedes mutation.
const eksWorkerPeersScript = `
python3 - <<'PY'
import hashlib,http.client,ipaddress,json,os,socket,subprocess
class Engine(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.connect('/var/run/docker.sock')
def request(path):
    c=Engine('localhost');c.request('GET','/v1.41'+path);r=c.getresponse();body=r.read();c.close()
    if r.status!=200: raise RuntimeError('Docker ownership query failed: '+str(r.status))
    return json.loads(body)
def run(*args):
    return subprocess.check_output(args,text=True)
def native(*args):
    return json.loads(run(*args))
p=json.loads(os.environ['EKS_WORKER_PEERS']);owner=os.environ['OWNER']
if request('/info')['ID']!=os.environ['NATIVE_ENGINE_ID']: raise RuntimeError('Docker engine identity changed')
witness=owner+':'+hashlib.sha256(p['OwnerToken'].encode()).hexdigest()[:24]
containers=[]
for cid in p['ContainerIDs'] or []:
    if len(cid)!=64 or any(c not in '0123456789abcdef' for c in cid): raise RuntimeError('Exact Docker ID required')
    c=request('/containers/'+cid+'/json');labels=c['Config']['Labels']
    if labels.get('stackd.eks.id')!=p['ClusterID'] or labels.get('stackd.eks.owner')!=p['OwnerToken']: raise RuntimeError('Unowned Kubernetes container')
    for name,link in c['NetworkSettings']['Networks'].items():
        net=request('/networks/'+link['NetworkID'])
        if net['Labels'].get('stackd.eks.id')!=p['ClusterID'] or net['Labels'].get('stackd.eks.owner')!=p['OwnerToken']: raise RuntimeError('Unowned Kubernetes network')
        address=str(ipaddress.IPv4Address(link['IPAddress']));containers.append(address)
workers=[]
for arn,address in (p['Workers'] or {}).items():
    address=str(ipaddress.IPv4Address(address));digest=hashlib.sha256(arn.encode()).hexdigest()[:24];tap='st'+digest[:12]
    links=native('ip','-j','link','show','dev',tap)
    if len(links)!=1 or links[0].get('ifalias')!='stackd.ec2:'+arn: raise RuntimeError('Worker TAP incarnation mismatch')
    table=native('nft','-j','list','table','netdev','stackd_ec2_'+digest)
    source=False;address_found=False
    for row in table['nftables']:
        chain=row.get('chain',{})
        if chain.get('name')=='source' and chain.get('dev')==tap: source=True
        rule=row.get('rule',{})
        if rule.get('chain')=='source':
            for expression in rule.get('expr',[]):
                match=expression.get('match',{})
                if match.get('left')=={'payload':{'protocol':'ip','field':'saddr'}} and match.get('op')=='==' and match.get('right')==address: address_found=True
    if not source or not address_found: raise RuntimeError('Worker address does not match authoritative EC2 packet policy')
    # Existing AWS enforcement must be present, not merely an unguarded TAP.
    native('nft','-j','list','table','bridge','stackd_ec2_'+digest)
    workers.append(address)
commands=[]
for family,table,chain in [('ip','filter','DOCKER-USER'),('ip','raw','PREROUTING')]:
    rows=native('nft','-j','list','chain',family,table,chain)['nftables']
    for row in rows:
        rule=row.get('rule',{});comment=rule.get('comment','')
        if comment.startswith(owner+':'):
            if comment!=witness: raise RuntimeError('Overlay grant belongs to another native controller incarnation')
            commands.append('delete rule %s %s %s handle %s'%(family,table,chain,rule['handle']))
for container in sorted(set(containers)):
    for worker in sorted(set(workers)):
        for src,dst in [(container,worker),(worker,container)]:
            # Docker isolation is separate from EC2 bridge-family enforcement.
            # Only the negotiated overlay port between these exact peers passes.
            commands.append('insert rule ip filter DOCKER-USER ip saddr %s ip daddr %s udp dport %d counter accept comment "%s"'%(src,dst,p['Port'],witness))
            commands.append('insert rule ip raw PREROUTING ip saddr %s ip daddr %s udp dport %d counter accept comment "%s"'%(src,dst,p['Port'],witness))
        # Direct kubelet clients (including metrics-server) use HTTPS. Exec/logs
        # use K3s agent tunnels instead. Replies must belong to an established
        # request, not a guest-originated connection.
        for table,chain in [('filter','DOCKER-USER'),('raw','PREROUTING')]:
            commands.append('insert rule ip %s %s ip saddr %s ip daddr %s tcp dport 10250 counter accept comment "%s"'%(table,chain,container,worker,witness))
            commands.append('insert rule ip %s %s ip saddr %s ip daddr %s tcp sport 10250 ct state established ct direction reply counter accept comment "%s"'%(table,chain,worker,container,witness))
if commands: subprocess.run(['nft','-f','-'],input='\n'.join(commands)+'\n',text=True,check=True)
PY
`
