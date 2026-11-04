package network

import (
	"net/netip"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestPodRouteEqualityIncludesEveryAuthorityWitness(t *testing.T) {
	route := PodRoute{Prefix: netip.MustParsePrefix("10.42.1.0/24"), ClusterID: "cluster", OwnerToken: "owner", NodeName: "node", NodeUID: "uid", ResourceVersion: "123", ContainerID: "container", NetworkID: "docker-network", WorkerIP: netip.MustParseAddr("172.20.0.2")}
	if !(Policy{PodRoutes: []PodRoute{route}}).Equal(Policy{PodRoutes: []PodRoute{route}}) {
		t.Fatal("equal pod authority compares unequal")
	}
	for i := range reflect.TypeOf(route).NumField() {
		changed := route
		field := reflect.ValueOf(&changed).Elem().Field(i)
		field.Set(reflect.Zero(field.Type()))
		if (Policy{PodRoutes: []PodRoute{route}}).Equal(Policy{PodRoutes: []PodRoute{changed}}) {
			t.Errorf("pod authority ignores %s", reflect.TypeOf(route).Field(i).Name)
		}
	}
}

func TestPodAdmissionDoesNotBecomePublicOrBypassAWSBoundary(t *testing.T) {
	spec := Specification{Pool: netip.MustParsePrefix("10.91.0.0/16"), Gateway: netip.MustParseAddr("10.91.0.1"), Address: netip.MustParseAddr("10.91.1.10"), MAC: "02:cc:00:00:00:10"}
	policy := Policy{Subnet: netip.MustParsePrefix("10.91.1.0/24"), PodRoutes: []PodRoute{{Prefix: netip.MustParsePrefix("10.42.1.0/24")}}}
	rules, err := Rules("stackd_elbv2_1234", spec, policy, "veth-test", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"chain public_from {\nip daddr 10.42.1.0/24 return\ncounter drop",
		"chain public_to {\nip saddr 10.42.1.0/24 ct state established,related ct direction reply return\ncounter drop",
		"ip daddr != 10.91.0.0/16 jump public_from\njump acl_from\nct state invalid counter drop",
		"ether saddr != 02:cc:00:00:00:10 counter drop",
		"ip saddr 10.91.1.10 ip daddr != 169.254.0.0/16 accept",
	} {
		if !strings.Contains(rules, fragment) {
			t.Errorf("missing pod route/AWS enforcement %q in %s", fragment, rules)
		}
	}
	if policy.PublicEgress || len(policy.PrivateRoutes) != 0 {
		t.Fatal("pod route was represented as public egress or fake VPC-local authority")
	}
}

// Exercise the production parser against independently synthetic iproute2 JSON,
// including numeric RTN_* types and the separately encoded rule dstlen. Only
// parser functions are extracted; all native queries/mutations are replaced by
// in-memory receipts, so this does not require Docker or network privileges.
func TestPodRouteKernelObservationContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for native route parser regression")
	}
	const program = `
import ast,copy,ipaddress,subprocess,sys,types
tree=ast.parse(sys.stdin.read())
names={'table_routes','destination','route_type','rule_destination','inspect_routes','retire'}
functions=[node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name in names]
assert len(functions)==len(names)
commands=[]
observed_routes=[];observed_rules=[]
def native(*args):
    return observed_routes if 'route' in args else observed_rules
def run(*args):
    commands.append(args)
subprocess=types.SimpleNamespace(run=lambda *args,**kwargs:types.SimpleNamespace(returncode=0,stdout='',stderr=''),PIPE=-1)
exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),'pod_routes_native.go','exec'))
p={'Source':'10.61.0.10','Table':20001,'Routes':[{'Prefix':'10.63.7.0/24','WorkerIP':'172.29.0.8','Device':'br-fixture'}]}
default={'type':'7','dst':'default','table':'20001','protocol':'242','flags':[]}
route={'dst':'10.63.7.0/24','table':'20001','protocol':'242','gateway':'172.29.0.8','dev':'br-fixture','flags':['onlink']}
rule={'priority':11000,'src':'10.61.0.10','dst':'10.63.7.0','dstlen':24,'table':'20001','protocol':'242'}
observed_routes=[copy.deepcopy(default),copy.deepcopy(route)];observed_rules=[copy.deepcopy(rule)]
assert inspect_routes(p,True)[1]==['10.63.7.0/24']
for value in ('unicast','1',1):
    observed_routes[1]['type']=value
    inspect_routes(p,True)
observed_routes[0]['type']='unreachable'
observed_rules[0].pop('dstlen');observed_rules[0]['dst']='10.63.7.0/24'
inspect_routes(p,True)
mutations=[
    lambda rows,rules:rows[0].update(type='6'),
    lambda rows,rules:rows[0].update(gateway='172.29.0.9'),
    lambda rows,rules:rows[0].update(dev='br-foreign'),
    lambda rows,rules:rows[1].update(protocol='99'),
    lambda rows,rules:rows[1].update(metric=10),
    lambda rows,rules:rows[1].update(gateway='172.29.0.9'),
    lambda rows,rules:rows.pop(),
    lambda rows,rules:rules[0].update(dstlen=25),
    lambda rows,rules:rules[0].update(srclen=24),
    lambda rows,rules:rules[0].update(fwmark='1'),
]
for mutate in mutations:
    observed_routes=[copy.deepcopy(default),copy.deepcopy(route)];observed_rules=[copy.deepcopy(rule)]
    mutate(observed_routes,observed_rules)
    try: inspect_routes(p,True)
    except (RuntimeError,ValueError): pass
    else: raise AssertionError('foreign or incomplete kernel tuple accepted')
# Interrupted cleanup may retain just the numeric unreachable default and
# selector after Docker removed the worker bridge. Delete exact witnessed rows.
observed_routes=[copy.deepcopy(default)];observed_rules=[copy.deepcopy(rule)]
retire(p)
assert ('ip','-4','rule','del','priority','11000','from','10.61.0.10/32','to','10.63.7.0/24','lookup','20001','protocol','242') in commands
assert ('ip','-4','route','del','table','20001','unreachable','default','proto','242') in commands
`
	command := exec.Command(python, "-c", program)
	command.Stdin = strings.NewReader(nativePodRoutesPython)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native kernel observation contract: %v\n%s", err, output)
	}
}

func TestPodRouteOptionalDockerRawGuard(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for native grant parser regression")
	}
	const program = `
import ast,json,sys
tree=ast.parse(sys.stdin.read())
names={'grant_chains','grant_rows'}
functions=[node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name in names]
assert len(functions)==len(names)
table='stackd_pods_fixture'
p={'Token':'incarnation','Source':'10.61.0.10','Bridge':'br-alb','Routes':[{'Prefix':'10.63.7.0/24','Device':'br-worker','Gateway':'172.29.0.1'}]}
mark=table+':'+p['Token']
def rule(chain,handle,comment=mark):
    return {'rule':{'family':'ip','table':'filter' if chain=='DOCKER-USER' else 'raw','chain':chain,'handle':handle,'comment':comment}}
filter_rows=[rule('DOCKER-USER',1),rule('DOCKER-USER',2)]
raw_rows=[rule('PREROUTING',3),rule('PREROUTING',4)]
mode='absent-table';failure=None
filter_query=('nft','-j','list','chain','ip','filter','DOCKER-USER')
tables_query=('nft','-j','list','tables')
raw_query=('nft','-j','list','table','ip','raw')
def native(*args):
    if args==failure: raise RuntimeError('injected nft query failure')
    if args==filter_query: return {'nftables':filter_rows}
    if args==tables_query: return {'nftables':[] if mode=='absent-table' else [{'table':{'family':'ip','name':'raw'}}]}
    if args==raw_query:
        assert mode!='absent-table','absent raw table was queried'
        chain='PREROUTING' if mode=='present' else 'OUTPUT'
        return {'nftables':[{'chain':{'family':'ip','table':'raw','name':chain}},rule('OUTPUT',5,table+':foreign-output')]+(raw_rows if mode=='present' else [])}
    raise AssertionError('unexpected native query: '+repr(args))
exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),'pod_routes_native.go','exec'))
for mode in ('absent-table','absent-chain','present'):
    commands=grant_rows(p)
    raw_inserts=[c for c in commands if c.startswith('insert rule ip raw PREROUTING')]
    assert len(raw_inserts)==(2 if mode=='present' else 0)
    assert sum(c.startswith('insert rule ip filter DOCKER-USER') for c in commands)==2
    assert all("create" not in c and "add table" not in c and "add chain" not in c for c in commands)
    deletes=grant_rows(p,True,True)
    assert len(deletes)==(4 if mode=='present' else 2)
    assert all('OUTPUT' not in c for c in commands+deletes)
    # Missing required forwarding/owned raw grants are not mistaken for an
    # optional absent raw guard during stable-path revalidation.
    saved=filter_rows;filter_rows=[]
    try: grant_rows(p,True,True)
    except RuntimeError: pass
    else: raise AssertionError('missing forwarding grants accepted')
    filter_rows=saved
mode='present'
saved=raw_rows;raw_rows=[]
try: grant_rows(p,True,True)
except RuntimeError: pass
else: raise AssertionError('new raw guard admitted without exact grants')
raw_rows=[rule('PREROUTING',3,table+':foreign')]
try: grant_rows(p,True)
except RuntimeError: pass
else: raise AssertionError('foreign raw grant incarnation accepted')
raw_rows=saved
# Permission failures, table/chain-query races and required-chain absence must
# propagate unchanged. Only a successful inventory proving absence is optional.
for failure in (filter_query,tables_query,raw_query):
    for remove in (False,True):
        try: grant_rows(p,remove)
        except RuntimeError as error: assert str(error)=='injected nft query failure'
        else: raise AssertionError('nft failure was mistaken for absent raw guard')
`
	command := exec.Command(python, "-c", program)
	command.Stdin = strings.NewReader(nativePodRoutesPython)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native optional Docker raw guard: %v\n%s", err, output)
	}
}
