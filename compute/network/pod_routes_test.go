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
