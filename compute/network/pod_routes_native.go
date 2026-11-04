package network

// Pod routing uses the same daemon identity handshake and kernel flock as bridge
// and public-address admission. A retained nft witness owns each policy-routing
// table/rule incarnation; there is no controller-side native routing registry.
// Quarantine precedes retirement and remains across every partial failure. The
// ordinary bridge policy is replaced before the new packet path is enabled.
const nativePodRoutesPrepareScript = "\nPOD_ROUTE_PHASE=prepare python3 - <<'STACKD_POD_ROUTES'\n" + nativePodRoutesPython + "\nSTACKD_POD_ROUTES\n"
const nativePodRoutesFinishScript = "\nPOD_ROUTE_PHASE=finish python3 - <<'STACKD_POD_ROUTES'\n" + nativePodRoutesPython + "\nSTACKD_POD_ROUTES\n"

const nativePodRoutesPython = `
import hashlib,http.client,ipaddress,json,os,re,secrets,socket,struct,subprocess
owner=os.environ['OWNER']
requested=json.loads(os.environ.get('POD_ROUTES','null')) or []
if not owner.startswith('stackd_elbv2_'):
    if requested: raise RuntimeError('Pod routing requires an ALB attachment')
else:
    class Engine(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.connect('/var/run/docker.sock')
    def engine(path,body=None,raw=False):
        c=Engine('localhost');c.request('GET' if body is None else 'POST','/v1.41'+path,None if body is None else json.dumps(body),{'Content-Type':'application/json'})
        r=c.getresponse();data=r.read();status=r.status;c.close()
        if status not in (200,201): raise RuntimeError('Docker pod-route ownership query failed: '+str(status))
        return data if raw else json.loads(data)
    def table_routes(number):
        return [row for row in native('ip','-N','-j','-4','route','show','table','all') if str(row.get('table','254'))==str(number)]
    def destination(value):
        return value if value=='default' else str(ipaddress.IPv4Network(value if '/' in value else value+'/32'))
    def route_type(row):
        # ip -N emits Linux RTN_* numbers, including RTN_UNREACHABLE=7.
        value=str(row.get('type','1'))
        return {'1':'unicast','7':'unreachable'}.get(value,value)
    def rule_destination(row):
        value=row.get('dst','default');bits=row.get('dstlen')
        if bits is None: return destination(value)
        if not isinstance(bits,int) or isinstance(bits,bool) or not 0<=bits<=32 or value=='default': raise RuntimeError('Invalid pod rule destination prefix length')
        network=ipaddress.IPv4Network(value if '/' in value else value+'/'+str(bits))
        if network.prefixlen!=bits: raise RuntimeError('Pod rule destination prefix lengths differ')
        return str(network)
    def run(*args): return subprocess.check_output(args,text=True)
    def native(*args): return json.loads(run(*args))
    def nft(commands):
        if commands: subprocess.run(['nft','-f','-'],input='\n'.join(commands)+'\n',text=True,check=True)
    def exact_id(value):
        if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value): raise RuntimeError('Exact Docker identity required')
    def address(value): return str(ipaddress.IPv4Address(value))
    def prefix(value):
        p=ipaddress.IPv4Network(value)
        if not p.is_private or p.prefixlen==0 or p.network_address.is_loopback or p.network_address.is_link_local or p.network_address.is_multicast: raise RuntimeError('Pod prefix must be private unicast IPv4')
        return p
    table='stackd_pods_'+owner[len('stackd_elbv2_'):]
    controller=os.environ['CONTROLLER']
    if engine('/info')['ID']!=os.environ['NATIVE_ENGINE_ID']: raise RuntimeError('Docker engine identity changed')
    tables=native('nft','-j','list','tables')['nftables']
    exists=any(row.get('table',{}).get('family')=='ip' and row['table'].get('name')==table for row in tables)
    def load():
        rows=native('nft','-j','list','table','ip',table)['nftables']
        metadata=[row['table'] for row in rows if 'table' in row]
        chains={row['chain']['name']:row['chain'] for row in rows if 'chain' in row}
        if len(metadata)!=1 or metadata[0].get('comment')!='stackd:'+owner or chains.get('controller',{}).get('comment')!=controller: raise RuntimeError('Pod routing belongs to another native controller')
        chunks=[chains[name].get('comment','') for name in sorted(chains) if name.startswith('identity_')]
        data=json.loads(bytes.fromhex(''.join(chunks)))
        if chains.get('incarnation',{}).get('comment')!=data['Token']: raise RuntimeError('Pod-route incarnation witness mismatch')
        data['Active']='source_nat' in chains and 'quarantine' not in chains
        return data
    def render(p,active=False):
        p=dict(p,Active=active)
        commands=['destroy table ip '+table,'table ip '+table+' {','comment '+json.dumps('stackd:'+owner), 'chain controller { comment '+json.dumps(controller)+'; }','chain incarnation { comment '+json.dumps(p['Token'])+'; }']
        data=json.dumps(p,sort_keys=True,separators=(',',':')).encode().hex()
        for i in range(0,len(data),64): commands.append('chain identity_%06d { comment "%s"; }'%(i//64,data[i:i+64]))
        if not active:
            commands.append('chain quarantine { type filter hook forward priority -10; policy accept;')
            for route in p.get('Blocked',p['Routes']):
                commands.append('ip saddr %s ip daddr %s drop;'%(p['Source'],route['Prefix']))
                commands.append('ip saddr %s ip daddr %s ct direction reply ct original ip saddr %s ct original ip daddr %s drop;'%(route['Prefix'],p['Source'],p['Source'],route['Prefix']))
            commands.append('}')
        else:
            commands.append('chain source_nat { type nat hook postrouting priority 98; policy accept;')
            for route in p['Routes']:
                commands.append('iifname %s oifname %s ip saddr %s ip daddr %s snat to %s;'%(json.dumps(p['Bridge']),json.dumps(route['Device']),p['Source'],route['Prefix'],route['Gateway']))
            commands.append('}')
        commands.append('}')
        return commands
    def grant_chains():
        # DOCKER-USER is required forwarding admission. Older Docker versions
        # have no raw direct-routing guard: prove that absence from successful
        # nft inventory reads, never by swallowing a failed chain query.
        chains=[('filter','DOCKER-USER',native('nft','-j','list','chain','ip','filter','DOCKER-USER')['nftables'])]
        tables=native('nft','-j','list','tables')['nftables']
        if any(row.get('table',{}).get('family')=='ip' and row['table'].get('name')=='raw' for row in tables):
            rows=native('nft','-j','list','table','ip','raw')['nftables']
            if any(row.get('chain',{}).get('family')=='ip' and row['chain'].get('table')=='raw' and row['chain'].get('name')=='PREROUTING' for row in rows):
                chains.append(('raw','PREROUTING',[row for row in rows if row.get('rule',{}).get('chain')=='PREROUTING']))
        return chains
    def grant_rows(p,remove=False,complete=False):
        commands=[];comment=table+':'+p['Token'];chains=grant_chains()
        for kind,chain,rows in chains:
            owned=0
            for row in rows:
                rule=row.get('rule',{});mark=rule.get('comment','')
                if mark.startswith(table+':'):
                    if mark!=comment: raise RuntimeError('Docker pod grant belongs to another incarnation')
                    owned+=1
                    commands.append('delete rule ip %s %s handle %s'%(kind,chain,rule['handle']))
            if complete and owned!=2*len(p['Routes']): raise RuntimeError('Pod forwarding grants are incomplete')
        if not remove:
            for route in p['Routes']:
                src=p['Source'];dst=route['Prefix'];bridge=json.dumps(p['Bridge']);dev=json.dumps(route['Device']);gateway=route['Gateway'];mark=json.dumps(comment)
                commands.append('insert rule ip filter DOCKER-USER iifname %s oifname %s ip saddr %s ip daddr %s ct direction original counter accept comment %s'%(bridge,dev,src,dst,mark))
                commands.append('insert rule ip filter DOCKER-USER iifname %s oifname %s ip saddr %s ip daddr %s ct state established,related ct direction reply ct original ip saddr %s ct original ip daddr %s counter accept comment %s'%(dev,bridge,dst,src,src,dst,mark))
                # Raw executes before conntrack and reverse SNAT. This exact
                # gateway tuple only lifts Docker's direct-routing raw guard;
                # the filter reply grant still requires the original ALB flow.
                if any(kind=='raw' for kind,chain,rows in chains):
                    commands.append('insert rule ip raw PREROUTING iifname %s ip saddr %s ip daddr %s counter accept comment %s'%(bridge,src,dst,mark))
                    commands.append('insert rule ip raw PREROUTING iifname %s ip saddr %s ip daddr %s counter accept comment %s'%(dev,dst,gateway,mark))
        return commands
    def inspect_routes(p,complete=False):
        # A stable path is reusable only while every kernel tuple still matches
        # its durable witness. Never repair or adopt foreign table additions.
        rows=table_routes(p['Table'])
        expected={r['Prefix']:(r['WorkerIP'],r['Device']) for r in p['Routes']}
        seen=[]
        for row in rows:
            if set(row)-{'table','type','dst','gateway','dev','protocol','flags','scope'} or str(row.get('protocol'))!='242' or str(row.get('scope','0')) not in ('0','global'): raise RuntimeError('Unowned route in pod table')
            dst=destination(row.get('dst','default'));seen.append(dst)
            if dst=='default':
                if route_type(row)!='unreachable' or row.get('flags') or row.get('gateway') or row.get('dev'): raise RuntimeError('Unowned default in pod table')
            elif dst not in expected or (row.get('gateway'),row.get('dev'))!=expected[dst] or route_type(row)!='unicast' or set(row.get('flags',[]))!={'onlink'}: raise RuntimeError('Pod route next-hop witness mismatch')
        if complete and (len(seen)!=len(expected)+1 or set(seen)!=set(expected)|{'default'}): raise RuntimeError('Pod routing table is incomplete')
        rules=native('ip','-N','-j','-4','rule','show');owned=[]
        for row in rules:
            if str(row.get('table'))!=str(p['Table']): continue
            dst=rule_destination(row)
            if set(row)-{'protocol','priority','src','srclen','dst','dstlen','table','flags'} or row.get('flags') or row.get('srclen',32)!=32 or str(row.get('protocol'))!='242' or row.get('priority')!=11000 or row.get('src') not in (p['Source'],p['Source']+'/32') or dst not in expected: raise RuntimeError('Unowned rule in pod table')
            owned.append(dst)
        if complete and (len(owned)!=len(expected) or set(owned)!=set(expected)): raise RuntimeError('Pod routing selectors are incomplete')
        return rows,owned
    def retire(p):
        rows,owned=inspect_routes(p)
        for route in p.get('Blocked',p['Routes']):
            result=subprocess.run(['conntrack','-D','-f','ipv4','--orig-src',p['Source'],'--orig-dst',route['Prefix']],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if result.returncode and '0 flow entries have been deleted' not in result.stdout+result.stderr: raise RuntimeError(result.stderr)
        for dst in owned:
            run('ip','-4','rule','del','priority','11000','from',p['Source']+'/32','to',dst,'lookup',str(p['Table']),'protocol','242')
        for row in rows:
            args=['ip','-4','route','del','table',str(p['Table'])]
            if route_type(row)=='unreachable': args+=['unreachable','default']
            else: args += [row['dst'],'via',row['gateway'],'dev',row['dev']]
            run(*(args+['proto','242']))
    def validate():
        source=address(os.environ['PRIVATE']);bridge=os.environ['BRIDGE'];pool=ipaddress.IPv4Network(os.environ['POOL'])
        links=native('ip','-j','-d','link','show','dev',bridge)
        if len(links)!=1 or links[0].get('linkinfo',{}).get('info_kind')!='bridge': raise RuntimeError('ALB bridge incarnation changed')
        result=[]
        for route in requested:
            for key in ('ClusterID','OwnerToken','NodeName','NodeUID','ResourceVersion'):
                if not isinstance(route.get(key),str) or not route[key]: raise RuntimeError('Pod route lacks current node ownership')
            exact_id(route['OwnerToken']);exact_id(route['ContainerID']);exact_id(route['NetworkID'])
            pod=prefix(route['Prefix']);worker=address(route['WorkerIP'])
            if pod.overlaps(pool) or any(pod.overlaps(ipaddress.IPv4Network(r['Prefix'])) for r in result): raise RuntimeError('Overlapping VPC pod route')
            c=engine('/containers/'+route['ContainerID']+'/json');labels=c['Config'].get('Labels') or {}
            if c['Id']!=route['ContainerID'] or not c['State']['Running'] or labels.get('stackd.eks.id')!=route['ClusterID'] or labels.get('stackd.eks.owner')!=route['OwnerToken']: raise RuntimeError('Unowned pod worker incarnation')
            endpoints=[link for link in c['NetworkSettings']['Networks'].values() if link['NetworkID']==route['NetworkID'] and link['IPAddress']==worker]
            if len(endpoints)!=1: raise RuntimeError('Pod worker network/IP changed')
            net=engine('/networks/'+route['NetworkID']);labels=net.get('Labels') or {}
            if net['Id']!=route['NetworkID'] or net['Driver']!='bridge' or net.get('Internal') or labels.get('stackd.eks.id')!=route['ClusterID'] or labels.get('stackd.eks.owner')!=route['OwnerToken']: raise RuntimeError('Unowned pod worker bridge')
            endpoint=net.get('Containers',{}).get(route['ContainerID'],{})
            if endpoint.get('IPv4Address','').split('/')[0]!=worker: raise RuntimeError('Docker endpoint incarnation changed')
            device=(net.get('Options') or {}).get('com.docker.network.bridge.name') or 'br-'+net['Id'][:12]
            if not re.fullmatch('[a-zA-Z0-9_.-]{1,15}',device) or device==bridge: raise RuntimeError('Invalid worker bridge')
            gateways=[address(cfg['Gateway']) for cfg in net['IPAM']['Config'] if cfg.get('Gateway') and ipaddress.IPv4Address(worker) in ipaddress.IPv4Network(cfg['Subnet'])]
            if len(gateways)!=1: raise RuntimeError('Worker bridge gateway ambiguous')
            gateway=gateways[0]
            native_links=native('ip','-j','-d','address','show','dev',device)
            if len(native_links)!=1 or native_links[0].get('linkinfo',{}).get('info_kind')!='bridge' or not any(a.get('local')==gateway for a in native_links[0].get('addr_info',[])): raise RuntimeError('Worker bridge native gateway changed')
            worker_pool=ipaddress.IPv4Network(endpoints[0]['IPAddress']+'/'+str(endpoints[0]['IPPrefixLen']),strict=False)
            if pod.overlaps(worker_pool): raise RuntimeError('Pod prefix overlaps worker bridge')
            # The API PodCIDR is not trusted as a route until the exact worker
            # namespace actually owns that connected cni0 prefix and hostname.
            execution=engine('/containers/'+route['ContainerID']+'/exec',{'AttachStdout':True,'AttachStderr':True,'Cmd':['cat','/proc/sys/kernel/hostname','/proc/net/route']})['Id']
            stream=engine('/exec/'+execution+'/start',{'Detach':False,'Tty':False},True);output=b''
            while stream:
                if len(stream)<8: raise RuntimeError('Truncated worker route observation')
                size=struct.unpack('>I',stream[4:8])[0]
                if len(stream)<8+size or stream[0]!=1: raise RuntimeError('Invalid worker route observation')
                output+=stream[8:8+size];stream=stream[8+size:]
            if engine('/exec/'+execution+'/json').get('ExitCode')!=0: raise RuntimeError('Worker route observation failed')
            lines=output.decode().splitlines()
            if not lines or lines[0]!=route['NodeName']: raise RuntimeError('Worker node hostname changed')
            connected=False
            for line in lines[2:]:
                fields=line.split()
                if len(fields)<8 or fields[0]!='cni0' or int(fields[2],16)!=0: continue
                destination=ipaddress.IPv4Address(struct.pack('<I',int(fields[1],16)));mask=ipaddress.IPv4Address(struct.pack('<I',int(fields[7],16)))
                if ipaddress.IPv4Network(str(destination)+'/'+str(mask))==pod and int(fields[3],16)&1: connected=True
            if not connected: raise RuntimeError('Worker no longer owns connected pod prefix')
            result.append(dict(route,Prefix=str(pod),WorkerIP=worker,Device=device,Gateway=gateway,BridgePool=str(worker_pool),IfIndex=native_links[0]['ifindex']))
        if any(ipaddress.IPv4Network(a['Prefix']).overlaps(ipaddress.IPv4Network(b['BridgePool'])) for a in result for b in result): raise RuntimeError('Pod prefix overlaps a worker bridge')
        return source,bridge,links[0]['ifindex'],result
    def same_path(p,source,bridge,index,routes):
        def identity(route): return {key:value for key,value in route.items() if key!='ResourceVersion'}
        return p.get('Active',False) and source==p['Source'] and bridge==p['Bridge'] and index==p['BridgeIfIndex'] and [identity(r) for r in routes]==[identity(r) for r in p['Routes']]
    def quarantine(p):
        nft(render(p))
        nft(grant_rows(p,True))
        retire(p)
    if os.environ['POD_ROUTE_PHASE']=='prepare':
        blocked=[];preserved=False
        if exists:
            old=load();blocked=old.get('Blocked',old['Routes'])
            try:
                if requested:
                    source,bridge,bridge_index,routes=validate()
                    if same_path(old,source,bridge,bridge_index,routes):
                        inspect_routes(old,True)
                        # Revalidate grant incarnation, but do not remove the
                        # live path or retire conntrack on policy-only refresh.
                        grant_rows(old,True,True)
                        old['Routes']=routes;old['Blocked']=routes
                        nft(render(old,True));preserved=True
            except Exception:
                quarantine(old)
                raise
            if not preserved: quarantine(old)
        if not requested or preserved:
            # A withdrawal remains quarantined until base policy is installed.
            # A stable path remains active while current SG/NACL rules update.
            pass
        else:
            source,bridge,bridge_index,routes=validate()
            used={int(row['table']) for row in native('ip','-N','-j','-4','rule','show') if str(row.get('table','')).isdigit()}
            while True:
                number=secrets.randbelow(1000000000)+10000
                if number not in used and not table_routes(number): break
            blocked=list({r['Prefix']:r for r in blocked+routes}.values())
            p={'Source':source,'Bridge':bridge,'BridgeIfIndex':bridge_index,'Routes':routes,'Blocked':blocked,'Table':number,'Token':secrets.token_hex(16)}
            nft(render(p))
            # Ownership is durable before the first nontransactional ip command.
            run('ip','-4','route','add','unreachable','default','table',str(number),'proto','242')
            for route in routes:
                run('ip','-4','route','add',route['Prefix'],'via',route['WorkerIP'],'dev',route['Device'],'onlink','table',str(number),'proto','242')
                # No iif selector: strict reverse-path lookup for the restored
                # reply tuple must select the same exact worker bridge.
                run('ip','-4','rule','add','priority','11000','from',source+'/32','to',route['Prefix'],'lookup',str(number),'protocol','242')
    elif exists:
        p=load()
        if not requested:
            nft(grant_rows(p,True)+['destroy table ip '+table])
        else:
            # Recheck Docker and actual worker routes immediately before grants.
            try:
                source,bridge,bridge_index,routes=validate()
                if source!=p['Source'] or bridge!=p['Bridge'] or bridge_index!=p['BridgeIfIndex'] or routes!=p['Routes']:
                    raise RuntimeError('Pod route snapshot changed during admission')
                inspect_routes(p,True)
                p['Blocked']=p['Routes']
                if p.get('Active',False):
                    grant_rows(p,True,True)
                    nft(render(p,True))
                else:
                    nft(render(p,True)+grant_rows(p))
            except Exception:
                quarantine(p)
                raise
`
