# Deploying QEMU guests and k3d Kubernetes

This guide deploys the existing native runtimes from a source checkout. It is not
an all-runtime installer: stackd does not bundle firmware, a guest OS, k3d, or
application images. Preparation and API provisioning are separate steps.

- [QEMU/KVM EC2](#qemukvm-ec2) executes Linux HVM guests with real EBS disks.
- [k3d EKS](#k3d-eks) executes Kubernetes in Docker. Its bootstrap worker does not
  require QEMU. **EKS managed node groups with real EC2 workers require both paths**,
  plus prepared worker AMIs and guest-reachable networking.
- [Managed-instance Lambda](#managed-instance-lambda) adds official SSM, Docker,
  runtime images and the managed Lambda agent **inside** prepared EC2 guests.

The examples use a native **Linux x86_64** controller on the same host as the
Docker daemon. Debian/Ubuntu package examples are scoped to that environment,
not Docker Desktop, macOS, rootless Docker, or a remote daemon. They intentionally
use local account `000000000000`, test credentials, and explicit local endpoints.
Run the commands only on a host you own; dependency installation, image preparation
and subsequent AWS-shaped API calls really create host resources.

## Shared prerequisites

### Install the host dependencies

Use a systemd host with cgroup v2 and local **rootful Docker Engine without
user-namespace remapping**. The CLI constructs its shared ECS/Lambda adapters when
`-docker-host` is supplied, even if your intended workload is EC2 or EKS. Their
[host admission requirements](ecs.md#setup-and-supported-execution) therefore
still apply. Docker socket access is effectively host-root authority; granting
access is not an isolation boundary.

For a fresh Ubuntu host, configure Docker's signed apt repository using the
[official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).
For Debian, use the [Debian repository instructions](https://docs.docker.com/engine/install/debian/)
instead; do not install Ubuntu repository packages on Debian. After configuring
the appropriate repository:

```sh
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo apt-get install ca-certificates curl make openssl python3 python3-venv jq
```

For the QEMU path (including managed EKS workers), install these Debian/Ubuntu
packages as well. `dnsmasq-base` supplies the executable without enabling a
host-wide dnsmasq service; stackd owns its per-network daemons.

```sh
sudo apt-get install qemu-system-x86 qemu-utils dnsmasq-base dnsmasq-utils \
  seabios ovmf iproute2 fdisk
# Ubuntu's optional KVM admission diagnostic:
sudo apt-get install cpu-checker
```

These correspond to the binaries discovered by
[`cmd/stackd/ec2.go`](../cmd/stackd/ec2.go): `qemu-system-x86_64`, `qemu-img`,
`qemu-nbd`, `qemu-io`, `dnsmasq`, and `dhcp_release`. The worker-image preparation
script additionally uses `sfdisk` and a privileged Docker helper. See
[Ubuntu's QEMU/KVM guide](https://ubuntu.com/server/docs/how-to/virtualisation/qemu/)
for host virtualization setup. Libvirt is not the instance owner here; do not
create a separate libvirt VM for an EC2 instance.

Install the Go toolchain required by [`go.mod`](../go.mod) (currently Go 1.26.5;
[official installation](https://go.dev/doc/install)), AWS CLI v2
([official installation](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)),
and, for EKS, a compatible `kubectl`
([official Linux installation and checksum verification](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)).
For Kubernetes 1.33, use a kubectl version within the upstream supported version
skew; do not assume the distro's default package is suitable.

### Admit the host and build the controller

Run the following checks as the identity that will run stackd. If that user
cannot access the Docker socket, either use your managed service identity or
explicitly grant Docker group membership according to
[Docker's post-install guide](https://docs.docker.com/engine/install/linux-postinstall/).
Log in again after changing group membership. Do not fix access with a
world-writable socket.

```sh
uname -m                                      # x86_64 for this guide
systemctl is-active docker
test -d /run/systemd/system
stat -fc %T /sys/fs/cgroup                     # cgroup2fs
test -e /dev/loop-control
docker --host unix:///var/run/docker.sock info \
  --format 'OS={{.OSType}} cgroups={{.CgroupVersion}} driver={{.CgroupDriver}} security={{json .SecurityOptions}}'
```

Expect Linux, cgroup v2, and no `rootless` or `userns` security option. These
checks do not replace native adapter admission. Do not automatically rewrite an
existing daemon configuration to pass them. A containerized controller additionally
needs the daemon host's existing `/run/lock` inode and matching host paths; the
native-controller examples below avoid that extra deployment contract.

From the repository root:

```sh
mkdir -p bin
make build
# Only if you also enable real ALB sockets:
CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node
```

`make build` builds stackd and both static Linux Lambda telemetry helpers; keep
those helpers beside the controller binary. There is no special EC2 guest kernel
or k3d helper compiled by this target. The optional ALB relay is selected with
`-elbv2-node-executable`; it is not required just to launch a guest or cluster.

Provision both shared pinned helpers on the **selected daemon**, during your
explicit connected preparation phase:

```sh
export DOCKER_ENGINE=unix:///var/run/docker.sock
export TOOLKIT=nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
export STORAGE=ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
docker --host "$DOCKER_ENGINE" pull "$TOOLKIT"
docker --host "$DOCKER_ENGINE" image inspect "$TOOLKIT"
docker --host "$DOCKER_ENGINE" pull "$STORAGE"
docker --host "$DOCKER_ENGINE" image inspect "$STORAGE"
```

For an offline deployment, transfer prepared images with `docker image save` /
`docker image load`, or an approved registry mirror, and **inspect the exact
reference above on the target daemon** before starting. Archive formats can lose
repository-digest aliases; a matching tag alone does not establish that the
runtime's digest-qualified reference resolves. Likewise stage Go dependencies,
OS packages, firmware, k3d and guest inputs before disconnecting. Runtime flags
are not download/install commands.

The storage image is a startup prerequisite even for an EC2/EKS-only invocation:
the shared Lambda adapter acquires its native owner lock with that installed
helper. Loop-device/ext4 support and telemetry binaries still matter; see the
[complete shared Docker host contract](runtime-containers.md#shared-docker-host).

### Reserve state, capacity and local credentials

Use a short, private, persistent path; do not put runtime state in `/tmp`. The
example gives the current trusted operator ownership. Use your service identity
instead when deploying under a service manager.

```sh
export STATE=/var/lib/stackd
sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$STATE" "$STATE/ec2" "$STATE/eks"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_PAGER=
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
export ENDPOINT=http://127.0.0.1:4566
aws_local() { aws --endpoint-url "$ENDPOINT" --region us-east-1 "$@"; }
```

Use a dedicated shell, not one containing live AWS credentials. Repeat the
exports/function in each client terminal. The HTTP examples bind all host IPv4
interfaces so compute can reach the controller; restrict ingress to your lab.
Do not expose the `test` credential controller to an untrusted network.

Budget disk space for the SQLite database, EBS snapshot blocks and hydrated
volumes, raw image staging copies, Docker images, Kubernetes data and guest RAM.
EBS native volumes live under `$STATE/ec2/volumes`; the remaining EC2 runtime
state is under `$STATE/ec2`. Preserve those directories and the database
together. K3d additionally retains its Docker objects and `$STATE/eks` private
credentials/manifests. Copying only SQLite is not a backup of live workloads.
Guest instance-type RAM/vCPU allocations and Kubernetes workloads consume real
host capacity; rollout surge needs additional headroom.

## QEMU/KVM EC2

### Enable KVM and select firmware

Enable Intel VT-x/AMD-V in host firmware. If this Linux host is itself a VM, the
outer hypervisor must expose nested virtualization and the provider must permit
it. CPU flags alone are not sufficient: stackd must open `/dev/kvm` read/write.
There is no software-emulation fallback when KVM is unavailable.

```sh
kvm-ok                                      # Ubuntu cpu-checker
ls -l /dev/kvm /dev/net/tun
id
# Grant only if the controller identity currently lacks KVM access:
sudo usermod -aG kvm "$(id -un)"
# Log out/in before continuing after a group change.
test -r /dev/kvm && test -w /dev/kvm
for executable in qemu-system-x86_64 qemu-img qemu-nbd qemu-io dnsmasq dhcp_release; do
  command -v "$executable" || exit 1
done
```

Host kernel support for TAP/bridges, packet filtering and systemd CPU scopes is
also required. Docker supplies privileged network/systemd operations, not a
replacement guest kernel. Do not run a second DHCP server on stackd-owned
bridges. Select VPC/subnet ranges that do not overlap your host, VPN, Docker or
Kubernetes networks.

Firmware paths differ between distributions and package releases. Discover the
installed files, then select an absolute path and a matching UEFI code/variable
pair if using UEFI:

```sh
dpkg -L seabios
dpkg -L ovmf
# Exercised Ubuntu SeaBIOS path; use only if this file exists on your host:
export EC2_BIOS=/usr/share/seabios/bios-256k.bin
test -r "$EC2_BIOS"
# For UEFI, select paths from the listing above, for example a matching
# OVMF_CODE_4M.fd / OVMF_VARS_4M.fd pair on a distro that supplies it.
# export EC2_UEFI_CODE=/absolute/path/to/selected/code.fd
# export EC2_UEFI_VARS=/absolute/path/to/matching/vars.fd
```

The smaller SeaBIOS `bios.bin` did not progress to NVMe disk reads in the retained
workflow; do not silently substitute it for `bios-256k.bin`. UEFI variable-store
templates are copied per instance: do not point multiple instances at a mutable
shared NVRAM store. A UEFI-only guest needs both `-ec2-uefi-code` and
`-ec2-uefi-vars`, and AMI `BootMode=uefi`; a legacy image needs `-ec2-bios` and
`BootMode=legacy-bios`. There is no portable default firmware path or implied
Secure Boot support.

### Start EC2/EBS execution

Run in a foreground terminal, retaining its logs:

```sh
./bin/stackd -listen 0.0.0.0:4566 -account-id 000000000000 \
  -database "$STATE/state.sqlite" -docker-host "$DOCKER_ENGINE" \
  -ec2-state-directory "$STATE/ec2" -ec2-bios "$EC2_BIOS"
```

For a UEFI guest, add `-ec2-uefi-code "$EC2_UEFI_CODE"` and
`-ec2-uefi-vars "$EC2_UEFI_VARS"`. Keep the BIOS option as well if you will run
both boot modes. The full generated `vm-<digest>/qmp.sock` path must fit Linux's
107-byte pathname limit; long checkout paths are unsuitable state locations.

By default guest DNS serves local names only. If external resolution is needed,
add repeated `-ec2-dns-upstream IP_ADDRESS` options with explicitly approved IPv4
resolvers. DNS forwarding does not itself create an Internet gateway, a route,
a public address, or security-group permission.

In the client terminal:

```sh
aws_local sts get-caller-identity
aws_local ec2 describe-instance-types --instance-types t3.small
```

Expect account `000000000000`. A responding API proves controller readiness,
not guest readiness. Merely enabling the runtime creates no instance or AMI.

### Prepare and import a bootable image

Supply an **x86_64 Linux HVM full-disk image**, with a firmware bootloader, NVMe
root-disk and virtio-net drivers, DHCP, and (for the user-data examples and EKS)
cloud-init's EC2 datasource. The backend presents Q35/NVMe/virtio, not Amazon
NVMe/ENA hardware identity. A root filesystem tarball, Docker image, kernel file,
or arbitrary AWS AMI ID is not a substitute. SSM and hibernation require additional
in-guest preparation described in [SSM](ssm.md) and
[EC2 hibernation](ec2.md#linux-hibernation).

The retained guest workflows used prepared Ubuntu 24.04 images. Obtain an Ubuntu
amd64 cloud disk from the [official cloud-image listing](https://cloud-images.ubuntu.com/noble/current/),
retain its release/build identifier and verify the published signed checksums
with your trusted Ubuntu keyring before conversion. The listing's `.img` is
QCOW2, not raw; select firmware based on the image's actual boot support (the
listing advertises UEFI/GPT), not its filename. For an already verified local
QCOW2 input:

```sh
export SOURCE_IMAGE=/absolute/path/to/noble-server-cloudimg-amd64.img
export RAW_IMAGE=/absolute/path/to/prepared-ubuntu.raw
qemu-img info "$SOURCE_IMAGE"
qemu-img convert -f qcow2 -O raw "$SOURCE_IMAGE" "$RAW_IMAGE"
sfdisk --json "$RAW_IMAGE"
```

Choose a new output path and retain the input read-only. Conversion does not
install missing drivers, cloud-init or a BIOS bootloader. Any offline filesystem
customization must use a private mount namespace and suppress package-service
autostart; a chroot alone does not isolate networking. See the
[image/network preparation cautions](ec2.md#execution-and-shared-compute-ownership).

Import the **raw full disk** through signed EBS direct APIs, wait for snapshot
completion, then register an AMI referring to it. There is no runtime flag that
registers a file automatically. The following local-only example is the same
sparse-block protocol used by
[`scripts/ssm_managed_guest_smoke.py`](../scripts/ssm_managed_guest_smoke.py)
and [`scripts/ec2_launch_template_smoke.py`](../scripts/ec2_launch_template_smoke.py).
The optional Python environment is client tooling, not controller state:

```sh
python3 -m venv .venv
.venv/bin/pip install boto3
export BOOT_MODE=uefi                    # or legacy-bios for a prepared BIOS disk
export IMAGE_NAME=local-ubuntu-$(date +%s)
.venv/bin/python - <<'PY'
import base64, hashlib, json, math, os, time
from pathlib import Path
import boto3

path = Path(os.environ['RAW_IMAGE'])
size_gib = math.ceil(path.stat().st_size / (1 << 30))
endpoint = os.environ['ENDPOINT']
assert endpoint.startswith(('http://127.0.0.1:', 'https://127.0.0.1:')), endpoint
options = dict(endpoint_url=endpoint, region_name='us-east-1',
               aws_access_key_id='test', aws_secret_access_key='test',
               verify=os.environ.get('AWS_CA_BUNDLE', True))
ebs, ec2 = (boto3.client(name, **options) for name in ('ebs', 'ec2'))
snapshot = ebs.start_snapshot(VolumeSize=size_gib, Description=os.environ['IMAGE_NAME'])['SnapshotId']
print('Owned snapshot:', snapshot, flush=True)  # retain this ID even if upload fails
block_size, changed = 512 * 1024, 0
with path.open('rb') as image:
    index = 0
    while data := image.read(block_size):
        data = data.ljust(block_size, b'\0')
        if data.strip(b'\0'):
            ebs.put_snapshot_block(SnapshotId=snapshot, BlockIndex=index,
                BlockData=data, DataLength=block_size, ChecksumAlgorithm='SHA256',
                Checksum=base64.b64encode(hashlib.sha256(data).digest()).decode())
            changed += 1
        index += 1
ebs.complete_snapshot(SnapshotId=snapshot, ChangedBlocksCount=changed)
deadline = time.monotonic() + 300
while True:
    state = ec2.describe_snapshots(SnapshotIds=[snapshot])['Snapshots'][0]['State']
    if state == 'completed':
        break
    if state == 'error' or time.monotonic() >= deadline:
        raise RuntimeError(f'{snapshot}: {state}; inspect before retrying or deleting')
    time.sleep(2)
image = ec2.register_image(Name=os.environ['IMAGE_NAME'], Architecture='x86_64',
    RootDeviceName='/dev/sda1', VirtualizationType='hvm', BootMode=os.environ['BOOT_MODE'],
    EnaSupport=True, BlockDeviceMappings=[{'DeviceName': '/dev/sda1', 'Ebs': {
        'SnapshotId': snapshot, 'VolumeSize': max(8, size_gib),
        'VolumeType': 'gp3', 'DeleteOnTermination': True}}])['ImageId']
print(json.dumps({'imageId': image, 'snapshotId': snapshot}, indent=2))
PY
```

Retain both returned IDs. `EnaSupport` is API image metadata, not a claim that the
guest sees an ENA device. For large images, use the existing bounded-concurrency
importer as a reference; the sequential example favors clarity. See
[EBS direct snapshot data plane](ec2.md#ebs-direct-snapshot-data-plane) for block
checksums, encryption and completion semantics.

### Provision an instance and observe it

Set `IMAGE_ID` to the actual registered AMI ID. This example uses a new isolated
VPC with no Internet route and relies on a prepared cloud-init image, not a
package download during boot:

```sh
export IMAGE_ID=ami-REPLACE_WITH_RETURNED_ID
VPC_ID=$(aws_local ec2 create-vpc --cidr-block 10.194.20.0/24 --query Vpc.VpcId --output text)
SUBNET_ID=$(aws_local ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.194.20.0/24 \
  --availability-zone us-east-1a --query Subnet.SubnetId --output text)
SG_ID=$(aws_local ec2 create-security-group --vpc-id "$VPC_ID" --group-name local-vm \
  --description 'Owned local VM' --query GroupId --output text)
printf '#!/bin/sh\necho STACKD_GUEST_BOOT_OK >/dev/console\n' > "$STATE/guest-user-data.sh"
INSTANCE_ID=$(aws_local ec2 run-instances --image-id "$IMAGE_ID" --instance-type t3.small \
  --subnet-id "$SUBNET_ID" --security-group-ids "$SG_ID" --count 1 \
  --user-data "file://$STATE/guest-user-data.sh" --query 'Instances[0].InstanceId' --output text)
printf 'Owned instance=%s vpc=%s subnet=%s sg=%s\n' "$INSTANCE_ID" "$VPC_ID" "$SUBNET_ID" "$SG_ID"
aws_local ec2 wait instance-running --instance-ids "$INSTANCE_ID"
aws_local ec2 describe-instance-status --include-all-instances --instance-ids "$INSTANCE_ID"
aws_local ec2 get-console-output --instance-id "$INSTANCE_ID" --latest
```

Wait for your guest's actual boot marker and application health, not just
`running`; console output can lag or require decoding the API's base64 `Output`.
A timeout is a failure to investigate, not proof of readiness. Check controller
logs, image/firmware pairing, permissions, KVM access and guest network policy.
SSH requires an imported/generated EC2 key pair, guest sshd/cloud-init support,
and explicit ingress; it is deliberately not opened by this example. Additional
volumes use ordinary `CreateVolume`/`AttachVolume` APIs; see
[volumes and volume-derived snapshots](ec2.md#volumes-and-volume-derived-snapshots).

## k3d EKS

### Install exactly k3d v5.8.3 and stage node images

Install from the [official v5.8.3 release assets](https://github.com/k3d-io/k3d/releases/tag/v5.8.3),
not a latest-version installer. These commands are for Linux amd64; this guide's
combined EC2 worker path is x86_64-only. Run during connected preparation:

```sh
mkdir -p downloads/k3d-v5.8.3
(
  cd downloads/k3d-v5.8.3 || exit 1
  curl -fSLO https://github.com/k3d-io/k3d/releases/download/v5.8.3/k3d-linux-amd64 &&
  curl -fSLO https://github.com/k3d-io/k3d/releases/download/v5.8.3/checksums.txt &&
  sha256sum --check --ignore-missing checksums.txt
) && install -m 0755 downloads/k3d-v5.8.3/k3d-linux-amd64 bin/k3d-v5.8.3
export K3D="$PWD/bin/k3d-v5.8.3"
"$K3D" version                             # must report k3d version v5.8.3
```

Keep the release checksum manifest with the binary for offline re-verification.
The checksum checks the release download against its published manifest; use
your organization's artifact trust policy for provenance. The runtime rejects a
different k3d version; `-eks-k3d` is a binary path, not an installation request.

Install the exact host Docker images used by
[`compute/eks/versions.go`](../compute/eks/versions.go),
[`runtime.go`](../compute/eks/runtime.go) and
[`native.go`](../compute/eks/native.go):

```sh
export K3S_132=rancher/k3s:v1.32.8-k3s1@sha256:f9f125ef9c662a231a98c507afdd3ba9a94d5f02631f946d1d34000ef67f7263
export K3S_133=rancher/k3s:v1.33.5-k3s1@sha256:fd4740667b7033055c27d424d0d2d660bf66cedbdb225d68e0eab6dd48aa0fd2
for image in "$K3S_132" "$K3S_133" ghcr.io/k3d-io/k3d-tools:5.8.3; do
  docker --host "$DOCKER_ENGINE" pull "$image"
  docker --host "$DOCKER_ENGINE" image inspect "$image" >/dev/null || exit 1
done
```

You can omit 1.32 if you will only create 1.33 clusters. Keep both for the
supported 1.32-to-1.33 control-plane upgrade. No other Kubernetes minor is
selected by this adapter. Stage workload and add-on images separately;
`docker pull` populates the host daemon, **not** each Kubernetes worker's
containerd image store. Offline workloads must have their exact references
imported into the worker stores before scheduling. See the
[add-on guide](eks.md#add-ons-and-control-plane-logs) for extra image requirements.

### Start the controller and create a cluster

For Kubernetes with the local Docker bootstrap worker only, QEMU, KVM and an AMI
are unnecessary. Start one controller (not a second process using the same
SQLite database):

```sh
./bin/stackd -listen 0.0.0.0:4566 -account-id 000000000000 \
  -database "$STATE/state.sqlite" -docker-host "$DOCKER_ENGINE" \
  -eks-state-directory "$STATE/eks" -eks-k3d "$K3D" \
  -eks-listen-host 127.0.0.1 -eks-endpoint-host 127.0.0.1
```

`-eks-listen-host` binds the authenticated Kubernetes proxy; `-eks-endpoint-host`
is the hostname/IP written into client endpoints and certificates. Loopback is
appropriate for host-only kubectl. Remote clients need an explicitly reachable
bind/advertised address and firewall admission; `0.0.0.0` is not a valid advertised
address. Cluster ports are allocated and retained, not fixed at 6443. The native
admin connection is separate from the user-facing authenticated proxy.

The adapter does not adopt an ambient kubeconfig, Docker context, `DOCKER_HOST`,
or arbitrary pre-existing cluster. **Do not run `k3d cluster create` first.**
`CreateCluster` is the resource provisioning path. It needs a same-account IAM
role trusting `eks.amazonaws.com`, role permission to inspect the EC2 network,
and two subnets in different Availability Zones. The local test principal can
perform the following setup; non-test callers also need applicable IAM actions
and `iam:PassRole`:

```sh
aws_local sts get-caller-identity
EKS_VPC=$(aws_local ec2 create-vpc --cidr-block 10.195.0.0/16 --query Vpc.VpcId --output text)
EKS_SUBNET_A=$(aws_local ec2 create-subnet --vpc-id "$EKS_VPC" --cidr-block 10.195.1.0/24 \
  --availability-zone us-east-1a --query Subnet.SubnetId --output text)
EKS_SUBNET_B=$(aws_local ec2 create-subnet --vpc-id "$EKS_VPC" --cidr-block 10.195.2.0/24 \
  --availability-zone us-east-1b --query Subnet.SubnetId --output text)
EKS_SG=$(aws_local ec2 create-security-group --vpc-id "$EKS_VPC" --group-name local-eks \
  --description 'Owned local EKS' --query GroupId --output text)
CONTROL_ROLE=$(aws_local iam create-role --role-name local-eks-control \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --query Role.Arn --output text)
aws_local iam put-role-policy --role-name local-eks-control --policy-name network-inspection \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeSubnets","ec2:DescribeSecurityGroups"],"Resource":"*"}]}'
aws_local eks create-cluster --name local-eks --kubernetes-version 1.33 --role-arn "$CONTROL_ROLE" \
  --resources-vpc-config "subnetIds=$EKS_SUBNET_A,$EKS_SUBNET_B,securityGroupIds=$EKS_SG" \
  --access-config authenticationMode=API_AND_CONFIG_MAP,bootstrapClusterCreatorAdminPermissions=true
aws_local eks wait cluster-active --name local-eks
aws_local eks describe-cluster --name local-eks --query 'cluster.{status:status,endpoint:endpoint,health:health}'
```

The native cluster has one agentless k3s server and a separate local bootstrap
worker, with no k3d load balancer or Traefik. Only the worker registers a Node.
It is real Kubernetes capacity, but it is **not** a managed node group or a fake
EC2 instance. `ACTIVE` follows native API readiness, not worker or application
health. On failure, inspect `cluster.health` and controller/native logs; do not
retry by deleting arbitrary Docker objects. Private endpoints/public CIDR
controls are outside this runtime's supported boundary; the k3s CNI is not an
implementation of EC2 VPC packet policy.

### Use the real Kubernetes endpoint

Keep kubeconfig separate from any production context:

```sh
export KUBECONFIG="$STATE/local-eks.kubeconfig"
aws_local eks update-kubeconfig --name local-eks --kubeconfig "$KUBECONFIG"
kubectl get --raw=/readyz
kubectl get nodes -o wide
kubectl wait --for=condition=Ready nodes --all --timeout=180s
kubectl get pods -A
```

The generated config contains the cluster endpoint/CA and `aws eks get-token`
exec authentication, not a permanent admin credential. Keep local test
credentials in the invoking shell. `get-token` signs locally; stackd verifies
its STS signature without calling AWS. The bootstrap creator grant above allows
this local principal to enter Kubernetes; other IAM users/roles need EKS access
entries and access policies or Kubernetes RBAC. See
[AWS CLI to authenticated Kubernetes](eks.md#aws-cli-to-authenticated-kubernetes).

The runtime-private `admin.kubeconfig` under the cluster's `$STATE/eks` directory
is controller-owned secret material, not the supported customer access path.
Never publish it or merge it into `$HOME/.kube/config`.

Import prepared workload images into **only the owned bootstrap worker**, not the
agentless control-plane server. Identify the cluster from its private manifest
and verify the selected Docker container against that manifest before importing:

```sh
# Display only non-secret fields; match ProxyPort to DescribeCluster's endpoint.
for manifest in "$STATE"/eks/*/owner.json; do
  printf '%s\n' "$manifest"
  jq '{ID,Name,ProxyPort,NativePort}' "$manifest"
done
export OWNER_MANIFEST=/absolute/path/to/the/selected/owner.json
export WORKLOAD_ARCHIVE=/absolute/path/to/prepared-workload-images.tar
NATIVE_NAME=$(jq -r .Name "$OWNER_MANIFEST")
NATIVE_WORKER=$(docker --host "$DOCKER_ENGINE" inspect \
  --format '{{.Id}}' "k3d-$NATIVE_NAME-agent-0")
docker --host "$DOCKER_ENGINE" inspect "$NATIVE_WORKER" |
  jq -e --slurpfile owner "$OWNER_MANIFEST" '
    .[0] as $c | $owner[0] as $o |
    $c.Name == ("/k3d-" + $o.Name + "-agent-0") and
    $c.Config.Labels["stackd.eks.id"] == $o.ID and
    $c.Config.Labels["stackd.eks.owner"] == $o.Token and
    $c.Config.Labels["k3d.cluster"] == $o.Name
  ' >/dev/null &&
  docker --host "$DOCKER_ENGINE" exec -i "$NATIVE_WORKER" \
    ctr images import - < "$WORKLOAD_ARCHIVE"
```

This is an explicit operator import, not cluster adoption. Do not infer ownership
from a similar name. For offline pods select an already imported reference and
`imagePullPolicy: Never`; verify actual pod readiness and application traffic.
Managed EC2 workers need their own archives in their guest images as below.

### Add real managed EC2 workers

A managed node group is not implemented by asking k3d for more Docker agents.
It uses Auto Scaling, launch templates, IAM instance profiles, EC2/QEMU and EBS;
workers must boot and join before satisfying readiness. Complete the QEMU host
setup above first. See [managed worker ownership](eks.md#managed-worker-ownership)
for rollout, drain and failure semantics.

#### Prepare an offline worker disk

Use the same x86_64 Ubuntu raw cloud disk requirements as the EC2 path, with
systemd, cloud-init, an ext4 Linux root partition, sufficient free disk space,
and guest kernel support for overlay, bridge filtering and containerd. Obtain a
matching **k3s binary and amd64 air-gap image archive** from the
[official K3s releases](https://github.com/k3s-io/k3s/releases) and verify the
release's `sha256sum-amd64.txt` manifest. Follow the
[upstream air-gap preparation](https://docs.k3s.io/installation/airgap), not an
online install script in a booting worker. For example, prepare `v1.33.5+k3s1`
for new 1.33 workers:

```sh
mkdir -p downloads/k3s-1.33.5
(
  cd downloads/k3s-1.33.5 || exit 1
  base=https://github.com/k3s-io/k3s/releases/download/v1.33.5%2Bk3s1
  curl -fSLO "$base/k3s" &&
  curl -fSLO "$base/k3s-airgap-images-amd64.tar.zst" &&
  curl -fSLO "$base/sha256sum-amd64.txt" &&
  sha256sum --check --ignore-missing sha256sum-amd64.txt
) && python3 scripts/eks_worker_image.py \
  --raw-image "$RAW_IMAGE" \
  --k3s-binary "$PWD/downloads/k3s-1.33.5/k3s" \
  --airgap-images "$PWD/downloads/k3s-1.33.5/k3s-airgap-images-amd64.tar.zst" \
  --docker-host "$DOCKER_ENGINE" \
  --output /absolute/path/to/new-eks-worker-1.33.raw
```

`--output` must be a new file distinct from the input. This script uses the
installed toolkit in a privileged, network-disabled container to modify a copy;
it does not download packages, boot the guest or prove that the guest will join.
It installs `/usr/local/bin/k3s`, air-gap images and kernel/sysctl configuration,
while preserving the image's cloud-init EC2 datasource. The managed launch
supplies private join material later. Add repeated `--image-archive /path/to/archive`
options for offline workloads/add-ons; the script stages private archive copies
and preserves digest-qualified OCI references. Keep the resulting image private.

For 1.32 workers use the matching `v1.32.8+k3s1` binary/archive. Historical workflow
captures used CUSTOM `v1.33.4+k3s1` worker images while the control plane later
moved to `v1.33.5+k3s1`; do not relabel an old disk as a new release. Host k3s Docker
images, the bootstrap worker's containerd images, and imported EC2 worker disks
are three different artifact stores.

Run the EBS import/AMI registration example above with `RAW_IMAGE` set to each
prepared worker output, a unique `IMAGE_NAME`, and its actual boot mode. Retain
the AMI/snapshot IDs. Publish the actual resulting AMI ID in a private mapping
file, for example:

```sh
export WORKER_IMAGE_ID=ami-REPLACE_WITH_IMPORTED_WORKER_ID
jq -n --arg image "$WORKER_IMAGE_ID" \
  '{"1.33":{"imageId":$image,"releaseVersion":"v1.33.5+k3s1","amiType":"CUSTOM"}}' \
  > "$STATE/eks-node-images.json"
chmod 0600 "$STATE/eks-node-images.json"
```

`-eks-node-images` accepts this JSON object keyed by Kubernetes **minor**. Each
entry has `imageId`, `releaseVersion`, and `amiType`; add a `"1.32"` entry only
when you have imported the corresponding disk. These are registered, local,
account/Region-accessible AMIs, not Docker references or raw filenames. The
mapping is read at controller startup, so restart with the file after import.
No image is fetched or substituted for an absent mapping.

#### Configure guest-reachable HTTPS and restart with both runtimes

Choose an **existing, stable, non-loopback host IP** reachable from your worker
subnets. Do not substitute the Docker-private server address or an as-yet
uncreated VPC gateway for `-eks-worker-advertise-host`. That flag controls the
native Kubernetes API advertisement and published worker transport; the proxy
client address can remain loopback. Workers need the real advertised API port,
UDP overlay transport, and the enforced kubelet/network paths, not merely TCP
4566. See [runtime networking](eks.md#explicit-runtime-selection), including
exact-peer TCP 10250 admission and security-group convergence.

The following is an isolated-lab TLS example. Set `WORKER_HOST` to your selected
host IP; `ip -4 address show` and `ip -4 route show` help identify candidates but
do not prove guest reachability. Restrict host ingress and provision EC2 routing,
security-group and NACL rules deliberately. The self-signed certificate here is
an explicit local trust root, not a recommendation to disable TLS verification.

If you created the earlier bootstrap-only cluster, delete that owned cluster
through the API **with its original controller configuration and endpoint still
running**, and wait for deletion before changing the flags below. Existing
clusters reject a changed worker advertisement; merely restarting does not
migrate their retained bindings. You can retain the VPC/subnets/roles and reuse
them for a fresh `CreateCluster` under the combined configuration.

```sh
export WORKER_HOST=192.0.2.10              # replace: documentation address is not usable
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=stackd-local \
  -addext "subjectAltName=IP:127.0.0.1,IP:$WORKER_HOST,DNS:localhost" \
  -keyout "$STATE/server.key" -out "$STATE/server.crt"
export ENDPOINT=https://127.0.0.1:4566
export AWS_CA_BUNDLE="$STATE/server.crt"
```

Stop the previous foreground controller with Ctrl-C and wait for exit; this
retains its guests/clusters. Then start, adding the UEFI flags if the imported
worker AMI uses UEFI:

```sh
./bin/stackd -listen 0.0.0.0:4566 -account-id 000000000000 \
  -database "$STATE/state.sqlite" -docker-host "$DOCKER_ENGINE" \
  -tls-cert "$STATE/server.crt" -tls-key "$STATE/server.key" \
  -public-endpoint "$ENDPOINT" -compute-endpoint "https://$WORKER_HOST:4566" \
  -ec2-state-directory "$STATE/ec2" -ec2-bios "$EC2_BIOS" \
  -eks-state-directory "$STATE/eks" -eks-k3d "$K3D" \
  -eks-listen-host 127.0.0.1 -eks-endpoint-host 127.0.0.1 \
  -eks-worker-advertise-host "$WORKER_HOST" -eks-node-images "$STATE/eks-node-images.json"
```

Select worker advertisement **before creating the cluster that will own these
workers**. The service guide's historical manual recovery investigations are not
an automatic endpoint migration feature.

#### Provision the worker network and node group

After creating the cluster with the earlier `CreateCluster` commands under the
combined configuration, configure the worker VPC route/public-address path.
The following isolated-lab recipe follows the executable managed-worker workflow;
first ensure the host can route the selected nonoverlapping VPC range. Its broad
ingress rule is appropriate only on a disposable, host-firewalled lab: it admits
the bootstrap container, host and worker paths without assuming their source
subnets. Before sharing the deployment, replace it with rules for the actual
VPC peers, native Docker peer addresses, advertised host and required application
ports, then check overlay and kubelet traffic. A VPC-CIDR-only rule is not enough
for Docker-originated kubelet traffic.

```sh
IGW_ID=$(aws_local ec2 create-internet-gateway --query InternetGateway.InternetGatewayId --output text)
aws_local ec2 attach-internet-gateway --vpc-id "$EKS_VPC" --internet-gateway-id "$IGW_ID"
ROUTE_TABLE=$(aws_local ec2 describe-route-tables --filters "Name=vpc-id,Values=$EKS_VPC" \
  --query 'RouteTables[0].RouteTableId' --output text)
aws_local ec2 create-route --route-table-id "$ROUTE_TABLE" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID"
aws_local ec2 authorize-security-group-ingress --group-id "$EKS_SG" \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'
NODE_ROLE=$(aws_local iam create-role --role-name local-eks-node \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --query Role.Arn --output text)
jq -n --arg sg "$EKS_SG" \
  '{InstanceType:"t3.small",MetadataOptions:{HttpTokens:"required",HttpPutResponseHopLimit:2},NetworkInterfaces:[{DeviceIndex:0,Groups:[$sg],AssociatePublicIpAddress:true,DeleteOnTermination:true}]}' \
  > "$STATE/worker-template.json"
WORKER_TEMPLATE=$(aws_local ec2 create-launch-template --launch-template-name local-eks-workers \
  --launch-template-data "file://$STATE/worker-template.json" --query LaunchTemplate.LaunchTemplateId --output text)
aws_local eks create-nodegroup --cluster-name local-eks --nodegroup-name workers \
  --node-role "$NODE_ROLE" --subnets "$EKS_SUBNET_A" "$EKS_SUBNET_B" \
  --launch-template "id=$WORKER_TEMPLATE,version=1" \
  --scaling-config minSize=1,maxSize=2,desiredSize=1
aws_local eks wait nodegroup-active --cluster-name local-eks --nodegroup-name workers
aws_local eks describe-nodegroup --cluster-name local-eks --nodegroup-name workers \
  --query 'nodegroup.{status:status,health:health,release:releaseVersion,resources:resources}'
aws_local eks update-kubeconfig --name local-eks --kubeconfig "$STATE/local-eks.kubeconfig"
KUBECONFIG="$STATE/local-eks.kubeconfig" kubectl get nodes -l eks.amazonaws.com/nodegroup=workers -o wide
KUBECONFIG="$STATE/local-eks.kubeconfig" kubectl wait --for=condition=Ready \
  nodes -l eks.amazonaws.com/nodegroup=workers --timeout=300s
```

The adapter uses the minor-version mapping when the launch template does not
specify an ImageId. Keep node-role permissions minimal; Pod Identity needs
additional `eks-auth:AssumeRoleForPodIdentity` authority and official-agent images
as described in [Pod Identity](eks.md#pod-identity). The recipe above is node
bootstrap, not a complete application/identity configuration.

Observe actual kubelet versions and Ready conditions; correlate worker Node
names with EC2 instance IDs and the node group's Auto Scaling membership. Then
run a preloaded workload and check application traffic across workers and the
bootstrap worker. A node-group record or a successful `RunInstances` alone is
not Kubernetes capacity. `CREATE_FAILED`, `DEGRADED`, a nonempty health diagnostic,
or a timeout requires diagnosis of the guest console, cloud-init/k3s, TLS,
transport, routing and native logs. Do not replace failed joins with simulated
success. The fuller signed API/import/rollout workload is
[`scripts/eks_managed_workers_smoke.py`](../scripts/eks_managed_workers_smoke.py);
it owns a separate controller and performs extensive mutations/cleanup, so it
is a workflow reference rather than an installer to run against this deployment.

## Managed-instance Lambda

This is a separate Lambda backend, not an alias for ordinary host-container
execution. It requires the QEMU path, a prepared x86_64 guest AMI and a reachable
local HTTPS API. k3d is **not** required. Reuse the
[guest-reachable TLS preparation](#configure-guest-reachable-https-and-restart-with-both-runtimes)
above, including its selected host IP (`WORKER_HOST`) and retained
`$STATE/server.crt`/`server.key`; omit the EKS flags for a Lambda-only deployment.
Do not replace a certificate already trusted by retained workloads.

### Prepare the guest, not just the host

Build the extra Linux agent from the source checkout:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -o bin/stackd-lambda-agent ./compute/lambda/managed/cmd/stackd-lambda-agent
```

Use a **disposable, isolated image-building VM**, not a chroot sharing the
controller's network namespace. Install rootful Docker inside it using the
[official distribution instructions](https://docs.docker.com/engine/install/ubuntu/),
plus `util-linux`, `e2fsprogs`, `iptables` and `ca-certificates`. Its guest kernel
must support cgroups, loop devices, ext4 and Docker networking. Install the
official SSM agent using the [Debian-package instructions](https://docs.aws.amazon.com/systems-manager/latest/userguide/agent-install-deb.html);
do not run a second Snap agent alongside it. The retained workflow used SSM
3.3.5226.0 and Docker 29.1.3; record and validate the versions in your own image.

Stage the compiled binary, the source-owned
[`stackd-lambda-agent.service`](../compute/lambda/managed/assets/stackd-lambda-agent.service),
the **public** local API certificate, and the verified SSM `.deb` in the builder.
Never copy the controller's private key or live credentials into an image.
Inside that builder, with those staged filenames in the working directory:

```sh
sudo apt-get install util-linux e2fsprogs iptables ca-certificates
sudo dpkg -i ./amazon-ssm-agent.deb
sudo install -m 0755 ./stackd-lambda-agent /usr/local/bin/stackd-lambda-agent
sudo install -m 0644 ./stackd-lambda-agent.service /etc/systemd/system/stackd-lambda-agent.service
sudo install -m 0644 ./server.crt /usr/local/share/ca-certificates/stackd-local.crt
sudo update-ca-certificates
sudo systemctl daemon-reload
sudo systemctl enable docker amazon-ssm-agent
# SSM starts this unit only after installing its incarnation-specific config:
sudo systemctl disable stackd-lambda-agent
```

The prepared SSM agent must use **this local deployment**, not AWS defaults.
Set `GUEST_ENDPOINT` inside the builder to the actual guest-reachable HTTPS
origin covered by the copied certificate, then install its endpoint configuration:

```sh
export GUEST_ENDPOINT=https://192.0.2.10:4566  # replace with the actual host IP
python3 - <<'PY' | sudo tee /etc/amazon/ssm/amazon-ssm-agent.json >/dev/null
import json, os
endpoint = os.environ["GUEST_ENDPOINT"]
print(json.dumps({
    "Agent": {"Region": "us-east-1", "SelfUpdate": False},
    "Ssm": {"Endpoint": endpoint, "HealthFrequencyMinutes": 1},
    "Mgs": {"Region": "us-east-1", "Endpoint": endpoint},
    "Mds": {"Endpoint": endpoint},
}))
PY
PYTHON_IMAGE=public.ecr.aws/lambda/python@sha256:1db929eee2769af5a502cb0ac7409245a1f5b8f8cb37f43832e9983f7a0aed53
sudo docker pull --platform linux/amd64 "$PYTHON_IMAGE"
sudo docker image inspect "$PYTHON_IMAGE"
```

Prepare/import images explicitly before disconnecting, and verify the exact
digest reference in the **guest's** Docker store. A host pull does not populate
that store. Install the local CA in customer runtime images or supply an
appropriate `AWS_CA_BUNDLE` if function code calls the self-signed HTTPS API;
guest OS trust alone does not change a container's trust store. SSM S3/CloudWatch
output needs its additional local endpoint/DNS configuration; the existing
[official-agent workflow](../scripts/ssm_managed_guest_smoke.py) shows it.

Capture a clean, shut-down builder disk without prior SSM registration,
cloud-init instance state, `/etc/stackd-lambda-agent.json`, agent TLS keys or
`/var/lib/stackd-lambda-managed` execution state. Preserve cloud-init's EC2
datasource. Import/register the resulting raw disk using the EBS/AMI procedure
above; its endpoint and trusted certificate are deployment-specific.

### Select the prepared capacity backend

With the local API controller still available, create a dedicated EC2-trusting
guest role/profile with the exercised SSM control-channel permissions:

```sh
aws_local iam create-role --role-name local-lambda-guest \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws_local iam put-role-policy --role-name local-lambda-guest --policy-name agent-channel \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:UpdateInstanceInformation","ssmmessages:CreateControlChannel","ssmmessages:OpenControlChannel"],"Resource":"*"}]}'
LAMBDA_INSTANCE_PROFILE=$(aws_local iam create-instance-profile \
  --instance-profile-name local-lambda-guest --query InstanceProfile.Arn --output text)
aws_local iam add-role-to-instance-profile \
  --instance-profile-name local-lambda-guest --role-name local-lambda-guest
```

Extend that policy only for the additional SSM output/features you use. Keep the
guest role distinct from the function's execution role and provider operator
role. Stop the old controller and select the returned AMI/profile in this
launch; add UEFI flags if the actual AMI requires them:

```sh
export LAMBDA_IMAGE_ID=ami-REPLACE_WITH_IMPORTED_MANAGED_IMAGE
export PYTHON_IMAGE=public.ecr.aws/lambda/python@sha256:1db929eee2769af5a502cb0ac7409245a1f5b8f8cb37f43832e9983f7a0aed53
./bin/stackd -listen 0.0.0.0:4566 -account-id 000000000000 \
  -database "$STATE/state.sqlite" -docker-host "$DOCKER_ENGINE" \
  -tls-cert "$STATE/server.crt" -tls-key "$STATE/server.key" \
  -public-endpoint "https://$WORKER_HOST:4566" -compute-endpoint "https://$WORKER_HOST:4566" \
  -ec2-state-directory "$STATE/ec2" -ec2-bios "$EC2_BIOS" \
  -lambda-managed-image-id "$LAMBDA_IMAGE_ID" \
  -lambda-managed-instance-profile "$LAMBDA_INSTANCE_PROFILE" \
  -lambda-managed-instance-type t3.medium \
  -lambda-managed-runtime-image "python3.13:x86_64=$PYTHON_IMAGE"
```

Then provision a capacity provider with same-VPC subnets/security groups and an
operator role trusting `lambda.amazonaws.com`. That role needs the supported EC2
inspection/launch, instance-profile pass-role, encrypted-volume/KMS and SSM
Run Command authority; callers also need provider pass-role and service-linked-role
authority. Allow guest-to-controller HTTPS and controller-to-guest TCP 9443 (or
the selected `-lambda-managed-agent-port`) through the enforced network policies.
Create/publish a managed function using the provider, matching architecture,
Python 3.13+ or a supported provided runtime, at least 2,048 MB, integral vCPU
allocation and 512-MB temporary storage.

Observe real EC2 boot, SSM registration and successful agent bootstrap, then an
actual function invocation; a provider's `Active` record alone is not readiness.
The controller installs private per-incarnation agent configuration/certificates
through SSM and starts the packaged unit; do not bake these files into a shared
AMI. [Managed Lambda's supported API/lifecycle contract](lambda.md#managed-instances-and-capacity-providers)
describes publication, scaling, credential isolation, retention and unsupported
combinations. Retain the exact-owned guest disks and instance state across restart;
delete functions/providers through their owning APIs before retiring dependencies.

## Shutdown, retention and exact-owned cleanup

Ctrl-C or SIGTERM stops controller listeners and joins in-flight work. It does
**not** imply that QEMU guests, Kubernetes containers or their workloads stopped.
Restart with the same database, runtime directories, daemon, firmware and
endpoint configuration to reattach retained resources. Protect the EKS private
manifests, TLS keys and native admin kubeconfigs (directories 0700, private files
0600). Do not hand-edit those files or manufacture ownership labels.

For a temporary EC2 pause, use the API and observe the actual stopped state:

```sh
aws_local ec2 stop-instances --instance-ids "$INSTANCE_ID"
aws_local ec2 wait instance-stopped --instance-ids "$INSTANCE_ID"
# Later: aws_local ec2 start-instances --instance-ids "$INSTANCE_ID"
```

For disposal, delete dependencies through their owning service **while the
controller is available**. For the examples above:

```sh
# Managed workers must retire before their cluster (omit if none were created).
aws_local eks delete-nodegroup --cluster-name local-eks --nodegroup-name workers
aws_local eks wait nodegroup-deleted --cluster-name local-eks --nodegroup-name workers
aws_local eks delete-cluster --name local-eks
aws_local eks wait cluster-deleted --name local-eks
# The standalone EC2 example, if created:
aws_local ec2 terminate-instances --instance-ids "$INSTANCE_ID"
aws_local ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
```

Remove any owned add-ons/Fargate profiles and other cluster dependencies first;
delete failures remain retryable, not permission to force-remove containers.
Then inspect/delete only your recorded launch templates, residual non-deleting
EBS volumes, AMIs (`deregister-image`) and snapshots (`delete-snapshot`), followed
by network routes/IGW attachments, security groups, subnets/VPCs and IAM policies,
profiles/roles no longer in use. Respect `DeleteOnTermination` and snapshot
retention: terminating an instance does not automatically deregister its AMI or
delete its source snapshot. Keep the recorded IDs so cleanup never depends on a
name prefix or broad account-wide enumeration.

EKS deletion checks the retained daemon identity, random incarnation labels and
exact native object IDs. Foreign or unexpected objects/files are preserved and
produce an error. **Do not use `docker system prune`, broad `k3d cluster delete`,
process-name killing, or recursive state-directory deletion as cleanup.** Only
retire the state directory after its exact-owned native resources and API
resources are confirmed gone. See [EKS ownership and retention](eks.md#explicit-runtime-selection)
and [EC2 execution ownership](ec2.md#execution-and-shared-compute-ownership) for
the detailed recovery contracts.
