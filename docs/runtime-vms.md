# Deploying QEMU guests and k3d Kubernetes

Prepare a Linux host to run EC2 guests, EKS clusters or managed-instance Lambda.
Install a [published release](releases.md#install-a-published-release) or build
the controller from source, then install the dependencies for your selected
runtime. Firmware, guest operating systems, k3d and application images are
installed separately.

- [QEMU/KVM EC2](#qemukvm-ec2) runs Linux HVM guests with EBS disks.
- [k3d EKS](#k3d-eks) runs Kubernetes in Docker. Its bootstrap worker does not
  require QEMU. **EKS managed node groups require both runtimes**,
  prepared worker AMIs and guest-reachable networking.
- [Managed-instance Lambda](#managed-instance-lambda) adds official SSM, Docker,
  runtime images and the managed Lambda agent **inside** prepared EC2 guests.

The examples use a **Linux x86_64** controller on the same host as the
Docker daemon. The Debian/Ubuntu instructions do not cover Docker Desktop,
macOS, rootless Docker or a remote daemon. Examples use account
`000000000000`, test credentials and local endpoints. Provisioning guests or
clusters creates containers, disks and network interfaces on this host.

## Shared prerequisites

### Install the host dependencies

Use a systemd host with cgroup v2 and local rootful Docker Engine without
user-namespace remapping for EC2 and EKS.
`-docker-host` selects the Engine connection; it does not enable Lambda or ECS.
EC2/EKS do not need Lambda telemetry or storage helpers.
Docker-socket access grants host-root authority; restrict it to trusted users.

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

The controller discovers `qemu-system-x86_64`, `qemu-img`, `qemu-nbd`, `qemu-io`,
`dnsmasq` and `dhcp_release`; see [`cmd/stackd/ec2.go`](../cmd/stackd/ec2.go).
The worker-image preparation script also uses `sfdisk` and a privileged Docker
helper. See [Ubuntu's QEMU/KVM guide](https://ubuntu.com/server/docs/how-to/virtualisation/qemu/)
for host virtualization setup. Stackd manages EC2 instances directly; do not
create a separate libvirt VM for them.

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
docker --host unix:///var/run/docker.sock info \
  --format 'OS={{.OSType}} cgroups={{.CgroupVersion}} driver={{.CgroupDriver}} security={{json .SecurityOptions}}'
```

Expect Linux, cgroup v2, and no `rootless` or `userns` security option. Stackd
also checks runtime prerequisites at startup. Review any existing Docker
configuration before changing it. A containerized controller needs the daemon
host's existing `/run/lock` inode and matching host paths; the examples below
run the controller directly on the host.

For a source build, run from the repository root. With a published release,
place the installed controller at `bin/stackd` or substitute its path below.
Source scripts and optional helper builds still require a checkout.

```sh
mkdir -p bin
go build -trimpath -o bin/stackd ./cmd/stackd
# Only if you also enable real ALB sockets:
CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node
```

EC2/EKS-only deployments do not need Lambda telemetry helpers or its storage
image. Build the optional ALB relay only if you need ALB sockets, and select it
with `-elbv2-node-executable`.

Install the networking toolkit on the selected daemon before starting:

```sh
export DOCKER_ENGINE=unix:///var/run/docker.sock
export TOOLKIT=nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
docker --host "$DOCKER_ENGINE" pull "$TOOLKIT"
docker --host "$DOCKER_ENGINE" image inspect "$TOOLKIT"
```

For an offline deployment, transfer prepared images with `docker image save` /
`docker image load`, or a registry mirror, then inspect the exact reference above
on the target daemon. Archives can lose repository-digest aliases, so a matching
tag alone is insufficient. Also stage Go dependencies, OS packages, firmware,
k3d and guest inputs before disconnecting; runtime flags do not install them.

If you also enable `-lambda-runtime`, prepare its storage image and static Linux
telemetry binaries as described in the
[container guide](runtime-containers.md#shared-docker-host).
EC2/EKS still require the local-host configuration described here.

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
Guest RAM/vCPU allocations and Kubernetes workloads consume host capacity;
allow additional headroom for rollout surge.

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
also required. Docker performs privileged networking and systemd operations;
guests use their own kernels. Do not run another DHCP server on stackd-managed
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

Use `bios-256k.bin` for the SeaBIOS configuration above: the smaller `bios.bin`
did not reach NVMe disk reads in this workflow. UEFI variable-store templates
are copied per instance; do not share a mutable NVRAM store between instances.
A UEFI-only guest needs both `-ec2-uefi-code` and `-ec2-uefi-vars`, and AMI
`BootMode=uefi`; a legacy image needs `-ec2-bios` and `BootMode=legacy-bios`.
Firmware paths vary by distribution; this setup does not imply Secure Boot support.

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

Expect account `000000000000`. Next, import an AMI and launch a guest;
starting the controller does not create either resource.

### Prepare and import a bootable image

Supply an **x86_64 Linux HVM full-disk image**, with a firmware bootloader, NVMe
root-disk and virtio-net drivers, DHCP, and (for the user-data examples and EKS)
cloud-init's EC2 datasource. The backend presents Q35/NVMe/virtio, not Amazon
NVMe/ENA hardware identity. A root filesystem tarball, Docker image, kernel file,
or arbitrary AWS AMI ID is not a substitute. SSM and hibernation require additional
in-guest preparation described in [SSM](ssm.md) and
[EC2 hibernation](ec2.md#linux-hibernation).

Ubuntu 24.04 amd64 cloud disks have been used with this runtime. Download an image
from the [official listing](https://cloud-images.ubuntu.com/noble/current/),
record its release/build identifier, and verify its signed checksums with your
trusted Ubuntu keyring. The listing's `.img` is QCOW2, not raw. Select firmware
for the image's boot support (the listing advertises UEFI/GPT), not its filename.
Convert the verified QCOW2 input:

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
completion, then register an AMI referring to it. Runtime flags do not register
image files. This local-only example uses the sparse-block protocol from
[`scripts/ssm_managed_guest_smoke.py`](../scripts/ssm_managed_guest_smoke.py)
and [`scripts/ec2_launch_template_smoke.py`](../scripts/ec2_launch_template_smoke.py).
The Python environment is client tooling, not controller state:

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

Retain both returned IDs. `EnaSupport` is API image metadata; the guest uses
virtio-net, not an ENA device. For large images, use the existing
bounded-concurrency importer as a reference. See
[EBS direct snapshot data plane](ec2.md#ebs-direct-snapshot-data-plane) for block
checksums, encryption and completion semantics.

### Provision an instance and observe it

Set `IMAGE_ID` to the registered AMI ID. This example creates an isolated VPC
with no Internet route. Prepare cloud-init in the image before launch rather
than downloading packages during boot:

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

Wait for the guest's boot marker and application health as well as `running`.
Console output can lag or require decoding the API's base64 `Output`. On a
timeout, check controller logs, image/firmware pairing, permissions, KVM access
and guest network policy. SSH requires an EC2 key pair, guest sshd/cloud-init
support and ingress rules; this example does not open SSH. Additional volumes
use `CreateVolume`/`AttachVolume`; see
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

Keep the checksum manifest for offline verification and follow your artifact
trust policy for release provenance. The runtime requires k3d v5.8.3;
`-eks-k3d` selects the installed binary.

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
  -eks-state-directory "$STATE/eks" -eks-k3d "$K3D" -eks-storage-reserve-gib 64 \
  -eks-listen-host 127.0.0.1 -eks-endpoint-host 127.0.0.1
```

`-eks-listen-host` binds the authenticated Kubernetes proxy; `-eks-endpoint-host`
is the hostname/IP written into client endpoints and certificates. Loopback is
appropriate for host-only kubectl. Remote clients need an explicitly reachable
bind/advertised address and firewall admission; `0.0.0.0` is not a valid advertised
address. Cluster ports are allocated and retained, not fixed at 6443. The native
admin connection is separate from the user-facing authenticated proxy.

`-eks-storage-reserve-gib` defaults to **64 GiB** and controls native worker
nodefs/imagefs eviction reserves, not an AWS API field. The daemon filesystem
must exceed twice the reserve. Creation retains the reserve and capacity-derived
image GC percentages for the bootstrap worker and future Fargate workers;
restarts preserve that policy. **Recreate the cluster** to change this setting
or replace an older cluster's native percentage defaults. See
[the exact storage thresholds and rounding](eks.md#native-worker-storage-reserve).

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

The cluster has one agentless k3s server and a separate Docker bootstrap worker,
with no k3d load balancer or Traefik. Only the worker registers a Node. It
provides Kubernetes capacity but is neither an EC2 instance nor a managed node
group. Cluster `ACTIVE` means the Kubernetes API is ready; check worker and
application health separately. On failure, inspect `cluster.health` and
controller/k3s logs rather than deleting Docker objects. Private endpoints and
public CIDR controls are unsupported. The k3s CNI does not enforce EC2 VPC
packet policy.

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

The cluster's `$STATE/eks` directory contains a private `admin.kubeconfig` for
the controller. Never publish it or merge it into `$HOME/.kube/config`; use the
authenticated endpoint above.

Import prepared workload images into the cluster's bootstrap worker, not the
agentless control-plane server. Select the cluster's private manifest and
check the container's identity against it before importing:

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

Use the manifest checks above rather than selecting a container by name alone.
For offline pods, select an imported reference and `imagePullPolicy: Never`,
then check pod readiness and application traffic. Managed EC2 workers need
their own archives in their guest images as described below.

### Add real managed EC2 workers

Managed node groups use Auto Scaling, launch templates, IAM instance profiles,
EC2/QEMU and EBS, rather than additional k3d Docker agents. Workers must boot
and join the cluster before they are ready. Complete the QEMU host setup first.
See [managed worker ownership](eks.md#managed-worker-ownership) for rollout,
drain and failure handling.

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

`--output` must be a new file distinct from the input. The script modifies a
copy using the installed toolkit in a privileged, network-disabled container.
It installs `/usr/local/bin/k3s`, air-gap images and kernel/sysctl configuration,
and preserves cloud-init's EC2 datasource. It does not download packages or
boot the guest; check that workers join after launch. Managed launches supply
private join material. Add repeated `--image-archive /path/to/archive` options
for offline workloads/add-ons; the script copies the archives and preserves
digest-qualified OCI references. Keep the resulting image private.

For 1.32 workers, use the matching `v1.32.8+k3s1` binary and archive. Do not relabel
an older prepared disk as a newer release. The host's k3s Docker images,
bootstrap worker's containerd images and imported EC2 worker disks are separate
artifact stores; prepare each one.

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
subnets for `-eks-worker-advertise-host`. Do not use the Docker-private server
address or a VPC gateway that has not been created. This flag advertises the
Kubernetes API and worker transport; the client proxy can remain on loopback.
Workers need the advertised API port, UDP overlay transport and kubelet/network
paths as well as TCP 4566. See [runtime networking](eks.md#explicit-runtime-selection)
for exact-peer TCP 10250 admission and security-group convergence.

For this isolated-lab TLS example, set `WORKER_HOST` to that host IP.
Use `ip -4 address show` and `ip -4 route show` to identify candidates, then
check guest reachability. Restrict host ingress and configure EC2 routes,
security groups and NACLs. Clients must trust the self-signed certificate below;
do not disable TLS verification.

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

Select the worker advertisement before creating the cluster.
Restarting does not migrate existing cluster endpoints.

#### Provision the worker network and node group

Create the cluster with the earlier `CreateCluster` commands under the combined
configuration, then configure worker VPC routing and public addresses. Ensure
the host can route the selected, nonoverlapping VPC range.

**Use the broad ingress rule below only in a disposable, host-firewalled lab.**
It admits bootstrap-container, host and worker traffic. Before sharing the
deployment, replace it with rules for the VPC peers, Docker peer addresses,
advertised host and application ports, then check overlay and kubelet traffic.
A VPC-CIDR-only rule does not admit Docker-originated kubelet traffic.

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

Check kubelet versions and Ready conditions, and match worker Node names to EC2
instance IDs and Auto Scaling membership. Run a preloaded workload and check
traffic across the EC2 workers and bootstrap worker.
For `CREATE_FAILED`, `DEGRADED`, health diagnostics or timeouts, inspect the guest
console, cloud-init/k3s, TLS, routing and native logs.
The [managed-worker workflow](../scripts/eks_managed_workers_smoke.py) includes
signed API calls, image import, rollout and cleanup. It starts its own controller
and mutates resources; do not run it as an installer against this deployment.

## Managed-instance Lambda

Managed-instance Lambda runs functions inside EC2 guests rather than host
containers. It requires QEMU, a prepared x86_64 guest AMI and a reachable local
HTTPS API; k3d is not required. Reuse the
[guest-reachable TLS preparation](#configure-guest-reachable-https-and-restart-with-both-runtimes),
including `WORKER_HOST` and `$STATE/server.crt`/`server.key`. Omit EKS flags for
a Lambda-only deployment. Keep certificates trusted by retained workloads.

### Prepare the guest, not just the host

Build the extra Linux agent from the source checkout:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -o bin/stackd-lambda-agent ./compute/lambda/managed/cmd/stackd-lambda-agent
```

Use a **disposable, isolated image-building VM**, not a chroot sharing the
controller's network namespace. Install rootful Docker using the
[official distribution instructions](https://docs.docker.com/engine/install/ubuntu/),
plus `util-linux`, `e2fsprogs`, `iptables` and `ca-certificates`. The guest kernel
must support cgroups, loop devices, ext4 and Docker networking. Install the
official SSM agent using the [Debian-package instructions](https://docs.aws.amazon.com/systems-manager/latest/userguide/agent-install-deb.html);
do not run a Snap agent alongside it. This workflow used SSM 3.3.5226.0 and
Docker 29.1.3; record and validate the versions in your image.

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

Before disconnecting, import runtime images into the **guest's** Docker store
and inspect their exact digest references. Pulling images on the host does not
populate the guest store. If function code calls the self-signed HTTPS API,
install the local CA in its runtime image or supply `AWS_CA_BUNDLE`; guest OS
trust does not change container trust stores. SSM S3/CloudWatch output needs
additional local endpoint/DNS configuration; see the
[official-agent workflow](../scripts/ssm_managed_guest_smoke.py).

Capture a clean, shut-down builder disk without prior SSM registration,
cloud-init instance state, `/etc/stackd-lambda-agent.json`, agent TLS keys or
`/var/lib/stackd-lambda-managed` execution state. Preserve cloud-init's EC2
datasource. Import/register the resulting raw disk using the EBS/AMI procedure
above; its endpoint and trusted certificate are deployment-specific.

### Select the prepared capacity backend

While the local API controller is available, create a dedicated EC2-trusting
guest role/profile with SSM control-channel permissions:

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

Check EC2 boot, SSM registration and agent bootstrap, then invoke a function.
A provider's `Active` status alone does not establish readiness. The controller
installs private per-incarnation agent configuration and certificates through
SSM and starts the packaged unit; do not bake these files into a shared AMI.
See [managed Lambda](lambda.md#managed-instances-and-capacity-providers) for
publication, scaling, credential isolation, retention and unsupported combinations.
Retain guest disks and instance state across restarts. Delete functions and
providers through their APIs before retiring dependencies.

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

Remove add-ons, Fargate profiles and other cluster dependencies first. If
deletion fails, resolve the error and retry through the API rather than
force-removing containers. Then remove your recorded launch templates, residual
EBS volumes, AMIs (`deregister-image`) and snapshots (`delete-snapshot`), followed
by routes, IGW attachments, security groups, subnets/VPCs and unused IAM
policies/profiles/roles. Respect `DeleteOnTermination` and snapshot retention:
terminating an instance does not deregister its AMI or delete its source
snapshot. Use recorded IDs rather than name prefixes or account-wide deletion.

EKS deletion checks the retained daemon identity, incarnation labels and
container IDs. Unexpected objects or files are preserved and reported as an
error. **Do not use `docker system prune`, broad `k3d cluster delete`,
process-name killing or recursive state-directory deletion as cleanup.**
Remove the state directory only after its runtime and API resources are gone.
See [EKS ownership and retention](eks.md#explicit-runtime-selection) and
[EC2 execution ownership](ec2.md#execution-and-shared-compute-ownership)
for recovery procedures.
