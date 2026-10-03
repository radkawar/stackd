#!/usr/bin/env python3
"""Prepare an explicit offline EC2 firmware image with a real k3s agent.

The input raw Ubuntu cloud image is read-only. No registry download, guest SSH,
network bootstrap or native cloud mutation occurs. Import the output through the
existing EBS direct APIs/RegisterImage path before using it in a nodegroup launch
template. Extra OCI/Docker archives supply workloads without guest Internet pulls.
"""
import argparse
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import uuid

TOOLKIT = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def digest_archive(source, directory):
    """Keep original image bytes and add the OCI names needed by CRI digest lookup."""
    directory.mkdir(parents=True)
    decoded = source
    if source.suffix in (".zst", ".zstd"):
        decoded = directory / "decoded" / "archive.tar"
        decoded.parent.mkdir()
        with decoded.open("wb") as target:
            command("zstd", "--decompress", "--stdout", str(source), stdout=target)
    with tarfile.open(decoded, "r:*") as archive:
        try:
            member = archive.getmember("index.json")
        except KeyError:
            # Docker-only exports cannot recover a registry manifest digest.
            return source, []
        with archive.extractfile(member) as stream:
            index = json.load(stream)
        manifests = index["manifests"]
        names = {item.get("annotations", {}).get("io.containerd.image.name") for item in manifests}
        aliases = []
        for item in list(manifests):
            annotations = item.get("annotations", {})
            name = annotations.get("io.containerd.image.name")
            if not name or "@" in name:
                continue
            repository = name[:name.rfind(":")] if name.rfind(":") > name.rfind("/") else name
            alias = repository + "@" + item["digest"]
            if alias in names:
                continue
            named = dict(item)
            named["annotations"] = dict(annotations, **{"io.containerd.image.name":alias, "org.opencontainers.image.ref.name":alias})
            manifests.append(named)
            names.add(alias)
            aliases.append(alias)
        if not aliases:
            return source, []
        name = source.name if source.suffix == ".tar" else source.stem
        if not name.endswith(".tar"):
            name += ".tar"
        output = directory / name
        replacement = json.dumps(index, separators=(",", ":")).encode()
        with tarfile.open(output, "w") as target:
            for item in archive:
                if item.name == "index.json":
                    item = copy.copy(item)
                    item.size = len(replacement)
                    target.addfile(item, io.BytesIO(replacement))
                elif item.isfile():
                    with archive.extractfile(item) as stream:
                        target.addfile(item, stream)
                else:
                    target.addfile(item)
    return output, aliases


def prepare_image(args, archives):
    source = args.raw_image.resolve(strict=True)
    binary = args.k3s_binary.resolve(strict=True)
    output = args.output.resolve()
    if output == source or output.exists():
        raise RuntimeError("Output must be a new path, distinct from the read-only source")
    output.parent.mkdir(parents=True, exist_ok=True)
    command("docker", "--host", args.docker_host, "image", "inspect", args.helper_image, stdout=subprocess.DEVNULL)
    table = json.loads(command("sfdisk", "--json", str(source), capture_output=True).stdout)["partitiontable"]
    partitions = [p for p in table["partitions"] if p.get("type", "").lower() in ("0fc63daf-8483-4772-8e79-3d69d8477de4", "83")]
    if not partitions:
        raise RuntimeError("Image has no Linux filesystem partition")
    root = max(partitions, key=lambda p: p["size"])
    sector = table.get("sectorsize", 512)
    command("qemu-img", "convert", "-f", "raw", "-O", "raw", str(source), str(output))
    name = "stackd-eks-image-" + uuid.uuid4().hex
    mounts = ["--mount", f"type=bind,source={output},target=/work/worker.raw",
              "--mount", f"type=bind,source={binary},target=/source/k3s,readonly"]
    for index, archive in enumerate(archives):
        mounts += ["--mount", f"type=bind,source={archive},target=/source/image-{index}{''.join(archive.suffixes)},readonly"]
    script = r'''set -eu
mkdir -p /mnt/worker
mounted=no
cleanup() { if [ "$mounted" = yes ]; then sync; umount /mnt/worker; fi; }
trap cleanup EXIT INT TERM
mount -t ext4 -o "loop,offset=$OFFSET,sizelimit=$SIZE" /work/worker.raw /mnt/worker
mounted=yes
install -D -m 0755 /source/k3s /mnt/worker/usr/local/bin/k3s
mkdir -p /mnt/worker/var/lib/rancher/k3s/agent/images /mnt/worker/etc/modules-load.d /mnt/worker/etc/sysctl.d
for archive in /source/image-*; do cp "$archive" /mnt/worker/var/lib/rancher/k3s/agent/images/; done
printf 'overlay\nbr_netfilter\n' > /mnt/worker/etc/modules-load.d/eks-workers.conf
printf 'net.ipv4.ip_forward=1\nnet.bridge.bridge-nf-call-iptables=1\nnet.bridge.bridge-nf-call-ip6tables=1\n' > /mnt/worker/etc/sysctl.d/90-eks-workers.conf
# The firmware cloud image retains its existing cloud-init/EC2 datasource.
# k3s starts only after the ASG launch template supplies private join material.
test -f /mnt/worker/etc/cloud/cloud.cfg
sync
'''
    try:
        command("docker", "--host", args.docker_host, "run", "--rm", "--pull=never", "--name", name,
                "--privileged", "--network", "none", "--env", f"OFFSET={root['start'] * sector}",
                "--env", f"SIZE={root['size'] * sector}", *mounts, args.helper_image, "sh", "-ec", script)
    finally:
        # The random exact container name is this invocation's only Docker owner.
        leftover = subprocess.run(["docker", "--host", args.docker_host, "container", "inspect", name], capture_output=True)
        if leftover.returncode == 0:
            command("docker", "--host", args.docker_host, "container", "rm", "-f", name)
    return {"raw_image": str(output), "source": str(source), "k3s_binary": str(binary),
            "image_archives": [str(p) for p in archives],
            "partition_start_sector": root["start"], "partition_size_sectors": root["size"]}


def prepare(args):
    originals = [args.airgap_images.resolve(strict=True)] + [path.resolve(strict=True) for path in args.image_archive]
    with tempfile.TemporaryDirectory(prefix="stackd-eks-archives-") as temporary:
        archives, aliases = [originals[0]], []
        for index, source in enumerate(originals[1:]):
            archive, references = digest_archive(source, Path(temporary) / str(index))
            archives.append(archive)
            aliases.extend(references)
        result = prepare_image(args, archives)
        result["image_archives"] = [str(path) for path in originals]
        result["digest_references"] = aliases
        return result




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-image", type=Path, required=True)
    parser.add_argument("--k3s-binary", type=Path, required=True)
    parser.add_argument("--airgap-images", type=Path, required=True)
    parser.add_argument("--image-archive", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    parser.add_argument("--helper-image", default=TOOLKIT)
    args = parser.parse_args()
    print(json.dumps(prepare(args), indent=2))


if __name__ == "__main__":
    main()
