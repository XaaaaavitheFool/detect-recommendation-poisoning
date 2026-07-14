#!/usr/bin/env python
"""Prepare an auditable local Qwen3.5-2B Q4_K_M model on Windows."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence
from uuid import uuid4


MODEL_ID = "Qwen/Qwen3.5-2B"
MODEL_REVISION = "0ef2f43b8689ae0a05bd952463a1f75f78c74d0b"
MODEL_GIT_URL = "https://www.modelscope.cn/Qwen/Qwen3.5-2B.git"
LLAMA_RELEASE_API = "https://api.github.com/repos/ggml-org/llama.cpp/releases/latest"
DEFAULT_ROOT = "qwen3.5-2b-local"


@dataclass(frozen=True)
class PreparationPaths:
    root: Path
    model_dir: Path
    download_dir: Path
    llama_source_dir: Path
    bin_dir: Path
    output_dir: Path
    fp16_gguf: Path
    quantized_gguf: Path
    server_exe: Path
    quantize_exe: Path
    manifest: Path

    @classmethod
    def from_root(cls, root: Path) -> "PreparationPaths":
        root = root.resolve()
        bin_dir = root / "llama-bin"
        output_dir = root / "model"
        return cls(
            root=root,
            model_dir=root / "official-safetensors",
            download_dir=root / "downloads",
            llama_source_dir=root / "llama.cpp-source",
            bin_dir=bin_dir,
            output_dir=output_dir,
            fp16_gguf=output_dir / "qwen3.5-2b-fp16.gguf",
            quantized_gguf=output_dir / "qwen3.5-2b-q4_k_m.gguf",
            server_exe=bin_dir / "llama-server.exe",
            quantize_exe=bin_dir / "llama-quantize.exe",
            manifest=root / "manifest.json",
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_json(url: str) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"User-Agent": "qwen-prefilter-preparer"})
    with urllib.request.urlopen(request, timeout=60) as response:
        parsed = json.load(response)
    if not isinstance(parsed, dict):
        raise ValueError(f"expected a JSON object from {url}")
    return parsed


def resolve_llama_tag_commit(tag_name: str) -> str:
    current = fetch_json(
        f"https://api.github.com/repos/ggml-org/llama.cpp/git/ref/tags/{tag_name}"
    ).get("object")
    for _ in range(3):
        if not isinstance(current, dict):
            break
        object_type = str(current.get("type", ""))
        sha = str(current.get("sha", ""))
        if object_type == "commit" and sha:
            return sha
        url = str(current.get("url", ""))
        if object_type != "tag" or not url:
            break
        current = fetch_json(url).get("object")
    raise ValueError(f"could not resolve llama.cpp release tag {tag_name!r} to a commit")


def select_windows_vulkan_asset(assets: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    matches = [
        asset
        for asset in assets
        if "bin-win-vulkan-x64.zip" in str(asset.get("name", "")).lower()
    ]
    if len(matches) != 1:
        names = [str(asset.get("name", "")) for asset in assets]
        raise ValueError(f"expected one Windows Vulkan x64 llama.cpp asset, found {matches!r}; assets={names!r}")
    return matches[0]


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "qwen-prefilter-preparer"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def safe_extract_zip(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            target = (destination / member.filename).resolve()
            if destination_root not in target.parents and target != destination_root:
                raise ValueError(f"unsafe archive member: {member.filename}")
        zipped.extractall(destination)


def extract_conversion_source(archive: Path, destination: Path) -> None:
    """Extract only the Python conversion toolchain, avoiding Windows long paths."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive) as zipped:
        converter_members = [
            member for member in zipped.infolist()
            if member.filename.endswith("/convert_hf_to_gguf.py")
        ]
        if len(converter_members) != 1:
            raise FileNotFoundError("llama.cpp source archive must contain one convert_hf_to_gguf.py")
        archive_root = converter_members[0].filename.removesuffix("convert_hf_to_gguf.py")
        allowed_prefixes = ("conversion/", "gguf-py/", "requirements/")
        extracted_converter = False
        for member in zipped.infolist():
            if not member.filename.startswith(archive_root):
                continue
            relative = member.filename[len(archive_root):]
            if relative != "convert_hf_to_gguf.py" and not relative.startswith(allowed_prefixes):
                continue
            target = (destination / relative).resolve()
            destination_root = destination.resolve()
            if destination_root not in target.parents and target != destination_root:
                raise ValueError(f"unsafe archive member: {member.filename}")
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            extracted_converter = extracted_converter or relative == "convert_hf_to_gguf.py"
        if not extracted_converter:
            raise FileNotFoundError("could not extract convert_hf_to_gguf.py")


def normalize_windows_binaries(extracted_dir: Path, bin_dir: Path) -> None:
    server_candidates = list(extracted_dir.rglob("llama-server.exe"))
    quantize_candidates = list(extracted_dir.rglob("llama-quantize.exe"))
    if len(server_candidates) != 1 or len(quantize_candidates) != 1:
        raise FileNotFoundError("Windows llama.cpp package must contain llama-server.exe and llama-quantize.exe")
    source_dir = server_candidates[0].parent
    if quantize_candidates[0].parent != source_dir:
        raise ValueError("llama.cpp executables were extracted into different directories")
    bin_dir.mkdir(parents=True, exist_ok=True)
    for source in source_dir.iterdir():
        if source.is_file():
            shutil.copy2(source, bin_dir / source.name)


def find_llama_source_root(extracted_dir: Path) -> Path:
    matches = list(extracted_dir.rglob("convert_hf_to_gguf.py"))
    if len(matches) != 1:
        raise FileNotFoundError("llama.cpp source archive must contain one convert_hf_to_gguf.py")
    return matches[0].parent


def build_conversion_command(python_executable: str, paths: PreparationPaths) -> list[str]:
    return [
        python_executable,
        str(paths.llama_source_dir / "convert_hf_to_gguf.py"),
        str(paths.model_dir),
        "--outfile",
        str(paths.fp16_gguf),
        "--outtype",
        "f16",
        "--no-mtp",
    ]


def build_quantization_command(paths: PreparationPaths) -> list[str]:
    return [
        str(paths.quantize_exe),
        str(paths.fp16_gguf),
        str(paths.quantized_gguf),
        "Q4_K_M",
    ]


def build_dependency_install_command(python_executable: str, requirements: Path) -> list[str]:
    return [
        python_executable,
        "-m",
        "pip",
        "install",
        "--timeout",
        "600",
        "--retries",
        "10",
        "-r",
        str(requirements),
    ]


def run_checked(command: Sequence[str], env: Mapping[str, str] | None = None) -> None:
    subprocess.run(list(command), check=True, env=dict(env) if env is not None else None)


def hash_files(
    root: Path,
    patterns: Sequence[str],
    path_base: Path | None = None,
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    paths: set[Path] = set()
    for pattern in patterns:
        paths.update(path for path in root.rglob(pattern) if path.is_file())
    for path in sorted(paths):
        result[path.relative_to(root).as_posix()] = {
            "path": path.relative_to(path_base or root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    return result


def installed_packages() -> list[str]:
    return sorted(
        f"{distribution.metadata['Name']}=={distribution.version}"
        for distribution in importlib.metadata.distributions()
        if distribution.metadata.get("Name")
    )


def build_manifest(
    paths: PreparationPaths,
    llama_release: Mapping[str, object],
    commands: Sequence[Sequence[str]],
    source_transport: str = "git-lfs",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_model": {
            "provider": "ModelScope",
            "id": MODEL_ID,
            "revision": MODEL_REVISION,
            "download_url": MODEL_GIT_URL,
            "transport": source_transport,
            "files": hash_files(
                paths.model_dir,
                ["*.safetensors", "config.json", "tokenizer*.json", "*.jinja"],
                path_base=paths.root,
            ),
        },
        "llama_cpp": {
            "repository": "ggml-org/llama.cpp",
            "release": str(llama_release.get("tag_name", "")),
            "target_commitish": str(llama_release.get("target_commitish", "")),
            "resolved_tag_commit": str(llama_release.get("resolved_tag_commit", "")),
            "release_url": str(llama_release.get("html_url", "")),
            "source_archive_url": str(llama_release.get("zipball_url", "")),
            "binary_asset_name": str(llama_release.get("binary_asset_name", "")),
            "binary_asset_url": str(llama_release.get("binary_asset_url", "")),
            "runtime": "official Windows Vulkan x64 prebuilt package",
            "downloads": hash_files(paths.download_dir, ["*.zip"], path_base=paths.root),
            "source_files": hash_files(
                paths.llama_source_dir,
                ["convert_hf_to_gguf.py", "requirements-convert_hf_to_gguf.txt"],
                path_base=paths.root,
            ),
            "files": hash_files(paths.bin_dir, ["*.exe", "*.dll"], path_base=paths.root),
        },
        "commands": [list(command) for command in commands],
        "artifacts": hash_files(paths.output_dir, ["*.gguf"], path_base=paths.root),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "packages": installed_packages(),
        },
    }


def build_model_download_commands(paths: PreparationPaths) -> list[list[str]]:
    return [
        ["git", "clone", "--no-checkout", MODEL_GIT_URL, str(paths.model_dir)],
        ["git", "-C", str(paths.model_dir), "checkout", "--detach", MODEL_REVISION],
        ["git", "-C", str(paths.model_dir), "lfs", "pull"],
    ]


def download_official_model(paths: PreparationPaths) -> list[list[str]]:
    commands = build_model_download_commands(paths)
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    run_checked(commands[0], env=env)
    run_checked(commands[1], env=env)
    run_checked(commands[2])
    resolved = subprocess.run(
        ["git", "-C", str(paths.model_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if resolved != MODEL_REVISION:
        raise ValueError(f"ModelScope checkout resolved to {resolved}, expected {MODEL_REVISION}")
    return commands


def validate_existing_model_snapshot(paths: PreparationPaths) -> list[str]:
    metadata_dir = paths.model_dir / ".git"
    revision_text = ""
    for revision_file in (
        metadata_dir / "packed-refs",
        metadata_dir / "refs" / "remotes" / "origin" / "master",
    ):
        if revision_file.is_file():
            revision_text += revision_file.read_text(encoding="utf-8", errors="replace")
    if MODEL_REVISION not in revision_text:
        raise ValueError(f"resumable ModelScope snapshot is not pinned to {MODEL_REVISION}")
    config_path = paths.model_dir / "config.json"
    index_path = paths.model_dir / "model.safetensors.index.json"
    if not config_path.is_file() or not index_path.is_file():
        raise FileNotFoundError("resumable snapshot is missing config.json or model.safetensors.index.json")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    weight_map = index.get("weight_map") if isinstance(index, dict) else None
    if not isinstance(weight_map, dict) or not weight_map:
        raise ValueError("model.safetensors.index.json has no weight_map")
    filenames = sorted({str(filename) for filename in weight_map.values()})
    for filename in filenames:
        weight_path = paths.model_dir / filename
        if not weight_path.is_file():
            raise FileNotFoundError(weight_path)
        with weight_path.open("rb") as handle:
            prefix = handle.read(128)
        if prefix.startswith(b"version https://git-lfs.github.com/spec"):
            raise ValueError(f"LFS weight was not downloaded: {weight_path}")
    return filenames


def prepare_llama_cpp(paths: PreparationPaths) -> dict[str, object]:
    release = fetch_json(LLAMA_RELEASE_API)
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("GitHub release response has no assets list")
    asset = select_windows_vulkan_asset(assets)
    binary_url = str(asset.get("browser_download_url", ""))
    source_url = str(release.get("zipball_url", ""))
    if not binary_url or not source_url:
        raise ValueError("GitHub release is missing binary or source archive URLs")
    tag_name = str(release.get("tag_name", ""))
    if not tag_name:
        raise ValueError("GitHub release is missing tag_name")
    release["resolved_tag_commit"] = resolve_llama_tag_commit(tag_name)
    release["binary_asset_name"] = str(asset.get("name", ""))
    release["binary_asset_url"] = binary_url

    paths.download_dir.mkdir(parents=True, exist_ok=True)
    binary_zip = paths.download_dir / str(asset.get("name", "llama-windows-vulkan.zip"))
    source_zip = paths.download_dir / f"llama.cpp-{release.get('tag_name', 'latest')}-source.zip"
    if not binary_zip.is_file():
        download_file(binary_url, binary_zip)
    if not source_zip.is_file():
        download_file(source_url, source_zip)

    extracted_binary = paths.download_dir / "llama-windows-extracted"
    safe_extract_zip(binary_zip, extracted_binary)
    normalize_windows_binaries(extracted_binary, paths.bin_dir)
    extract_conversion_source(source_zip, paths.llama_source_dir)
    return release


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare official Qwen3.5-2B as an auditable Q4_K_M GGUF.")
    parser.add_argument("--work-dir", default=DEFAULT_ROOT, help=f"Artifact directory. Default: {DEFAULT_ROOT}.")
    parser.add_argument(
        "--resume-staging",
        help="Resume from an existing staging directory whose official ModelScope weights are complete.",
    )
    parser.add_argument(
        "--skip-dependency-install",
        action="store_true",
        help="Do not install the pinned llama.cpp conversion requirements before conversion.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if os.name != "nt":
        print("prepare_qwen_model.py requires Windows for the precompiled llama.cpp package", file=sys.stderr)
        return 2
    final_root = Path(args.work_dir).resolve()
    if final_root.exists():
        print(
            f"Qwen work directory already exists: {final_root}. "
            "Refusing to mix old and new artifacts; choose a new --work-dir.",
            file=sys.stderr,
        )
        return 2
    resume_mode = bool(args.resume_staging)
    staging_root = (
        Path(args.resume_staging).resolve()
        if resume_mode
        else final_root.parent / f".{final_root.name}.staging-{uuid4().hex}"
    )
    if resume_mode and not staging_root.is_dir():
        print(f"Resume staging directory does not exist: {staging_root}", file=sys.stderr)
        return 2
    paths = PreparationPaths.from_root(staging_root)
    try:
        paths.output_dir.mkdir(parents=True, exist_ok=True)
        if resume_mode:
            validate_existing_model_snapshot(paths)
            commands: list[list[str]] = [
                ["resume-modelscope-snapshot", MODEL_ID, MODEL_REVISION, str(paths.model_dir)]
            ]
        else:
            commands = download_official_model(paths)
        release = prepare_llama_cpp(paths)
        if not args.skip_dependency_install:
            requirements = paths.llama_source_dir / "requirements" / "requirements-convert_hf_to_gguf.txt"
            install_command = build_dependency_install_command(sys.executable, requirements)
            run_checked(install_command)
            commands.append(install_command)
        conversion_commands = [
            build_conversion_command(sys.executable, paths),
            build_quantization_command(paths),
        ]
        for command in conversion_commands:
            run_checked(command)
        commands.extend(conversion_commands)
        source_transport = "modelscope-sdk-snapshot-cache" if resume_mode else "git-lfs"
        manifest = build_manifest(paths, release, commands, source_transport=source_transport)
        paths.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        staging_root.replace(final_root)
        final_paths = PreparationPaths.from_root(final_root)
        print(f"Prepared {final_paths.quantized_gguf} and wrote {final_paths.manifest}", file=sys.stderr)
        return 0
    except Exception as exc:
        print(f"Qwen model preparation failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if staging_root.exists() and not resume_mode:
            try:
                shutil.rmtree(staging_root)
            except OSError as cleanup_error:
                print(f"Could not remove staging directory {staging_root}: {cleanup_error}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
