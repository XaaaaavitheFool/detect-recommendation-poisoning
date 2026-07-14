import contextlib
import hashlib
import io
import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "prepare_qwen_model.py"


def load_module():
    if not SCRIPT_PATH.is_file():
        raise AssertionError(f"missing preparation script: {SCRIPT_PATH}")
    spec = importlib.util.spec_from_file_location("prepare_qwen_model", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrepareQwenModelTests(unittest.TestCase):
    def test_pins_official_modelscope_model_to_immutable_revision(self):
        module = load_module()

        self.assertEqual(module.MODEL_ID, "Qwen/Qwen3.5-2B")
        self.assertEqual(
            module.MODEL_REVISION,
            "0ef2f43b8689ae0a05bd952463a1f75f78c74d0b",
        )

    def test_selects_official_windows_vulkan_prebuilt_asset(self):
        module = load_module()
        assets = [
            {"name": "llama-b9999-bin-win-cpu-x64.zip", "browser_download_url": "cpu"},
            {"name": "llama-b9999-bin-win-vulkan-x64.zip", "browser_download_url": "vulkan"},
            {"name": "llama-b9999-bin-ubuntu-x64.zip", "browser_download_url": "linux"},
        ]

        selected = module.select_windows_vulkan_asset(assets)

        self.assertEqual(selected["browser_download_url"], "vulkan")

    def test_extracts_only_conversion_source_from_llama_archive(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "llama-source.zip"
            destination = root / "source"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("llama-commit/convert_hf_to_gguf.py", "converter")
                zipped.writestr("llama-commit/conversion/qwen.py", "qwen")
                zipped.writestr("llama-commit/gguf-py/gguf/__init__.py", "gguf")
                zipped.writestr(
                    "llama-commit/requirements/requirements-convert_hf_to_gguf.txt",
                    "-r ./requirements-convert_legacy_llama.txt\n",
                )
                zipped.writestr(
                    "llama-commit/requirements/requirements-convert_legacy_llama.txt",
                    "numpy\n",
                )
                zipped.writestr("llama-commit/examples/very/deep/demo.txt", "unused")

            module.extract_conversion_source(archive, destination)

            self.assertTrue((destination / "convert_hf_to_gguf.py").is_file())
            self.assertTrue((destination / "conversion" / "qwen.py").is_file())
            self.assertTrue((destination / "gguf-py" / "gguf" / "__init__.py").is_file())
            self.assertTrue(
                (destination / "requirements" / "requirements-convert_legacy_llama.txt").is_file()
            )
            self.assertFalse((destination / "examples").exists())

    def test_builds_modelscope_git_lfs_commands_for_fixed_commit(self):
        module = load_module()
        paths = module.PreparationPaths.from_root(Path("work"))

        self.assertTrue(hasattr(module, "build_model_download_commands"))
        commands = module.build_model_download_commands(paths)

        self.assertEqual(
            commands[0][:3],
            ["git", "clone", "--no-checkout"],
        )
        self.assertIn("https://www.modelscope.cn/Qwen/Qwen3.5-2B.git", commands[0])
        self.assertEqual(commands[1][-1], module.MODEL_REVISION)
        self.assertEqual(commands[2][-2:], ["lfs", "pull"])

    def test_builds_fp16_conversion_and_q4_k_m_quantization_commands(self):
        module = load_module()
        paths = module.PreparationPaths.from_root(Path("work"))

        conversion = module.build_conversion_command(
            python_executable="python.exe",
            paths=paths,
        )
        quantization = module.build_quantization_command(paths)

        self.assertEqual(conversion[0], "python.exe")
        self.assertIn("convert_hf_to_gguf.py", conversion[1])
        self.assertEqual(conversion[-3:], ["--outtype", "f16", "--no-mtp"])
        self.assertTrue(quantization[0].endswith("llama-quantize.exe"))
        self.assertEqual(quantization[-1], "Q4_K_M")

    def test_dependency_install_tolerates_slow_large_wheel_downloads(self):
        module = load_module()
        requirements = Path("requirements-convert_hf_to_gguf.txt")

        command = module.build_dependency_install_command("python.exe", requirements)

        self.assertEqual(command[:4], ["python.exe", "-m", "pip", "install"])
        self.assertIn("--timeout", command)
        self.assertEqual(command[command.index("--timeout") + 1], "600")
        self.assertIn("--retries", command)
        self.assertEqual(command[-2:], ["-r", str(requirements)])

    def test_sha256_file_returns_traceable_digest(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "artifact.bin"
            path.write_bytes(b"official-model-artifact")

            digest = module.sha256_file(path)

        self.assertEqual(digest, hashlib.sha256(b"official-model-artifact").hexdigest())

    def test_manifest_records_source_toolchain_commands_and_hashes(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = module.PreparationPaths.from_root(root)
            paths.model_dir.mkdir(parents=True)
            paths.bin_dir.mkdir(parents=True)
            paths.output_dir.mkdir(parents=True)
            paths.llama_source_dir.mkdir(parents=True)
            source = paths.model_dir / "model.safetensors"
            server = paths.server_exe
            quantized = paths.quantized_gguf
            converter = paths.llama_source_dir / "convert_hf_to_gguf.py"
            source.write_bytes(b"source")
            server.write_bytes(b"server")
            quantized.write_bytes(b"quantized")
            converter.write_bytes(b"converter")
            commands = [["convert", "--outtype", "f16"], ["quantize", "Q4_K_M"]]

            manifest = module.build_manifest(
                paths=paths,
                llama_release={
                    "tag_name": "b9999",
                    "target_commitish": "master",
                    "html_url": "https://github.com/ggml-org/llama.cpp/releases/tag/b9999",
                },
                commands=commands,
            )

        self.assertEqual(manifest["source_model"]["id"], "Qwen/Qwen3.5-2B")
        self.assertEqual(manifest["source_model"]["revision"], module.MODEL_REVISION)
        self.assertEqual(manifest["llama_cpp"]["release"], "b9999")
        self.assertIn("source_files", manifest["llama_cpp"])
        self.assertIn("convert_hf_to_gguf.py", manifest["llama_cpp"]["source_files"])
        self.assertIn("environment", manifest)
        self.assertIn("python", manifest["environment"])
        self.assertIn("packages", manifest["environment"])
        self.assertEqual(manifest["commands"], commands)
        self.assertIn("model.safetensors", manifest["source_model"]["files"])
        self.assertIn("qwen3.5-2b-q4_k_m.gguf", manifest["artifacts"])
        self.assertEqual(json.loads(json.dumps(manifest)), manifest)

    def test_manifest_identifies_resumed_modelscope_sdk_snapshot(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = module.PreparationPaths.from_root(Path(temp_dir))
            paths.model_dir.mkdir(parents=True)
            paths.download_dir.mkdir(parents=True)
            paths.llama_source_dir.mkdir(parents=True)
            paths.bin_dir.mkdir(parents=True)
            paths.output_dir.mkdir(parents=True)

            manifest = module.build_manifest(
                paths,
                {},
                [],
                source_transport="modelscope-sdk-snapshot-cache",
            )

        self.assertEqual(
            manifest["source_model"]["transport"],
            "modelscope-sdk-snapshot-cache",
        )

    def test_existing_final_work_dir_is_not_mutated(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "prepared"
            root.mkdir()
            marker = root / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = module.main(["--work-dir", str(root)])
            marker_contents = marker.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 2)
        self.assertIn("already exists", stderr.getvalue())
        self.assertEqual(marker_contents, "keep")

    def test_validates_resumable_modelscope_snapshot_at_pinned_revision(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = module.PreparationPaths.from_root(Path(temp_dir))
            metadata = paths.model_dir / ".git"
            metadata.mkdir(parents=True)
            (metadata / "packed-refs").write_text(
                f"{module.MODEL_REVISION} refs/remotes/origin/master\n",
                encoding="utf-8",
            )
            weight = paths.model_dir / "model.safetensors"
            weight.write_bytes(b"weights")
            (paths.model_dir / "config.json").write_text("{}", encoding="utf-8")
            (paths.model_dir / "model.safetensors.index.json").write_text(
                json.dumps({"weight_map": {"layer": weight.name}}),
                encoding="utf-8",
            )

            files = module.validate_existing_model_snapshot(paths)

        self.assertEqual(files, ["model.safetensors"])

    def test_resume_argument_uses_existing_staging_directory(self):
        module = load_module()

        args = module.parse_args(
            ["--work-dir", "qwen3.5-2b-local", "--resume-staging", ".qwen-staging"]
        )

        self.assertEqual(args.resume_staging, ".qwen-staging")


if __name__ == "__main__":
    unittest.main()
