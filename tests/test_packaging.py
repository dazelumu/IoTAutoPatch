"""Release consistency checks use an isolated package, never the real dist."""
from pathlib import Path
import copy
import re
import tomllib
import zipfile

import pytest
import yaml

from scripts import package


@pytest.fixture
def release(tmp_path, monkeypatch):
    script_source = Path(package.__file__).read_bytes()
    for name in ("AGENTS.md", "README.md", "VALIDATION.md", "requirements.txt",
                 ".gitignore", ".gitattributes"):
        (tmp_path / name).write_text("fixture\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.1"\n')
    for name in ("repair_tool", "tests", "scripts"):
        (tmp_path / name).mkdir()
    (tmp_path / "repair_tool/__init__.py").write_text('__version__ = "0.2.1"\n')
    script = tmp_path / "scripts/package.py"
    script.write_bytes(script_source)
    monkeypatch.setattr(package, "__file__", str(script))
    package.main([])
    return tmp_path


def test_release_matches_current_source_and_excludes_credentials(release):
    (release / "config.yaml").write_text("model: {api_key: fixture-secret}\n")
    package.main(["--check"])
    with zipfile.ZipFile(release / "dist/project-vuln-repair-0.2.1.zip") as archive:
        assert {name.split('/')[0] for name in archive.namelist()} == {"project-vuln-repair"}
        assert "project-vuln-repair/config.yaml" not in archive.namelist()


def test_release_check_rejects_stale_source(release):
    (release / "README.md").write_text("new instructions\n")
    with pytest.raises(ValueError, match="Release is stale"):
        package.main(["--check"])


def test_release_check_rejects_bad_checksum(release):
    checksum = release / "dist/project-vuln-repair-0.2.1.zip.sha256"
    checksum.write_text("0" * 64 + "  project-vuln-repair-0.2.1.zip\n")
    with pytest.raises(ValueError, match="checksum"):
        package.main(["--check"])


@pytest.mark.parametrize("missing, message", [
    ("project-vuln-repair-0.2.1.zip", "release archive does not exist"),
    ("project-vuln-repair-0.2.1.zip.sha256",
     "release checksum does not exist"),
])
def test_release_check_reports_missing_artifact(release, missing, message,
                                                capsys):
    (release / "dist" / missing).unlink()
    with pytest.raises(SystemExit) as caught:
        package.main(["--check"])
    assert caught.value.code == 2
    assert message in capsys.readouterr().err


def test_readme_first_install_uses_current_archive():
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    readme = (root / "README.md").read_text(encoding="utf-8")
    install = readme.split("## Ubuntu 快速开始", 1)[1].split("### 检查就绪状态", 1)[0]
    archive = f"project-vuln-repair-{version}.zip"
    assert f"sha256sum -c {archive}.sha256" in install
    assert f"unzip {archive} -d ~/tools" in install


def test_operations_configuration_examples_load(tmp_path, monkeypatch):
    """Operations documents the current firmware-first product scope."""
    from repair_tool.config import load_config

    root = Path(__file__).resolve().parents[1]
    operations = (root / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    examples = [yaml.safe_load(block) for block in re.findall(r"```yaml\n(.*?)\n```", operations, re.S)]
    global_example = next(item for item in examples
                          if isinstance(item, dict) and set(item) == {"model"}
                          and item["model"].get("base_url") == "https://model-provider.example/v1")
    global_path = tmp_path / "config.yaml"
    global_path.write_text(yaml.safe_dump(global_example), encoding="utf-8")
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_path))
    poc = tmp_path / "poc.py"
    poc.write_text("# read-only example input\n", encoding="utf-8")
    pytest.importorskip("fcntl", reason="Firmware case validation imports Linux session control")
    example = next(item for item in examples if isinstance(item, dict)
                   and item.get("firmware", {}).get("rootfs") == "/absolute/path/to/rootfs")
    case = copy.deepcopy(example)
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/httpd").write_bytes(b"fixture")
    case["firmware"]["rootfs"] = str(rootfs)
    case["poc"]["path"] = str(poc)
    case["output"]["directory"] = str(tmp_path / "results")
    case_path = tmp_path / "case.yaml"
    case_path.write_text(yaml.safe_dump(case), encoding="utf-8")
    cfg = load_config(case_path)
    assert cfg["firmware"]["mode"] is True
    assert cfg["model"]["base_url"] == global_example["model"]["base_url"]
    assert cfg["model"]["api_key"] is None
