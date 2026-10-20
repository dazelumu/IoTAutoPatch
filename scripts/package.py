"""Create the manually transferable source package without local test dependencies."""
from pathlib import Path
import ast
import hashlib
import tomllib
import zipfile
import argparse


def collect_files(root: Path) -> list[Path]:
    """Return source, curated documentation, and formal test fixtures."""
    files = [root / name for name in ("AGENTS.md", "README.md", "VALIDATION.md",
                                      "pyproject.toml", "requirements.txt",
                                      ".gitignore", ".gitattributes")]
    files.extend(sorted((root / "docs").glob("*.md")))
    files.extend(sorted((root / "docs" / "releases").glob("*.md")))
    # Curated case narratives, PoCs, templates, patch sources, and sanitized results.
    # Local archive/ payloads remain intentionally excluded.
    for path in sorted((root / "cases").rglob("*")):
        if not path.is_file() or "archive" in path.relative_to(root / "cases").parts:
            continue
        if path.suffix in {".md", ".py", ".c"} or path.name.endswith(".example.yaml") \
                or (path.parent.name == "results" and path.suffix == ".json"):
            files.append(path)
    for directory in ("repair_tool", "tests", "scripts"):
        for pattern in ("*.py", "*.sh"):
            files.extend(sorted((root / directory).rglob(pattern)))
    # Formal tests read external diagnostic fixtures from tests/fixtures.
    # Python-only collection used to omit those files and make the deployed
    # test suite fail before it could exercise diagnostics normalization.
    for pattern in ("*.json", "*.yaml", "*.yml"):
        files.extend(sorted((root / "tests" / "fixtures").rglob(pattern)))
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="Check the current version's archive against current source")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    output = root / "dist"
    output.mkdir(exist_ok=True)
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    tree = ast.parse((root / "repair_tool/__init__.py").read_text(encoding="utf-8"))
    module_version = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets))
    if module_version != version:
        raise ValueError("pyproject.toml and repair_tool.__version__ must match before packaging")
    archive = output / f"project-vuln-repair-{version}.zip"
    checksum = archive.with_suffix(".zip.sha256")
    if args.check and not archive.is_file():
        parser.error(f"release archive does not exist: {archive.name}")
    if args.check and not checksum.is_file():
        parser.error(f"release checksum does not exist: {checksum.name}")
    files = collect_files(root)
    if not args.check:
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            for path in files:
                handle.write(path, "project-vuln-repair/" + path.relative_to(root).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if not args.check:
        checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    if checksum.read_text(encoding="ascii").split() != [digest, archive.name]:
        raise ValueError("Release checksum does not match the archive")
    with zipfile.ZipFile(archive) as handle:
        expected = {"project-vuln-repair/" + path.relative_to(root).as_posix(): path
                    for path in files}
        if len(handle.namelist()) != len(expected) or set(handle.namelist()) != set(expected):
            raise ValueError("Release file list or fixed root directory differs from current source")
        if handle.testzip() is not None:
            raise ValueError("Release CRC check failed")
        for name, path in expected.items():
            if handle.read(name) != path.read_bytes():
                raise ValueError(f"Release is stale: {name}")
    print(f"Package: {archive}\nFiles: {len(files)}\nSHA256: {digest}")


if __name__ == "__main__":
    main()
