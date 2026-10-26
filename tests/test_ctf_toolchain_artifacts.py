import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_dockerfile_restores_pinned_original_and_high_value_system_tools():
    dockerfile = (ROOT / "Dockerfile.toolchain").read_text(encoding="utf-8")
    app = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM ${TOOLCHAIN_IMAGE}" in app
    assert "python:3.12-slim-bookworm" in dockerfile
    for package in (
        "apktool",
        "binwalk",
        "chromium",
        "dnsutils",
        "ffmpeg",
        "foremost",
        "john",
        "libimage-exiftool-perl",
        "qemu-system-x86",
        "qemu-user",
        "socat",
        "sleuthkit",
        "steghide",
        "tesseract-ocr",
        "tshark",
        "tmux",
        "wabt",
        "whois",
        "gdb-multiarch",
        "gdbserver",
        "nmap",
        "sqlmap",
        "testdisk",
        "git",
        "ltrace",
        "mediainfo",
        "patchelf",
        "pngcheck",
        "poppler-utils",
        "sox",
        "strace",
        "yara",
        "zbar-tools",
    ):
        assert package in dockerfile
    assert "RADARE2_VERSION=6.2.2" in dockerfile
    assert "09234e4139bf8dfcbb7fc1fdb2519859ad516e63c19d3c27d92aaecdf463b1ad" in dockerfile
    assert "FFUF_VERSION=2.2.1" in dockerfile
    assert "86307885810d3c36ba4a3e9ba5178c2d9027bba0dd7f4ea39e39e7c972b62396" in dockerfile
    for release in ("STEGSEEK_VERSION=0.6", "GHIDRA_VERSION=12.1.4", "JADX_VERSION=1.5.6", "JDK21_VERSION=21.0.13_9", "PWNDBG_VERSION=2026.10.22", "WEBSOCAT_VERSION=1.14.1"):
        assert release in dockerfile
    for executable in ("ghidra_headless", "jadx", "multimon-ng", "pari-gp", "pwndbg", "websocat"):
        assert executable in dockerfile
    for script in ("DecompileAll.java", "DecompileFn.java"):
        assert script in dockerfile
        assert (ROOT / "deploy" / script).is_file()
        assert f"!deploy/{script}" in (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "sha256sum --check --strict" in dockerfile
    assert " bubblewrap " not in dockerfile


def test_image_and_worker_smoke_functionally_check_pinned_toolchain():
    smoke = (ROOT / "deploy" / "image-smoke.py").read_text(encoding="utf-8")
    for executable in (
        "apktool",
        "binwalk",
        "chromium",
        "ctf-browser",
        "dig",
        "foremost",
        "exiftool",
        "fls",
        "steghide",
        "john",
        "ffmpeg",
        "tesseract",
        "tshark",
        "qemu-x86_64",
        "qemu-system-x86_64",
        "socat",
        "tmux",
        "wasm2wat",
        "whois",
        "zbarimg",
        "r2",
        "ffuf",
        "yara",
        "gdb-multiarch",
        "gdbserver",
        "nmap",
        "sqlmap",
        "testdisk",
        "photorec",
        "strace",
        "ltrace",
        "patchelf",
        "pngcheck",
        "pdfinfo",
        "mediainfo",
        "sox",
        "ghidra_headless",
        "jadx",
        "gp",
        "stegseek",
        "multimon-ng",
        "pwndbg",
        "websocat",
    ):
        assert f'"{executable}"' in smoke
    for operation in (
        "angr.Project",
        "claripy.BVS",
        "LLL.reduction",
        "lief.parse",
        "owiener.attack",
        "yara.compile",
        "volatility_constants.PACKAGE_VERSION",
        "jadx-output",
        "DecompileAll.java",
        "factor(91)",
        "help vmmap",
    ):
        assert operation in smoke

    worker = (ROOT / "ctf_agent" / "solver_worker.py").read_text(encoding="utf-8")
    for check in (
        "toolchain_environment_writable",
        "toolchain_commands_present",
        "toolchain_binaries_functional",
        "toolchain_browser_functional",
        "toolchain_trace_functional",
        "toolchain_python_functional",
    ):
        assert worker.count(f'"{check}"') >= 2
    assert '"XDG_CACHE_HOME":tool_cache' in worker
    assert '("strace","-qq","-o",trace_path,"/bin/true")' in worker
    workspace = (ROOT / "ctf_agent" / "agent_workspace.py").read_text(encoding="utf-8")
    assert "HOME=$PWD/tmp/home XDG_CACHE_HOME=$PWD/tmp/cache TMPDIR=$PWD/tmp/temp" in workspace
    assert "ctf-browser --dump-dom" in workspace
    assert "qemu-system-x86_64 -accel tcg -nographic -snapshot" in workspace

    documentation = (ROOT / "docs" / "ctf-toolchain.md").read_text(encoding="utf-8")
    assert "radare2" in documentation
    assert "6.2.2" in documentation
    assert "2.2.1" in documentation
    assert "direct DNS and Internet sockets" in documentation
    assert "does not impose a solver memory, process-count or scratch-size ceiling" in documentation
    assert "CTF_SOLVER_MIN_FREE_BYTES" in documentation
    assert "127.0.0.1" in documentation
    assert "QEMU system emulation uses software TCG" in documentation
    assert "Host KVM, GPU, USB, display" in documentation
    assert "Bubblewrap is excluded" in documentation
    assert "Ghidra 12.1.4" in documentation
    assert "JADX 1.5.6" in documentation
    assert "NetworkX" in documentation


def test_python_analysis_stack_uses_compatible_exact_pins():
    requirements = (ROOT / "requirements-ctf.txt").read_text(encoding="utf-8")
    for requirement in (
        "angr==9.2.223",
        "capstone==5.0.6",
        "cysignals==1.12.6",
        "fpylll==0.6.4",
        "lief==0.17.6",
        "owiener==1.0.10",
        "pefile==2024.8.26",
        "unicorn==2.1.2",
        "volatility3==2.28.0",
        "yara-python==4.5.4",
        "z3-solver==4.13.0.0",
    ):
        assert requirement in requirements
    assert "volatility3[full]" not in requirements


def test_embedded_worker_toolchain_canary_is_valid_python():
    source = (ROOT / "ctf_agent" / "solver_worker.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    scripts = [
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "script" for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and "toolchain_python_functional" in node.value.value
        and "toolchain_browser_functional" in node.value.value
    ]
    assert len(scripts) == 1
    compile(scripts[0], "<sandbox-canary>", "exec")


def test_remote_launcher_uses_an_absolute_module_path_outside_app_workdir():
    launcher = (ROOT / "deploy" / "connect-remote").read_text(encoding="utf-8")
    assert "/app/ctf_agent/remote_client.py" in launcher
    assert "-m ctf_agent" not in launcher

    smoke = (ROOT / "deploy" / "image-smoke.py").read_text(encoding="utf-8")
    assert "cwd=temporary" in smoke
