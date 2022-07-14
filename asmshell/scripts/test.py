import subprocess
import sys


def test_unittest() -> None:
    completed = subprocess.run(
        ["python", "-u", "-m", "unittest", "discover", "-v"]
    )
    sys.exit(completed.returncode)


def test_coverage() -> None:
    completed = subprocess.run(["coverage", "run", "-m", "unittest"])
    subprocess.run(["coverage", "html"])
    sys.exit(completed.returncode)
