import subprocess


def test_unittest() -> None:
    subprocess.run(["python", "-u", "-m", "unittest", "discover", "-v"])


def test_coverage() -> None:
    subprocess.run(["coverage", "run", "-m", "unittest"])
    subprocess.run(["coverage", "html"])
