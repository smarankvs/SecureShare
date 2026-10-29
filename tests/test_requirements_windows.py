from pathlib import Path


def test_semgrep_is_windows_compatible_in_requirements():
    requirements = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text(encoding="utf-8")

    assert 'semgrep>=' in requirements
    assert 'semgrep>=1.65.0; platform_system != "Windows"' in requirements
