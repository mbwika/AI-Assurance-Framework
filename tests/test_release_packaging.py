from pathlib import Path


def test_package_version_matches_project_version():
    import aiaf

    assert aiaf.__version__ == "0.2.0"


def test_dashboard_assets_exist_in_package_tree():
    from aiaf.api import portal

    assert portal.INDEX_HTML.is_file()
    assert portal.ASSETS_DIR.is_dir()
    assert any(path.suffix == ".js" for path in portal.ASSETS_DIR.iterdir())
    assert any(path.suffix == ".css" for path in portal.ASSETS_DIR.iterdir())


def test_manifest_in_exists_for_source_distribution():
    assert Path("MANIFEST.in").is_file()
