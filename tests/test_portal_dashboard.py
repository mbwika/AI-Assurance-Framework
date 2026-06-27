from pathlib import Path


def ensure_src():
    import sys

    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_portal_home_serves_built_spa_when_available():
    ensure_src()
    from aiaf.api import portal

    response = portal.portal_home()
    body = response.body.decode("utf-8")

    if portal.build_available():
        # The compiled SPA shell is served verbatim.
        assert response.status_code == 200
        assert '<div id="root">' in body
        assert "/assets/" in body
        assert "AI Assurance Framework" in body
    else:
        # Without a build, a helpful 503 hint is returned instead.
        assert response.status_code == 503
        assert "npm run build" in body


def test_missing_build_hint_mentions_build_command():
    ensure_src()
    from aiaf.api import portal

    assert "npm run build" in portal._MISSING_BUILD_HTML
    assert "src/aiaf/web/" in portal._MISSING_BUILD_HTML


def test_portal_route_is_registered_and_serves_html():
    ensure_src()
    from aiaf.api.app import app

    assert "/" in app.openapi()["paths"]
