from app.core.targets import detect_target, modules_for_target


def test_target_detection():
    assert detect_target("analyst@example.org")[0] == "email"
    assert detect_target("203.0.113.10")[0] == "ip"
    assert detect_target("192.0.2.0/24") == ("cidr", "192.0.2.0/24")
    assert detect_target("example.org")[0] == "domain"
    assert detect_target("https://example.org/path")[0] == "url"
    assert detect_target("@sample_user")[0] == "username"
    assert "domain" in modules_for_target("domain")


def test_default_modules_are_supported_by_stateless_api():
    from app.api.stateless_routes import SUPPORTED_MODULES
    for target_type in ("email", "username", "phone", "domain", "url", "ip", "cidr"):
        assert set(modules_for_target(target_type)).intersection(SUPPORTED_MODULES)


def test_credential_and_file_workflows_are_not_recommended():
    from app.api.stateless_routes import SUPPORTED_MODULES
    assert "credential" not in SUPPORTED_MODULES
    assert "image" not in SUPPORTED_MODULES
    assert "document" not in SUPPORTED_MODULES
