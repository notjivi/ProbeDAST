import pytest
from probedast.scope import Scope, OutOfScope


def test_allows_in_scope_host():
    s = Scope(hosts={"localhost"}, path_prefixes=["/"])
    assert s.allows("http://localhost/anything")


def test_rejects_other_host():
    s = Scope(hosts={"localhost"}, path_prefixes=["/"])
    assert not s.allows("http://evil.com/anything")


def test_rejects_other_scheme():
    s = Scope(hosts={"localhost"}, path_prefixes=["/"], schemes=("https",))
    assert not s.allows("http://localhost/x")


def test_host_with_explicit_port_scoping():
    s = Scope(hosts={"localhost:4280"}, path_prefixes=["/"])
    assert s.allows("http://localhost:4280/x")
    assert not s.allows("http://localhost:9999/x")


def test_path_prefix_restriction():
    s = Scope(hosts={"localhost"}, path_prefixes=["/app/"])
    assert s.allows("http://localhost/app/foo")
    assert not s.allows("http://localhost/other/foo")


def test_check_raises_out_of_scope():
    s = Scope(hosts={"localhost"}, path_prefixes=["/"])
    with pytest.raises(OutOfScope):
        s.check("http://evil.com/x")


@pytest.mark.parametrize("path", [
    "/logout", "/user/logout", "/signout", "/account/delete/5",
    "/reset-password", "/payment/checkout", "/admin/wipe",
])
def test_dangerous_paths_detected(path):
    assert Scope.is_dangerous(path)


@pytest.mark.parametrize("path", ["/item/5", "/search?q=hi", "/profile", "/api/users"])
def test_safe_paths_not_flagged(path):
    assert not Scope.is_dangerous(path)
