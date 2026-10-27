from probedast.canon import canonicalize_url, path_template, make_signature, infer_type, segment_type


def test_canonicalize_lowercases_host_and_drops_default_port():
    assert canonicalize_url("HTTP://Example.COM:80/a") == "http://example.com/a"
    assert canonicalize_url("https://Example.COM:443/a") == "https://example.com/a"


def test_canonicalize_sorts_query_and_drops_tracking():
    url = canonicalize_url("http://e.com/x?b=2&a=1&utm_source=newsletter")
    assert url == "http://e.com/x?a=1&b=2"


def test_canonicalize_resolves_dot_segments():
    assert canonicalize_url("http://e.com/a/./b/../c") == "http://e.com/a/c"


def test_canonicalize_drops_fragment():
    assert "#" not in canonicalize_url("http://e.com/a#section")


def test_canonicalize_is_idempotent():
    u = canonicalize_url("http://e.com/a/b/?z=1&a=2")
    assert canonicalize_url(u) == u


def test_two_equivalent_urls_map_to_one_key():
    a = canonicalize_url("http://E.com//a/../item?id=1&utm_source=x")
    b = canonicalize_url("http://e.com/item?utm_source=y&id=1")
    assert a == b


def test_path_template_collapses_integers():
    assert path_template("/item/1") == path_template("/item/2") == "/item/{int}"


def test_path_template_collapses_uuid():
    t = path_template("/order/550e8400-e29b-41d4-a716-446655440000")
    assert t == "/order/{uuid}"


def test_path_template_preserves_static_segments():
    assert path_template("/api/users/42/profile") == "/api/users/{int}/profile"


def test_segment_type_recognizes_hex_but_not_short_numbers():
    assert segment_type("deadbeefcafebabe1234") == "hex"
    assert segment_type("42") == "int"
    assert segment_type("profile") is None


def test_signature_stable_across_equivalent_endpoints():
    sig1 = make_signature("GET", "e.com", "/item/{int}", ["id"])
    sig2 = make_signature("GET", "e.com", "/item/{int}", ["id"])
    sig3 = make_signature("GET", "e.com", "/item/{int}", ["id", "verbose"])
    assert sig1 == sig2
    assert sig1 != sig3


def test_infer_type():
    assert infer_type("42") == "int"
    assert infer_type("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert infer_type("true") == "boolean"
    assert infer_type("a@b.com") == "email"
    assert infer_type("hello world") == "text"
    assert infer_type("") == "text"
