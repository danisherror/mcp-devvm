import pytest

from common.canonical import NonCanonicalValue, canonicalize, content_hash, proposal_hash


def test_key_order_independent():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonicalize(a) == canonicalize(b)
    assert content_hash(a) == content_hash(b)


def test_lists_are_never_joined_into_strings():
    # ["rm", "-rf", "/tmp/a b"] and ["rm", "-rf", "/tmp/a", "b"] must not collide.
    a = {"argv": ["rm", "-rf", "/tmp/a b"]}
    b = {"argv": ["rm", "-rf", "/tmp/a", "b"]}
    assert content_hash(a) != content_hash(b)


def test_floats_rejected():
    with pytest.raises(NonCanonicalValue):
        canonicalize({"x": 1.5})


def test_none_vs_absent_key_distinguishable():
    a = {"x": None}
    b = {}
    assert content_hash(a) != content_hash(b)


def test_nfc_normalization_makes_equivalent_forms_hash_equal():
    combining = {"name": "café"}  # e + combining acute accent
    precomposed = {"name": "café"}  # precomposed é
    assert content_hash(combining) == content_hash(precomposed)


def test_nested_structures():
    obj = {"a": [1, 2, {"b": "x"}], "c": {"d": [3, 4]}}
    assert isinstance(canonicalize(obj), bytes)
    # Re-encoding the same structure is deterministic.
    assert canonicalize(obj) == canonicalize(dict(reversed(list(obj.items()))))


def test_proposal_hash_changes_with_manifest_version():
    kwargs = dict(
        v=1,
        principal="usr_123",
        target_id="dev-vm-01",
        operation_id="git.checkout",
        manifest_hash="abc123",
        params={"repo": "api", "branch": "main"},
        preconditions={"git.head_sha": "a1b2"},
    )
    h1 = proposal_hash(manifest_version=3, **kwargs)
    h2 = proposal_hash(manifest_version=4, **kwargs)
    assert h1 != h2  # a redeploy (version bump) must invalidate the hash


def test_proposal_hash_changes_with_manifest_hash():
    kwargs = dict(
        v=1,
        principal="usr_123",
        target_id="dev-vm-01",
        operation_id="git.checkout",
        manifest_version=3,
        params={"repo": "api", "branch": "main"},
        preconditions={"git.head_sha": "a1b2"},
    )
    h1 = proposal_hash(manifest_hash="abc123", **kwargs)
    h2 = proposal_hash(manifest_hash="def456", **kwargs)
    assert h1 != h2


def test_proposal_hash_stable_and_reproducible():
    kwargs = dict(
        v=1,
        principal="usr_123",
        target_id="dev-vm-01",
        operation_id="git.checkout",
        manifest_version=3,
        manifest_hash="abc123",
        params={"repo": "api", "branch": "main"},
        preconditions={"git.head_sha": "a1b2"},
    )
    assert proposal_hash(**kwargs) == proposal_hash(**kwargs)
