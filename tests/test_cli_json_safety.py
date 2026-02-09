from __future__ import annotations


def _import_cli_module():
    try:
        from src.core import bean_vuln_cli as cli  # type: ignore
        return cli
    except Exception:
        import core.bean_vuln_cli as cli  # type: ignore

        return cli


def test_sanitize_for_json_breaks_circular_references():
    cli = _import_cli_module()

    a = []
    a.append(a)
    sanitized = cli.sanitize_for_json(a)

    assert isinstance(sanitized, list)
    assert sanitized == ["[circular_reference]"]


def test_sanitize_for_json_coerces_non_string_dict_keys():
    cli = _import_cli_module()

    obj = {0: "zero", 1: {"nested": True}}
    sanitized = cli.sanitize_for_json(obj)

    assert "0" in sanitized and "1" in sanitized
    assert 0 not in sanitized and 1 not in sanitized


def test_safe_json_dumps_handles_nested_structures_and_keys():
    cli = _import_cli_module()

    payload = {
        "prototypes": {0: [1.0, 2.0], 1: [3.0, 4.0]},
        "meta": {"ok": True},
    }
    encoded = cli.safe_json_dumps(payload, indent=2, sort_keys=True)

    assert '"0"' in encoded
    assert '"1"' in encoded
    assert '"prototypes"' in encoded

