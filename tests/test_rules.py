import pytest
from pyhunter.detection.rules import load_rule


# Test that a valid YAML rule is loaded correctly
def test_load_valid_rule():

    # Load the SSH brute-force rule
    rule = load_rule("rules/ssh_bruteforce.yml")

    # Check that the loaded rule has the expected values
    assert rule.name == "ssh_bruteforce"
    assert rule.threshold == 10
    assert rule.window_seconds == 60
    assert rule.mitre == "T1110"


# Test that loading a rule with missing fields raises an error
def test_missing_field_raises(tmp_path):

    # Create a temporary YAML file for this test
    bad = tmp_path / "bad.yml"

    # Write an incomplete rule into the temporary file
    bad.write_text("name: broken\nthreshold: 5\n")

    # Verify that load_rule() raises a ValueError
    with pytest.raises(ValueError):
        load_rule(str(bad))