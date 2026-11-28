from dataclasses import dataclass
import yaml

# Define the fields that every detection rule must contain
REQUIRED = [
    "name", "event_type", "group_by", "threshold",
    "window_seconds", "severity", "mitre"
]


# Define the structure of a detection rule
@dataclass
class Rule:
    name: str
    event_type: str
    group_by: str
    threshold: int
    window_seconds: int
    severity: str
    mitre: str
    description: str = ""


# Load a YAML file and convert it into a Rule object
def load_rule(path):

    # Open the YAML file and read its content
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # Check that the YAML content is a dictionary
    if not isinstance(data, dict):
        raise ValueError(f"Rule file {path} is empty or not valid YAML")

    # Find any required fields missing from the YAML file
    missing = [key for key in REQUIRED if key not in data]

    # Stop loading if a required field is missing
    if missing:
        raise ValueError(f"Rule file {path} is missing: {', '.join(missing)}")

    # Create a Rule object using the YAML values
    return Rule(
        name=data["name"],
        event_type=data["event_type"],
        group_by=data["group_by"],
        threshold=int(data["threshold"]),
        window_seconds=int(data["window_seconds"]),
        severity=data["severity"],
        mitre=data["mitre"],
        description=data.get("description", ""),
    )