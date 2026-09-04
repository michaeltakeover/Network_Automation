"""
Maps each assessment question to the relevant IoT security standard/regulation.
Kept as static data since these mappings are a design/methodology decision,
not something derived at runtime.
"""

# This means: a hardcoded list mapping each of the four questionnaire
# questions to the real-world security standard or regulation it's based
# on, along with the specific clause/provision that justifies it. Since
# these mappings represent a deliberate design decision (not something that
# changes based on live data), they're just kept as a plain Python list
# rather than being calculated or fetched from anywhere.
STANDARDS_MAP = [
    {
        "question": "Automatic Firmware Updates",
        "standard": "ETSI EN 303 645",
        "clause": "Provision 5.3 — Keep software updated",
    },
    {
        "question": "Strong Authentication",
        "standard": "NISTIR 8259 / ETSI EN 303 645",
        "clause": "No universal default passwords (5.1)",
    },
    {
        "question": "Encryption",
        "standard": "ETSI EN 303 645",
        "clause": "Provision 5.4 — Securely store sensitive security parameters",
    },
    {
        "question": "Long-Term Vendor Support",
        "standard": "UK PSTI Act 2022",
        "clause": "Minimum security update period disclosure",
    },
]


def load_standards():
    # This means: just hand back the static list defined above. It's wrapped
    # in a function (rather than importing STANDARDS_MAP directly everywhere)
    # so that if this ever needs to load from a database or file in the
    # future, only this one function would need to change.
    return STANDARDS_MAP