# Points added when an indicator triggers
WEIGHTS = {
    "sanctioned": 80,
    "known_malicious": 75,
    "mixer_exposure": 40,
    "rapid_pass_through": 25,
    "new_wallet_burst": 15,
}

# Points when the analyzed address itself is on a threat list
TARGET_LISTED_POINTS = {
    "sanctioned": 100,
    "malicious": 90,
    "mixer": 70,
}

SEVERITY = {
    "sanctioned": "high",
    "known_malicious": "high",
    "target_listed": "high",
    "mixer_exposure": "medium",
    "rapid_pass_through": "medium",
    "new_wallet_burst": "low",
}

TITLES = {
    "sanctioned": "Sanctioned address contact",
    "known_malicious": "Known malicious contact",
    "target_listed": "Listed threat address",
    "mixer_exposure": "Mixer exposure",
    "rapid_pass_through": "Rapid pass-through",
    "new_wallet_burst": "New wallet burst",
}

FLAG_LABELS = {  # matches the flag names the dashboard colors
    "sanctioned": "Sanctioned",
    "known_malicious": "Malicious",
    "target_listed": "Listed",
    "mixer_exposure": "Mixer",
    "rapid_pass_through": "Pass-through",
    "new_wallet_burst": "Burst",
}

# Rating bands
LOW_MAX = 39
MEDIUM_MAX = 69

# Detector settings
MIN_TX_REQUIRED = 1
PASS_THROUGH_WINDOW_SEC = 3600       # forwarded within 1 hour
PASS_THROUGH_MIN_RATIO = 0.8         # at least 80% of the value forwarded
BURST_WINDOW_SEC = 2 * 3600          # first 2 hours of activity
BURST_MIN_TX = 10                    # 10+ transactions in that window
NEW_WALLET_MAX_AGE_SEC = 7 * 86400   # "new" means active for 7 days or less

MAX_EVIDENCE = 10                    # evidence hashes shown per finding
MAX_GRAPH_NODES = 30


def rating_for(score: int) -> str:
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"