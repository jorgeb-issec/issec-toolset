def validate_policy_json(obj):
    # simple example, extend as needed
    if not isinstance(obj, dict):
        return False, "policy must be a JSON object"
    if "id" not in obj:
        return False, "missing 'id' (FortiGate policy ID)"
    return True, ""
