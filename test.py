data = {"precomputed_gnr": 1, "precomputed_gm": 2}

if any(key not in data for key in ("precomputed_gnr", "precomputed_gm")):
    print("true")
