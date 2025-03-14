import json

def import_from_json(file: str) -> dict:
  with open(file) as f:
    return json.load(f)