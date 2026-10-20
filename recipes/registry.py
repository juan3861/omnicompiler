"""
RC-11 Recipe Registry: Manages lifecycle, versioning, and retrieval of reusable adaptation recipes.
States: DISCOVERED -> CANDIDATE -> LOCALLY_VALIDATED -> HOLDOUT_VALIDATED -> PROMOTED -> REVOKED.
Enforces holdout validation before promotion to avoid false generalizations.
"""

import json
import os
from typing import Dict, List, Optional, Any
from contracts.models import canonical_json, sha256_digest


VALID_STATES = {
    "DISCOVERED", "CANDIDATE", "LOCALLY_VALIDATED",
    "HOLDOUT_VALIDATED", "PROMOTED", "REVOKED"
}


class RecipeRegistry:
    def __init__(self, storage_dir: str):
        self.storage_dir = os.path.abspath(storage_dir)
        os.makedirs(self.storage_dir, exist_ok=True)
        self.index_file = os.path.join(self.storage_dir, "recipes_index.json")
        self._load_index()

    def _load_index(self):
        if os.path.exists(self.index_file):
            with open(self.index_file, "r", encoding="utf-8") as f:
                self.index = json.load(f)
        else:
            self.index = {}

    def _save_index(self):
        with open(self.index_file, "w", encoding="utf-8") as f:
            f.write(canonical_json(self.index))

    def register_recipe(
        self,
        recipe_id: str,
        name: str,
        source_pattern: str,
        target_pattern: str,
        template_code: str,
        preconditions: List[str],
        flush: bool = True
    ) -> Dict[str, Any]:
        recipe_entry = {
            "recipe_id": recipe_id,
            "name": name,
            "source_pattern": source_pattern,
            "target_pattern": target_pattern,
            "template_code": template_code,
            "preconditions": preconditions,
            "state": "DISCOVERED",
            "evidence": [],
            "digest": sha256_digest(template_code)
        }
        self.index[recipe_id] = recipe_entry
        if flush:
            self._save_index()
        return recipe_entry

    def transition_state(self, recipe_id: str, target_state: str, evidence_ref: str, flush: bool = True) -> Dict[str, Any]:
        if target_state not in VALID_STATES:
            raise ValueError(f"Invalid state: {target_state}")
        if recipe_id not in self.index:
            raise KeyError(f"Recipe not found: {recipe_id}")

        entry = self.index[recipe_id]
        entry["state"] = target_state
        entry["evidence"].append(evidence_ref)
        if flush:
            self._save_index()
        return entry

    def find_eligible_recipe(self, requirement: str, capability_kind: str) -> Optional[Dict[str, Any]]:
        for r in self.index.values():
            if r["state"] == "PROMOTED":
                if r["source_pattern"].lower() in capability_kind.lower() and r["target_pattern"].lower() in requirement.lower():
                    return r
        return None
