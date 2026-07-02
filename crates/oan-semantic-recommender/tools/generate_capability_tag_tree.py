#!/usr/bin/env python3
"""Generate OAN capability tag tree data from AgentTaxo-9K.

The generated tree is intentionally independent from OAN authorized domains.
AgentTaxo top-level folders become parent capability tags. JSON `Tags` values
under each folder become child capability tags after conservative cleanup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


def clean_label(value: object) -> str:
    label = re.sub(r"\s+", " ", str(value).strip())
    label = label.strip(".,;:/\\|")
    return label


def tag_id(label: str) -> str:
    value = label.lower().replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    value = re.sub(r"-+", "-", value)
    return value


def valid_label(label: str) -> bool:
    if not label:
        return False
    if len(label) > 80:
        return False
    if len(label) == 1 and not label.isdigit():
        return False
    if not re.search(r"[A-Za-z0-9]", label):
        return False
    return True


def collect(
    agent_taxo_root: Path,
) -> tuple[dict[str, Counter[str]], dict[str, int], dict[str, set[str]], dict[str, str]]:
    parent_tags: dict[str, Counter[str]] = defaultdict(Counter)
    parent_records: dict[str, int] = defaultdict(int)
    tag_parents: dict[str, set[str]] = defaultdict(set)
    tag_labels: dict[str, str] = {}

    for split in ("trainingSet", "testSet"):
        base = agent_taxo_root / split
        if not base.is_dir():
            raise FileNotFoundError(f"missing AgentTaxo split: {base}")

        for json_file in base.rglob("*.json"):
            relative = json_file.relative_to(base)
            if len(relative.parts) < 2:
                continue
            parent_label = clean_label(relative.parts[0])
            if not valid_label(parent_label):
                continue

            data = json.loads(json_file.read_text(encoding="utf-8"))
            tags = data.get("Tags", [])
            if not isinstance(tags, list):
                continue

            parent_records[parent_label] += 1
            seen_in_file: set[str] = set()
            for raw_tag in tags:
                label = clean_label(raw_tag)
                if not valid_label(label):
                    continue
                tag_key = tag_id(label)
                if not tag_key or tag_key == tag_id(parent_label):
                    continue
                if tag_key in seen_in_file:
                    continue
                seen_in_file.add(tag_key)
                parent_tags[parent_label][label] += 1
                tag_parents[tag_key].add(parent_label)
                tag_labels.setdefault(tag_key, label)

    return parent_tags, parent_records, tag_parents, tag_labels


def build_tree(
    parent_tags: dict[str, Counter[str]],
    parent_records: dict[str, int],
    tag_parents: dict[str, set[str]],
    tag_labels: dict[str, str],
    min_count: int,
    cross_parent_threshold: int,
) -> dict:
    used_parent_ids: Counter[str] = Counter()
    nodes = []
    cross_cutting_counts: Counter[str] = Counter()

    for parent_label in sorted(parent_tags, key=lambda item: tag_id(item)):
        base_parent_id = tag_id(parent_label)
        used_parent_ids[base_parent_id] += 1
        parent_id = (
            base_parent_id
            if used_parent_ids[base_parent_id] == 1
            else f"{base_parent_id}-{used_parent_ids[base_parent_id]}"
        )

        child_id_counts: Counter[str] = Counter()
        children = []
        for child_label, count in sorted(
            parent_tags[parent_label].items(),
            key=lambda item: (-item[1], tag_id(item[0]), item[0]),
        ):
            if count < min_count:
                continue
            base_child_id = tag_id(child_label)
            if not base_child_id:
                continue
            if len(tag_parents.get(base_child_id, set())) >= cross_parent_threshold:
                cross_cutting_counts[base_child_id] += count
                continue
            child_id_counts[base_child_id] += 1
            child_id = (
                base_child_id
                if child_id_counts[base_child_id] == 1
                else f"{base_child_id}-{child_id_counts[base_child_id]}"
            )
            children.append(
                {
                    "id": f"{parent_id}.{child_id}",
                    "label": child_label,
                    "sourceCount": count,
                    "aliases": [child_label],
                }
            )

        nodes.append(
            {
                "id": parent_id,
                "label": parent_label,
                "sourceRecordCount": parent_records.get(parent_label, 0),
                "aliases": [parent_label],
                "children": children,
            }
        )

    if cross_cutting_counts:
        cross_children = []
        for child_key, count in sorted(
            cross_cutting_counts.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            label = tag_labels.get(child_key, child_key.replace("-", " ").title())
            cross_children.append(
                {
                    "id": f"cross-cutting.{child_key}",
                    "label": label,
                    "sourceCount": count,
                    "sourceParentCount": len(tag_parents.get(child_key, set())),
                    "aliases": [label],
                }
            )
        nodes.append(
            {
                "id": "cross-cutting",
                "label": "Cross-Cutting",
                "sourceRecordCount": sum(cross_cutting_counts.values()),
                "aliases": ["Cross-Cutting", "Common"],
                "children": cross_children,
            }
        )

    payload = {
        "version": 1,
        "source": {
            "name": "AgentTaxo-9K",
            "license": "ODC-ODbL-1.0",
            "attribution": "Derived from AgentTaxo-9K by CAICT/Jinliang Xu.",
            "splits": ["trainingSet", "testSet"],
        },
        "cleanup": {
            "minChildSourceCount": min_count,
            "crossParentThreshold": cross_parent_threshold,
            "dropsEmptyLabels": True,
            "dropsOverlongLabels": True,
            "dropsParentSelfTags": True,
            "deduplicatesTagsWithinEachRecord": True,
            "movesBroadTagsToCrossCutting": True,
        },
        "tags": nodes,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["snapshotHash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-taxo-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--min-count", default=5, type=int)
    parser.add_argument("--cross-parent-threshold", default=20, type=int)
    args = parser.parse_args()

    parent_tags, parent_records, tag_parents, tag_labels = collect(args.agent_taxo_root)
    payload = build_tree(
        parent_tags,
        parent_records,
        tag_parents,
        tag_labels,
        args.min_count,
        args.cross_parent_threshold,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    child_count = sum(len(node["children"]) for node in payload["tags"])
    print(
        f"wrote {args.out} with {len(payload['tags'])} parent tags and {child_count} child tags"
    )


if __name__ == "__main__":
    main()
