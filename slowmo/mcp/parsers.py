"""
Output parsers for tenet CLI text/tabular output → structured JSON.
"""

import re


def parse_trace_info(output: str) -> dict:
    """Parse tenet's startup output into structured metadata."""
    info = {}
    for line in output.split("\n"):
        line = line.strip()
        if "Magic:" in line:
            info["magic"] = line.split(":", 1)[1].strip()
        elif "Version:" in line:
            info["version"] = line.split(":", 1)[1].strip()
        elif "Arch:" in line:
            info["arch"] = line.split(":", 1)[1].strip()
        elif "GPR count:" in line:
            info["gpr_count"] = int(line.split(":", 1)[1].strip())
        elif "Module:" in line and "module_name" not in info:
            info["module_name"] = line.split(":", 1)[1].strip()
        elif "Base:" in line:
            info["module_base"] = line.split(":", 1)[1].strip()
        elif "Slide:" in line:
            info["module_slide"] = line.split(":", 1)[1].strip()
        elif "Range:" in line:
            info["address_range"] = line.split(":", 1)[1].strip()
        elif "File size:" in line:
            info["file_size"] = line.split(":", 1)[1].strip()
        elif "Flags:" in line:
            info["flags"] = line.split(":", 1)[1].strip()
        elif "instructions" in line.lower() and "Done." in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "instructions," and i > 0:
                    try:
                        info["instruction_count"] = int(parts[i - 1])
                    except ValueError:
                        pass
                elif p == "anchors," and i > 0:
                    try:
                        info["anchor_count"] = int(parts[i - 1])
                    except ValueError:
                        pass
        elif "Loaded" in line and "distinct PCs" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "distinct" and i > 0:
                    try:
                        info["distinct_pcs"] = int(parts[i - 1])
                    except ValueError:
                        pass
    return info


def parse_pattern_output(output: str) -> dict:
    """Parse tenet --pattern tabular output into structured JSON."""
    matches = []
    in_table = False
    for line in output.split("\n"):
        line = line.strip()
        if "CATEGORY" in line and "CONFIDENCE" in line:
            in_table = True
            continue
        if in_table and line and not line.startswith("["):
            parts = line.split()
            if len(parts) >= 5:
                category = parts[0]
                confidence = parts[1]
                match_entry = {
                    "category": category,
                    "confidence": confidence,
                    "raw": line
                }
                for j, p in enumerate(parts):
                    if p.startswith("#"):
                        try:
                            match_entry["start_inst_id"] = int(p.lstrip("#"))
                        except ValueError:
                            pass
                    if p == "-" and j + 1 < len(parts) and parts[j + 1].startswith("#"):
                        try:
                            match_entry["end_inst_id"] = int(parts[j + 1].lstrip("#"))
                        except ValueError:
                            pass
                if len(parts) > 4:
                    match_entry["pattern_name"] = parts[-1]
                matches.append(match_entry)
        elif line.startswith("[patterns]"):
            pass

    return {"matches": matches, "total": len(matches)}


def parse_strings_output(output: str) -> dict:
    """Parse tenet --strings tabular output into structured JSON."""
    strings = []
    in_table = False
    for line in output.split("\n"):
        stripped = line.strip()
        if "ADDR" in stripped and "CONTENT" in stripped:
            in_table = True
            continue
        if in_table and stripped:
            parts = stripped.split('"')
            if len(parts) >= 2:
                content = parts[1] if len(parts) > 1 else ""
                meta = parts[0].split()
                entry = {
                    "content": content,
                    "addr": meta[0] if len(meta) > 0 else "",
                    "length": int(meta[1]) if len(meta) > 1 else 0,
                    "encoding": meta[2] if len(meta) > 2 else "",
                    "refs": int(meta[3]) if len(meta) > 3 else 0,
                }
                strings.append(entry)

    return {"strings": strings, "total": len(strings)}


def parse_constants_output(output: str) -> dict:
    """Parse tenet --constants tabular output into structured JSON."""
    identified = []
    all_constants = []
    by_algorithm = {}
    total = 0
    identified_count = 0

    section = None
    for line in output.split("\n"):
        stripped = line.strip()

        if stripped.startswith("[constants]"):
            m = re.search(r"Found (\d+) materialized constants \((\d+) identified", stripped)
            if m:
                total = int(m.group(1))
                identified_count = int(m.group(2))
            continue

        if "=== Identified Algorithm Constants ===" in stripped:
            section = "identified"
            continue
        elif "=== Summary by Algorithm ===" in stripped:
            section = "summary"
            continue
        elif "=== All Materialized Constants" in stripped:
            section = "all"
            continue

        if section == "identified" and stripped and not stripped.startswith("VALUE"):
            parts = stripped.split()
            if len(parts) >= 5 and parts[0].startswith("0x"):
                entry = {
                    "value": parts[0],
                    "register": parts[1],
                    "algorithm": parts[2],
                    "name": parts[3],
                    "inst_range": parts[4] if len(parts) > 4 else ""
                }
                identified.append(entry)

        elif section == "summary" and stripped and ":" in stripped:
            algo_parts = stripped.split(":")
            if len(algo_parts) == 2:
                algo_name = algo_parts[0].strip()
                count_str = algo_parts[1].strip().split()[0]
                try:
                    by_algorithm[algo_name] = int(count_str)
                except ValueError:
                    pass

        elif section == "all" and stripped and not stripped.startswith("VALUE") and not stripped.startswith("..."):
            parts = stripped.split()
            if len(parts) >= 5 and parts[0].startswith("0x"):
                known = " ".join(parts[5:]) if len(parts) > 5 else "-"
                entry = {
                    "value": parts[0],
                    "register": parts[1],
                    "parts": int(parts[2]) if parts[2].isdigit() else 0,
                    "inst_range": f"{parts[3]}-{parts[4]}" if len(parts) > 4 else "",
                    "known_as": known if known != "-" else None
                }
                all_constants.append(entry)

    return {
        "total": total,
        "identified_count": identified_count,
        "identified_constants": identified,
        "by_algorithm": by_algorithm,
        "constants": all_constants
    }


def extract_json_blocks(text: str) -> list:
    """Extract complete JSON object blocks from text output."""
    blocks = []
    current = []
    depth = 0
    for line in text.split("\n"):
        if depth == 0 and "{" in line:
            current = [line]
            depth = line.count("{") - line.count("}")
        elif depth > 0:
            current.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                blocks.append("\n".join(current))
                current = []
                depth = 0
    return blocks
