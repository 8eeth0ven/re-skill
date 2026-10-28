from pathlib import Path
from typing import Any

import yaml
from defusedxml import ElementTree

from .errors import BudgetExceeded, InvalidInput
from .safety import parse_json, read_bytes


def load_yaml(data: bytes) -> Any:
    if len(data) > 16_777_216:
        raise BudgetExceeded("YAML byte budget exceeded")
    # Aliases can amplify the parsed graph or introduce cycles even with SafeLoader.
    try:
        count, depth = 0, 0
        for event in yaml.parse(data):
            count += 1
            if isinstance(event, yaml.AliasEvent):
                raise InvalidInput("YAML aliases are rejected")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if count > 100000 or depth > 48:
                raise BudgetExceeded("YAML node/depth budget exceeded")

        class UniqueLoader(yaml.SafeLoader):
            pass

        def mapping(loader, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key in result:
                    raise InvalidInput("YAML keys must be unique strings")
                result[key] = loader.construct_object(value_node, deep=deep)
            return result

        UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        value = yaml.load(data, Loader=UniqueLoader)
        # Enforce finite primitive JSON shape and rule out constructed timestamps.
        import json
        return parse_json(json.dumps(value, allow_nan=False))
    except (yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        raise InvalidInput(f"Malformed/unsupported YAML: {type(exc).__name__}") from exc


def structured(path: Path, limit: int = 16_777_216) -> Any:
    data = read_bytes(path, limit)
    return load_yaml(data) if path.suffix.lower() in (".yaml", ".yml") else parse_json(data)


def xml(data: bytes):
    if len(data) > 16_777_216:
        raise BudgetExceeded("XML byte budget exceeded")
    try:
        root = ElementTree.fromstring(data)
    except Exception as exc:
        raise InvalidInput(f"Malformed/unsafe XML: {type(exc).__name__}") from exc
    count, stack = 0, [(root, 0)]
    while stack:
        element, depth = stack.pop()
        count += 1
        if count > 100000 or depth > 48:
            raise BudgetExceeded("XML node/depth budget exceeded")
        stack.extend((child, depth + 1) for child in element)
    return root
