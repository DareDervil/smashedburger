""" Legacy implementation using the raw API, before refactoring into CVEChat class. Kept for reference and testing during development. """

import anthropic
from anthropic.types import ToolParam
import dotenv
import json
from tools import parse_nvd_cve

_ = dotenv.load_dotenv()

client = anthropic.Anthropic()

TOOL_REGISTRY = {
    "parse_nvd_cve": parse_nvd_cve,
}

tools: list[ToolParam] = [
    {
        "name": "parse_nvd_cve",
        "description": "Query the NVD (National Vulnerability Database) API for a given CVE ID. "
        "Returns a cleaned summary including: CVE ID, published and last-modified dates, "
        "vulnerability status, and English description. For each available CVSS version "
        "(v2, v3.0, v3.1, v4.0) returns the base score, severity rating, raw vector string, "
        "and a human-readable breakdown of every CVSS metric (e.g. Attack Vector: Network, "
        "Privileges Required: None). Also includes CISA exploit data when present (exploit "
        "add date, required action, vulnerability name). Use this whenever the user asks "
        "about a specific CVE or vulnerability by ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE-ID to query, e.g. 'CVE-2021-44228'",
                }
            },
            "required": ["cve_id"],
        },
        "input_examples": [
            {
                "cve_id": "CVE-2021-44228"
            }
        ]
    }
]

messages=[
        {
            "role": "user",
            "content": "Act as a security consultant. Brief me on the details of CVE-2026-45247",
        }
    ]

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=500,
    tools=tools,
    messages=messages, # type: ignore
)

if response.stop_reason == "tool_use":
    for block in response.content:
        if block.type == "tool_use":
            print(f"Tool {block.name} with the input {block.input} was called.")
            result = TOOL_REGISTRY[block.name](**block.input) # type: ignore
            # print(f"Tool result: {result}")
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result),
                }
            ]})
    response = client.messages.create(               # call API again
        model="claude-sonnet-4-6",
        max_tokens=1000,
        tools=tools,
        messages=messages,
    )

    if response.stop_reason == "end_turn":
        for block in response.content:
            if block.type == "text":
                print(block.text)

elif response.stop_reason == "end_turn":
    for block in response.content:
        if block.type == "text":
            print(block.text)
