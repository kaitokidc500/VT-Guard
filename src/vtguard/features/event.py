from __future__ import annotations

import re
from pathlib import PureWindowsPath

from vtguard.data.schema import NormalizedEvent


# Only stable syntax and built-in tool names. Hostnames, users, arbitrary paths,
# source tags, and emulation identities never enter this baseline vocabulary.
BEHAVIOR_TERMS = frozenset({
    "ipconfig", "all", "route", "print", "arp", "netstat", "ano",
    "get-nettcpconnection", "get-netudpendpoint", "net", "view", "domain",
    "nltest", "dclist", "dsgetdc", "dsquery", "computer", "get-adcomputer",
    "get-aduser", "user", "adsisearcher", "objectcategory", "person",
    "samaccountname", "wevtutil", "qe", "el", "get-winevent", "get-eventlog",
    "win32_ntlogevent", "psloglist", "logname", "listlog", "security",
    "system", "application", "powershell", "cmd", "wmic",
})
KNOWN_IMAGES = frozenset({
    "ipconfig.exe", "route.exe", "arp.exe", "netstat.exe", "net.exe",
    "nltest.exe", "dsquery.exe", "wevtutil.exe", "wmic.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe", "psloglist.exe",
})
TOKEN_RE = re.compile(r"[a-z][a-z0-9_-]*", re.IGNORECASE)


def event_tokens(event: NormalizedEvent) -> frozenset[str]:
    """Feature vocabulary constrained to observable behavior at event time."""
    result: set[str] = set()
    if event.event_id is not None:
        result.add(f"event:{event.event_id}")
    if event.channel:
        lower = event.channel.lower()
        if "sysmon" in lower:
            result.add("channel:sysmon")
        elif "powershell" in lower:
            result.add("channel:powershell")
        elif "security" in lower:
            result.add("channel:security")
    if event.image:
        image = PureWindowsPath(event.image).name.lower()
        if image in KNOWN_IMAGES:
            result.add(f"image:{image}")
    for text in (event.command_line, event.script_block_text):
        if text:
            result.update(f"term:{token}" for token in TOKEN_RE.findall(text.lower())
                          if token in BEHAVIOR_TERMS)
    return frozenset(result)


def fit_vocabulary(events: list[NormalizedEvent]) -> dict[str, int]:
    tokens = sorted({token for event in events for token in event_tokens(event)})
    return {token: index for index, token in enumerate(tokens)}


def vectorize(event: NormalizedEvent, vocabulary: dict[str, int]) -> dict[int, float]:
    return {vocabulary[token]: 1.0 for token in event_tokens(event) if token in vocabulary}
