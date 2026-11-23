"""Normalize OSPF neighbor state names emitted by vendor parsers."""

from app.schemas.event import OspfNeighborState


def parse_ospf_state(value: str) -> OspfNeighborState:
    state = value.upper()
    if state in {"2WAY", "TWOWAY"}:
        return OspfNeighborState.TWO_WAY
    return OspfNeighborState(state)
