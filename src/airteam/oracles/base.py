"""What an oracle sees, and the interface every oracle implements."""

from typing import Protocol

from airteam.core.base import StrictModel
from airteam.core.oracles import OracleKind, OracleResult


class Observation(StrictModel):
    text: str
    """The output as the application returned it to the caller."""


class Oracle(Protocol):
    @property
    def kind(self) -> OracleKind: ...

    def evaluate(self, observation: Observation) -> OracleResult: ...
