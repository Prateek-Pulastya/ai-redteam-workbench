"""Schema oracle: the output breaks the response contract the application promises.

Positive when the output is not JSON, or is JSON that fails the contract model
(missing or extra fields, wrong types, values outside an allowlist). Make the
contract strict (``extra="forbid"``) so unexpected fields count as violations.
"""

from pydantic import BaseModel, ValidationError

from airteam.core.oracles import OracleKind, OracleResult
from airteam.oracles.base import Observation


class SchemaOracle:
    kind = OracleKind.SCHEMA

    def __init__(self, contract: type[BaseModel]) -> None:
        self.contract = contract

    def evaluate(self, observation: Observation) -> OracleResult:
        name = self.contract.__name__
        try:
            self.contract.model_validate_json(observation.text)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "<root>"
            return OracleResult(
                oracle=self.kind,
                positive=True,
                reason=f"output violates {name}: {exc.error_count()} error(s), "
                f"first at {where}: {first['msg']}",
            )
        return OracleResult(oracle=self.kind, positive=False, reason=f"output conforms to {name}")
