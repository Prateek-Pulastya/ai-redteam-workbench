"""Variants: target builds with a declared set of enabled controls (spec §0A.11)."""

from airteam.core.base import Slug, StrictModel


class Variant(StrictModel):
    name: Slug
    controls_enabled: frozenset[Slug] = frozenset()

    def has_control(self, control_id: str) -> bool:
        return control_id in self.controls_enabled
