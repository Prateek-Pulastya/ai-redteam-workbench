from hypothesis import given
from hypothesis import strategies as st

from airteam.core.evidence import GENESIS_HASH, EvidenceChain, verify_chain

json_scalars = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20))
payloads = st.dictionaries(st.text(min_size=1, max_size=10), json_scalars, max_size=5)
entries = st.lists(
    st.tuples(st.sampled_from(["request", "response", "oracle"]), payloads), min_size=1, max_size=10
)


def _build(items: list[tuple[str, dict[str, object]]]) -> EvidenceChain:
    chain = EvidenceChain()
    for kind, payload in items:
        chain.append(kind, payload)  # type: ignore[arg-type]
    return chain


def test_empty_chain_head_is_genesis() -> None:
    chain = EvidenceChain()
    assert chain.head == GENESIS_HASH
    assert verify_chain(chain.records)


def test_records_link_to_previous_hash() -> None:
    chain = _build([("request", {"path": "/orders/201"}), ("response", {"status": 200})])
    first, second = chain.records
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.record_hash
    assert chain.head == second.record_hash


@given(entries)
def test_untampered_chain_verifies(items: list[tuple[str, dict[str, object]]]) -> None:
    assert verify_chain(_build(items).records)


@given(entries, st.data())
def test_any_payload_change_is_detected(
    items: list[tuple[str, dict[str, object]]], data: st.DataObject
) -> None:
    records = list(_build(items).records)
    i = data.draw(st.integers(min_value=0, max_value=len(records) - 1))
    tampered_payload = {**records[i].payload, "__tampered__": True}
    records[i] = records[i].model_copy(update={"payload": tampered_payload})
    assert not verify_chain(records)


@given(entries)
def test_dropping_a_record_is_detected(items: list[tuple[str, dict[str, object]]]) -> None:
    records = list(_build(items).records)
    if len(records) < 2:
        return
    del records[0]
    assert not verify_chain(records)
