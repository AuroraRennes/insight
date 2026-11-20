import pytest

from insight.drain.synth import Code, Synth, SynthError, classify


@pytest.mark.parametrize(
    ("word", "kind"),
    [
        (0x14000002, "branch"),  # b
        (0x94000002, "branch"),  # bl
        (0xD65F03C0, "branch"),  # ret
        (0xD61F0200, "branch"),  # br x16
        (0x54FFFFAB, "cond"),  # b.lt
        (0xB4000040, "cond"),  # cbz
        (0x37000040, "cond"),  # tbnz
        (0xD5033FDF, "isb"),
        (0xD4000001, "svc"),
        (0x8B020021, ""),  # add
    ],
)
def test_instruction_classes(word, kind):
    assert classify(word) == kind


def program(*words: int) -> Code:
    return Code([(0x1000, b"".join(word.to_bytes(4, "little") for word in words))])


ADD, BLT, B, SVC = 0x8B020021, 0x54FFFFCB, 0x14000000, 0xD4000001  # b.lt at 0x1004, b at 0x1010


def test_the_events_of_a_trace():
    code = program(ADD, BLT, ADD, SVC, B)
    records = [("B", 0x1000, 2), ("R", 0, 0), ("B", 0x1000, 2), ("S", 7), ("B", 0x1008, 2), ("B", 0x1010, 1)]
    events = Synth(code).run([*records, ("B", 0x1000, 1)])
    assert [str(event) for event in events] == [
        "BRANCH - 0x1000",
        "BRANCH E 0x1000",  # b.lt taken
        "ATOMS N",  # not taken, sent before the exception
        "EXCEPTION 0x2 0x1010",
        "BRANCH - 0x1010",
        "BRANCH E 0x1000",
    ]


def test_a_signal_between_two_instructions():
    events = Synth(program(ADD, ADD, ADD)).run([("B", 0x1000, 1), ("G", 0, 0, 0, 0), ("B", 0x1008, 1)])
    assert [str(event) for event in events][1:] == ["EXCEPTION 0xe 0x1004", "BRANCH - 0x1008"]


@pytest.mark.parametrize(
    ("records", "message"),
    [
        ([("B", 0x1000, 3)], "has a branch before its end"),
        ([("B", 0x1000, 1), ("B", 0x1008, 1)], "without a branch"),
        ([("B", 0x1000, 2), ("G", 0, 0, 0, 0), ("B", 0x1000, 1)], "its target is unknown"),
    ],
)
def test_traces_the_generator_refuses(records, message):
    with pytest.raises(SynthError, match=message):
        Synth(program(ADD, BLT, ADD)).run(records)
