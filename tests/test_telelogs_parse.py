"""TeleLogs row parsing on hand-written rows in the published layout (no dataset content). The key property:
cause codes are mapped by meaning, so the same fault gets the same catalogue label whichever numbering the
question uses."""
import pytest

from data.telelogs_parse import answer_codes, canonical, cause_map, parse_row

# Numbering used in the TeleLogs paper's example question (paraphrased).
PAPER = {"C1": "The serving cell's downtilt angle is too large, so far-end coverage is weak.",
         "C2": "The serving cell's coverage distance exceeds 1 km (over-shooting).",
         "C3": "A neighboring cell provides higher throughput.",
         "C4": "Non-colocated co-frequency neighboring cells cause heavy overlap.",
         "C5": "Frequent handovers degrade performance.",
         "C6": "Neighbor cell and serving cell have the same PCI mod 30.",
         "C7": "Test vehicle speed exceeds 40 km/h.",
         "C8": "Average scheduled RBs are below 160."}
# Numbering used on the model card (= common/catalogue.py).
CARD = {"C1": "Test vehicle speed exceeds 40 km/h", "C2": "Downtilt angle of the serving cell is too large",
        "C3": "Serving cell coverage distance exceeds 1 km", "C4": "Non-colocated co-frequency neighboring cells interfere",
        "C5": "Neighbor cell and serving cell have the same PCI mod 30", "C6": "Frequent handovers degrade performance",
        "C7": "Misconfigured handover thresholds", "C8": "Average scheduled resource blocks (RBs) below 160"}

DRIVE = """Timestamp|Longitude|Latitude|GPS Speed (km/h)|5G KPI PCell RF Serving PCI|5G KPI PCell RF Serving SS-RSRP [dBm]|5G KPI PCell RF Serving SS-SINR [dB]|5G KPI PCell Layer2 MAC DL Throughput [Mbps]|Measurement PCell Neighbor Cell Top Set(Cell Level) Top 1 PCI|Measurement PCell Neighbor Cell Top Set(Cell Level) Top 1 Filtered Tx BRSRP [dBm]|5G KPI PCell Layer1 DL RB Num (Including 0)
2026-01-01 10:00:00|100.0000|20.0000|52|101|-85.0|9.0|310.0|222|-90.0|170
2026-01-01 10:00:01|100.0001|20.0001|58|101|-86.0|8.0|290.0|222|-91.0|168
2026-01-01 10:00:02|100.0002|20.0002|61|101|-87.0|7.5|300.0|222|-92.0|172"""
ENG = """gNodeB ID|Cell ID|Longitude|Latitude|Mechanical Azimuth|Mechanical Downtilt|Digital Tilt|Digital Azimuth|Beam Scenario|Height|PCI|TxRx Mode|Max Transmit Power|Antenna Model
0000900|1|100.0000|20.0010|30|3|255|0|DEFAULT|20.0|101|32T32R|34.9|AAU A
0000900|2|100.0000|20.0010|150|4|7|0|SCENARIO_2|20.0|102|32T32R|34.9|AAU A
0000901|5|100.0100|20.0000|270|2|8|0|DEFAULT|25.0|222|32T32R|34.9|AAU B"""


def question(defs):
    causes = "\n".join(f"{k} : {v}" for k, v in defs.items())
    return (f"Analyse the 5G drive test. Choose the most likely root cause and put its number in \\boxed{{}}.\n"
            f"{causes}\nGiven: default electronic downtilt 255 means 6 degrees.\n"
            f"User plane drive test data as follows:\n{DRIVE}\nEngineering parameters data as follows:\n{ENG}\n")


def test_same_fault_same_label_under_both_numberings():
    a = parse_row({"question": question(PAPER), "answer": "\\boxed{C7}"})      # paper: C7 = speed
    b = parse_row({"question": question(CARD), "answer": "\\boxed{C1}"})       # card:  C1 = speed
    assert a["label"] == b["label"] == "C1"
    assert a["telelogs_label"] == "C7" and a["code_map"]["C7"] == "C1"


def test_full_paper_map():
    assert cause_map(question(PAPER)) == {"C1": "C2", "C2": "C3", "C3": "C7", "C4": "C4", "C5": "C6",
                                          "C6": "C5", "C7": "C1", "C8": "C8"}
    assert cause_map(question(CARD)) == {f"C{i}": f"C{i}" for i in range(1, 9)}


@pytest.mark.parametrize("answer", ["\\boxed{C1}\\boxed{C3}", "C2, C5", "", None, "none of these"])
def test_not_single_cause_is_dropped(answer):
    assert parse_row({"question": question(CARD), "answer": answer}) is None


def test_unmappable_or_incomplete_cause_list_is_dropped():
    odd = dict(CARD, C4="Something we have never heard of")
    assert parse_row({"question": question(odd), "answer": "C1"}) is None
    dup = dict(CARD, C8="Frequent handovers again")
    assert parse_row({"question": question(dup), "answer": "C1"}) is None
    short = {k: v for k, v in CARD.items() if k != "C8"}
    assert parse_row({"question": question(short), "answer": "C1"}) is None


def test_tables_become_cells_and_features():
    r = parse_row({"question": question(CARD), "answer": "C1"})
    serving = r["cells"][0]
    assert serving["role"] == "serving" and serving["pci"] == 101 and serving["cell_id"] == "0000900-1"
    assert serving["downtilt_deg"] == 9.0                       # 3 mechanical + default 255 -> 6
    roles = {c["cell_id"]: c["role"] for c in r["cells"]}
    assert roles == {"0000900-1": "serving", "0000900-2": "cosite", "0000901-5": "neighbour"}
    f = r["features"]
    assert f["speed_kmh"] == 57.0 and f["n_handovers"] == 0 and f["avg_rb"] == 170.0
    assert f["pci_mod30_clash"] == 0 and f["cofreq_gap_db"] == 5.0
    assert 100 < f["serving_distance_m"] < 130                  # UE ~110 m south of the site
    assert r["_source"] == "telelogs" and r["raw_text"].startswith("Analyse")


def test_pci_mod30_clash_detected():
    q = question(CARD).replace("|222|", "|131|").replace("|222|", "|131|")   # 131 % 30 == 101 % 30
    assert parse_row({"question": q, "answer": "C5"})["features"]["pci_mod30_clash"] == 1


def test_missing_tables_dropped():
    q = question(CARD).split("User plane")[0]
    assert parse_row({"question": q, "answer": "C1"}) is None


def test_canonical_rules():
    assert canonical("A neighbouring cell provides higher throughput") == "C7"
    assert canonical("Same PCI mod 30 as the serving cell") == "C5"
    assert canonical("Frequent handovers") == "C6" and canonical("handover thresholds misconfigured") == "C7"
    assert answer_codes("\\boxed{C3}") == {"C3"}


def test_select_drops_train_overlap_and_multi_cause_and_reports_counts_only():
    from data.prepare_telelogs import select_telelogs
    seen = {"question": question(CARD), "answer": "C1"}
    fresh = {"question": question(PAPER), "answer": "\boxed{C2}"}
    multi = {"question": question(PAPER) + " ", "answer": "C1 C2"}
    inc, stats = select_telelogs([seen, fresh, multi, dict(fresh)], [seen])
    assert [x["label"] for x in inc] == ["C3"]                       # paper C2 = distance = catalogue C3
    assert stats == {"test_rows": 4, "in_train": 1, "not_single_cause_or_unparsed": 1, "duplicates": 1,
                     "kept": 1, "labels": {"C3": 1}}
