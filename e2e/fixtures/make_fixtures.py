"""Writes the synthetic fixtures from the rows below, which are the source of truth for the tests.

Only needed to REGENERATE the committed files; running the suite needs no third-party package.
Needs pyarrow and openpyxl:   python3 e2e/fixtures/make_fixtures.py
All data is invented. The ZQXCANARY / zqx strings and the two long numbers are canaries: they must
never appear in an output that is meant to be redacted.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent

CANARY_BORROWER = "ZQXCANARY-borrower-4417 Holdings"
CANARY_EMAIL = "zqx.canary.4417@example.invalid"
CANARY_NOTE = "ZQXCANARY-note-secret-9931"
CANARY_LOAN_ID = "ZQX-LOAN-88231"
CANARY_HEADER = "zqx_canary_hdr_5520"
CANARY_AMOUNT_OLD = Decimal("918273645.19")
CANARY_AMOUNT_NEW = Decimal("827364554.73")
CANARIES = (
    CANARY_BORROWER, CANARY_EMAIL, CANARY_NOTE, CANARY_LOAN_ID, CANARY_HEADER,
    str(CANARY_AMOUNT_OLD), str(CANARY_AMOUNT_NEW),
)

COLUMNS = ("loan_id", "borrower", "balance", "rate", "maturity", "status", "notes", CANARY_HEADER)

# loan_id, borrower, balance, rate, maturity, status, notes (None = blank), canary column
OLD_ROWS = [
    ("00017", "Alpha, LLC", Decimal("1000.50"), Decimal("5.25"), dt.date(2027, 1, 15), "current", None, "a"),
    ("00018", 'Beta "Quoted" Inc', Decimal("2000.00"), Decimal("6.00"), dt.date(2028, 3, 31), "current",
     "first line\nsecond line", "b"),
    ("00019", "Müller & Søn GmbH", Decimal("3000.25"), Decimal("4.75"), dt.date(2026, 12, 1), "watchlist",
     "N/A", "c"),
    (CANARY_LOAN_ID, CANARY_BORROWER, CANARY_AMOUNT_OLD, Decimal("7.125"), dt.date(2029, 6, 30), "current",
     CANARY_NOTE, CANARY_EMAIL),
    ("00021", "Delta Partners", Decimal("5500.00"), Decimal("5.00"), dt.date(2027, 9, 30), "delinquent",
     "  padded  ", "e"),
    ("00022", "Epsilon; Semi", Decimal("0.00"), Decimal("0.00"), dt.date(2030, 1, 1), "current", None, "f"),
]

# The only differences between old and new: three cells.
CHANGES = {
    ("00018", "balance"): Decimal("2750.00"),
    (CANARY_LOAN_ID, "balance"): CANARY_AMOUNT_NEW,
    ("00019", "status"): "delinquent",
}


def new_rows() -> list[tuple]:
    rows = []
    for row in OLD_ROWS:
        values = list(row)
        for index, column in enumerate(COLUMNS):
            if (row[0], column) in CHANGES:
                values[index] = CHANGES[(row[0], column)]
        rows.append(tuple(values))
    return rows


def drifted_rows() -> list[tuple]:
    """The new rows with one more cell changed: readable, but no longer the locked bytes."""
    balance = COLUMNS.index("balance")
    return [row[:balance] + (Decimal("2751.00"),) + row[balance + 1:] if row[0] == "00018" else row
            for row in new_rows()]


def cell_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dt.date):
        return value.isoformat()
    return str(value)


def messy_csv(rows: list[tuple]) -> bytes:
    """UTF-8 with a BOM, CRLF line ends, quoted commas, quotes and an embedded newline."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([cell_text(v) for v in row])
    return b"\xef\xbb\xbf" + buffer.getvalue().encode("utf-8")


def write_xlsx(path: Path, rows: list[tuple]) -> None:
    import openpyxl

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "tape"
    sheet.append(list(COLUMNS))
    for row in rows:
        sheet.append([float(v) if isinstance(v, Decimal) else v for v in row])
    for cells in sheet.iter_rows(min_row=2):
        cells[0].number_format = "@"
        cells[4].number_format = "yyyy-mm-dd"
    book.properties.created = book.properties.modified = dt.datetime(2026, 1, 15, 10, 30)
    book.save(path)


def write_parquet(path: Path, rows: list[tuple]) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    types = [pa.string(), pa.string(), pa.decimal128(18, 2), pa.decimal128(9, 3), pa.date32(),
             pa.string(), pa.string(), pa.string()]
    arrays = [pa.array([row[i] for row in rows], type=kind) for i, kind in enumerate(types)]
    table = pa.Table.from_arrays(arrays, names=list(COLUMNS))
    pq.write_table(table, path, compression="snappy", store_schema=False)


def main() -> None:
    (HERE / "drifted").mkdir(exist_ok=True)
    for name, rows in (("old", OLD_ROWS), ("new", new_rows()), ("drifted/new", drifted_rows())):
        (HERE / f"{name}.csv").write_bytes(messy_csv(rows))
        write_xlsx(HERE / f"{name}.xlsx", rows)
        write_parquet(HERE / f"{name}.parquet", rows)


if __name__ == "__main__":
    main()
