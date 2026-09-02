import json
from pathlib import Path


STATE_FILE = (
    Path(__file__).resolve().parent
    / "ingestion_state.json"
)


def load_last_uid():
    """
    Load the UID of the last successfully processed email.

    Returns 0 if no state file exists or if the state file
    cannot be read.
    """

    if not STATE_FILE.exists():
        return 0

    try:

        with open(
            STATE_FILE,
            "r"
        ) as file:

            data = json.load(file)

        return int(
            data.get(
                "last_uid",
                0
            )
        )

    except (
        json.JSONDecodeError,
        OSError,
        ValueError
    ):

        return 0


def save_last_uid(uid):
    """
    Save the last successfully processed UID.
    """

    with open(
        STATE_FILE,
        "w"
    ) as file:

        json.dump(
            {
                "last_uid": int(uid)
            },
            file,
            indent=2
        )