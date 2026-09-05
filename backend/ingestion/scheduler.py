import logging
import os
from pathlib import Path

from apscheduler.schedulers.blocking import (
    BlockingScheduler
)

from dotenv import load_dotenv

from backend.ingestion.processor import (
    process_emails
)


# ----------------------------------------
# Load backend/.env
# ----------------------------------------

ENV_PATH = (
    Path(__file__).resolve().parents[1]
    / ".env"
)

load_dotenv(
    ENV_PATH
)


# ----------------------------------------
# Logging
# ----------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ----------------------------------------
# Configuration
# ----------------------------------------

POLL_INTERVAL = int(
    os.getenv(
        "POLL_INTERVAL",
        "20"
    )
)


# ----------------------------------------
# One ingestion cycle
# ----------------------------------------

def run_ingestion():

    logging.info(
        "Starting ingestion cycle..."
    )

    try:

        process_emails()

    except Exception as e:

        logging.error(
            "Ingestion cycle failed: %s",
            e
        )


# ----------------------------------------
# Start scheduler
# ----------------------------------------

def start_scheduler():

    scheduler = BlockingScheduler()

    scheduler.add_job(
        run_ingestion,
        "interval",
        seconds=POLL_INTERVAL,
        id="email_ingestion",
        max_instances=1,
        coalesce=True
    )

    logging.info(
        "Continuous ingestion started."
    )

    logging.info(
        "Polling every %d seconds.",
        POLL_INTERVAL
    )

    # Run immediately when the scheduler starts
    run_ingestion()

    try:

        scheduler.start()

    except (
        KeyboardInterrupt,
        SystemExit
    ):

        logging.info(
            "Stopping email ingestion..."
        )

        scheduler.shutdown()


if __name__ == "__main__":

    start_scheduler()