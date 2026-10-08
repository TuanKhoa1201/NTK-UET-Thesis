"""
logger.py

Logging utility for OpenGrep + IRIS + LLM
"""

import logging
import os
from datetime import datetime


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[94m",
        "INFO": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "CRITICAL": "\033[95m",
    }

    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        message = super().format(record)
        return f"{color}{message}{self.RESET}"


class Logger:

    def __init__(
        self,
        level="INFO",
        log_dir="logs",
        verbose=True,
        name="OpenGrepIRIS",
    ):

        self.verbose = verbose

        os.makedirs(log_dir, exist_ok=True)

        logfile = os.path.join(
            log_dir,
            datetime.now().strftime("%Y%m%d_%H%M%S.log"),
        )

        self.logger = logging.getLogger(name)

        self.logger.handlers.clear()

        self.logger.setLevel(getattr(logging, level.upper()))

        # --------------------------------------
        # Console
        # --------------------------------------

        console = logging.StreamHandler()

        console.setLevel(getattr(logging, level.upper()))

        console.setFormatter(
            ColorFormatter("[%(levelname)s] %(message)s")
        )

        self.logger.addHandler(console)

        # --------------------------------------
        # File
        # --------------------------------------

        file_handler = logging.FileHandler(
            logfile,
            encoding="utf-8",
        )

        file_handler.setLevel(logging.DEBUG)

        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )
        )

        self.logger.addHandler(file_handler)

    # =======================================================
    # Basic logging
    # =======================================================

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)

    def success(self, msg):
        self.logger.info("✓ " + str(msg))

    # =======================================================
    # Formatting
    # =======================================================

    def line(self, char="-", length=70):
        self.logger.info(char * length)

    def blank(self):
        self.logger.info("")

    def header(self, title):

        self.blank()

        self.line("=")

        self.logger.info(title)

        self.line("=")

        self.blank()

    def section(self, title):

        self.line()

        self.logger.info(title)

        self.line()

    def step(self, number, title):

        self.blank()

        self.line("=")

        self.logger.info(f"STEP {number} : {title}")

        self.line("=")

        self.blank()

    # =======================================================
    # Pipeline helpers
    # =======================================================

    def start(self, name):
        self.info(f"Starting {name}...")

    def finish(self, name):
        self.success(f"{name} finished.")

    def command(self, cmd):
        self.info(cmd)

    def file(self, path):
        self.info(f"Output : {path}")

    def exception(self, ex):
        self.logger.exception(ex)


# ==========================================================
# Test
# ==========================================================

if __name__ == "__main__":

    log = Logger()

    log.header("LOGGER TEST")

    log.section("Basic")

    log.debug("Debug")

    log.info("Information")

    log.warning("Warning")

    log.error("Error")

    log.success("Success")

    log.section("Pipeline")

    log.step(1, "OpenGrep Scan")

    log.command(
        "opengrep --config p/java project --sarif --output report.sarif"
    )

    log.finish("OpenGrep")

    log.step(2, "IRIS")

    log.finish("IRIS")

    log.step(3, "Generate Report")

    log.file("reports/report.html")

    log.success("Everything works.")
