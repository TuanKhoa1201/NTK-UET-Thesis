"""
pipeline.py

Main pipeline controller for OpenGrep + IRIS + LLM.
"""

from config import Config
from logger import Logger


class Pipeline:

    def __init__(self, cfg=None, logger=None):

        self.cfg = cfg if cfg else Config()
        self.logger = logger if logger else Logger()

    # =====================================================
    # STEP 1
    # =====================================================

    def run_opengrep(self):

        self.logger.step(1, "OpenGrep Scan")

        from runner import run_opengrep

        run_opengrep(self.cfg)

        self.logger.success("OpenGrep scan completed.")

    # =====================================================
    # STEP 2
    # =====================================================

    def normalize_findings(self):

        self.logger.step(2, "Normalize Findings")

        from parser import normalize_sarif

        normalize_sarif(self.cfg)

        self.logger.success("Findings normalized.")

    # =====================================================
    # STEP 3
    # =====================================================

    def create_jobs(self):

        self.logger.step(3, "Create IRIS Jobs")

        from dispatcher import create_jobs

        create_jobs(self.cfg)

        self.logger.success("IRIS jobs created.")

    # =====================================================
    # STEP 4
    # =====================================================

    def run_iris(self):

        self.logger.step(4, "Run IRIS")

        from runner import run_iris

        summary = run_iris(self.cfg)

        if summary.get("failed", 0) > 0:
            raise RuntimeError(
                f"IRIS failed jobs: {summary['failed']}/{summary['total']}"
            )

        self.logger.success("IRIS analysis completed.")

    # =====================================================
    # STEP 5
    # =====================================================

    def generate_report(self):

        self.logger.step(5, "Generate Final Report")

        from report_generator import generate_report

        generate_report(self.cfg)

        self.logger.success("Security report generated.")

    # =====================================================
    # RUN PIPELINE
    # =====================================================

    def run(self):

        self.logger.header("OpenGrep + IRIS + LLM Pipeline")

        try:

            self.run_opengrep()

            self.normalize_findings()

            self.create_jobs()

            self.run_iris()

            self.generate_report()

            self.logger.header("PIPELINE FINISHED SUCCESSFULLY")

            return True

        except Exception as ex:

            self.logger.error(f"Pipeline failed: {ex}")

            self.logger.exception(ex)

            return False


# ==========================================================
# Test
# ==========================================================

if __name__ == "__main__":

    cfg = Config()

    logger = Logger(
        level=cfg.log_level,
        log_dir=cfg.log_dir,
        verbose=cfg.verbose,
    )

    pipeline = Pipeline(cfg, logger)

    pipeline.run()
