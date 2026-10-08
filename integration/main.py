#!/usr/bin/env python3

"""
OpenGrep + IRIS + LLM

Main Entry Point
"""

import argparse
import sys

from config import Config
from logger import Logger
from pipeline import Pipeline


def parse_args():

    parser = argparse.ArgumentParser(
        description="OpenGrep + IRIS + LLM Automation"
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose mode",
    )

    return parser.parse_args()


def main():

    args = parse_args()

    try:

        cfg = Config(args.config)

        logger = Logger(
            level=cfg.log_level,
            log_dir=cfg.log_dir,
            verbose=args.verbose or cfg.verbose,
        )

        logger.header("OpenGrep + IRIS + LLM")

        pipeline = Pipeline(cfg, logger)

        success = pipeline.run()

        if not success:
            sys.exit(1)

        logger.success("Pipeline completed successfully.")

    except KeyboardInterrupt:

        print("\nInterrupted by user.")
        sys.exit(1)

    except Exception as e:

        print()

        print("=" * 70)
        print("PIPELINE FAILED")
        print("=" * 70)

        print(e)

        sys.exit(1)


if __name__ == "__main__":
    main()
