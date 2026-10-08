"""
config.py

Load configuration from config.yaml

Usage:

from config import Config

cfg = Config()

print(cfg.project["source"])
print(cfg.iris["queries"])
print(cfg.report["output_dir"])
"""

from pathlib import Path
import yaml


class Config:

    def __init__(self, config_file="config.yaml"):

        config_path = Path(config_file)

        if not config_path.exists():
            raise FileNotFoundError(
                f"Cannot find configuration file: {config_file}"
            )

        with open(config_path, "r", encoding="utf-8") as f:
            self.cfg = yaml.safe_load(f)

    # -------------------------------------------------
    # Sections
    # -------------------------------------------------

    @property
    def project(self):
        return self.cfg.get("project", {})

    @property
    def opengrep(self):
        return self.cfg.get("opengrep", {})

    @property
    def iris(self):
        return self.cfg.get("iris", {})

    @property
    def report(self):
        return self.cfg.get("report", {})

    @property
    def metadata(self):
        return self.cfg.get("metadata", {})

    @property
    def paths(self):
        return self.cfg.get("paths", {})

    @property
    def logging(self):
        return self.cfg.get("logging", {})

    @property
    def runtime(self):
        return self.cfg.get("runtime", {})

    # -------------------------------------------------
    # Common shortcuts
    # -------------------------------------------------

    @property
    def log_dir(self):
        return self.logging.get("log_dir", "logs")


    @property
    def log_level(self):
        return self.logging.get("level", "INFO")


    @property
    def verbose(self):
        return self.runtime.get("verbose", True)


    @property
    def project_source(self):
        return self.project.get("source")


    @property
    def project_name(self):
        return self.project.get("name")


    @property
    def output_dir(self):
        return self.report.get("output_dir", "reports")

    # -------------------------------------------------
    # Helper
    # -------------------------------------------------

    def get(self, section, key, default=None):
        """
        Example:

        cfg.get("project","source")
        cfg.get("report","output_dir")
        """
        return self.cfg.get(section, {}).get(key, default)

    # -------------------------------------------------
    # Pretty Print
    # -------------------------------------------------

    def show(self):

        print("=" * 70)
        print("OpenGrep + IRIS + LLM Configuration")
        print("=" * 70)

        print("\nPROJECT")
        print("-------------------------------")
        print("Name       :", self.project.get("name"))
        print("Source     :", self.project.get("source"))
        print("Language   :", self.project.get("language", "java"))

        print("\nOPENGREP")
        print("-------------------------------")
        print("Executable :", self.opengrep.get("executable"))
        print("Config     :", self.opengrep.get("config"))
        print("Output     :", self.opengrep.get("output"))

        print("\nIRIS")
        print("-------------------------------")
        print("Executable :", self.iris.get("executable"))
        print("Script     :", self.iris.get("script"))
        print("Queries    :", self.iris.get("queries"))
        print("Run ID     :", self.iris.get("run_id"))
        print("LLM        :", self.iris.get("llm"))

        print("\nREPORT")
        print("-------------------------------")
        print("Output Dir :", self.report.get("output_dir"))
        print("Project    :", self.report.get("project_name"))
        print("Version    :", self.report.get("analyzer_version"))

        print("\nPATHS")
        print("-------------------------------")
        for k, v in self.paths.items():
            print(f"{k:22}: {v}")

        print("\nLOGGING")
        print("-------------------------------")
        for k, v in self.logging.items():
            print(f"{k:22}: {v}")

        print("\nRUNTIME")
        print("-------------------------------")
        for k, v in self.runtime.items():
            print(f"{k:22}: {v}")

        print("\nMETADATA")
        print("-------------------------------")
        for k, v in self.metadata.items():
            print(f"{k:22}: {v}")

        print("=" * 70)


if __name__ == "__main__":

    cfg = Config()

    cfg.show()

    print("\nExample access:")
    print("-------------------------------")
    print("Project Source :", cfg.project["source"])
    print("OpenGrep Config:", cfg.opengrep["config"])
    print("IRIS Queries   :", cfg.iris["queries"])
    print("Report Output  :", cfg.report["output_dir"])
