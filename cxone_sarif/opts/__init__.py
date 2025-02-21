from dataclasses import dataclass


@dataclass(frozen=True)
class ReportOpts:
  SkipSast : bool
  SkipSca : bool
  SkipKics : bool
  SkipApi : bool
  SkipContainers : bool
