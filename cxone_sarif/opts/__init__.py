from dataclasses import dataclass

@dataclass(frozen=True)
class SastOpts:
  SkipSast : bool
  OmitApiResults : bool

@dataclass(frozen=True)
class ReportOpts:
  SastOpts : SastOpts
  SkipSca : bool
  SkipKics : bool
  SkipContainers : bool
