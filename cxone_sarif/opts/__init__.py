from dataclasses import dataclass


@dataclass(frozen=True)
class SastOpts:
    SkipSast: bool
    OmitApiResults: bool


@dataclass(frozen=True)
class ReportOpts:
    SastOpts: SastOpts
    SkipSca: bool
    SkipKics: bool
    SkipContainers: bool


DEFAULT = ReportOpts(
    SastOpts=SastOpts(SkipSast=False, OmitApiResults=False),
    SkipSca=False,
    SkipKics=False,
    SkipContainers=False,
)
