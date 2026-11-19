from dataclasses import dataclass, field


@dataclass(frozen=True)
class SastOpts:
    SkipSast: bool = field(default=False)
    OmitApiResults: bool = field(default=False)
    AppendSimilarityId: bool = field(default=False)


@dataclass(frozen=True)
class ReportOpts:
    SastOpts: SastOpts = field(default_factory=SastOpts)  # type: ignore
    SkipSca: bool = field(default=False)
    SkipKics: bool = field(default=False)
    SkipContainers: bool = field(default=False)
    SkipSecrets: bool = field(default=False)


DEFAULT = ReportOpts(
    SastOpts=SastOpts(SkipSast=False, OmitApiResults=False, AppendSimilarityId=False),
    SkipSca=False,
    SkipKics=False,
    SkipContainers=False,
    SkipSecrets=False,
)
