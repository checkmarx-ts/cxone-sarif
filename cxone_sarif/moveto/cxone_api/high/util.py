from cxone_api import CxOneClient
from cxone_api.util import json_on_ok
from typing import Self
from ..low.misc import retrieve_versions
from dataclasses import dataclass
from dataclasses_json import dataclass_json

@dataclass_json
@dataclass(frozen=True)
class CxOneVersions:
  CxOne : str
  SAST : str
  KICS : str

  async def factory(client : CxOneClient) -> Self:
    v = json_on_ok(await retrieve_versions(client))
    return CxOneVersions(CxOne=v["CxOne"], SAST=v["SAST"], KICS=v["KICS"])
