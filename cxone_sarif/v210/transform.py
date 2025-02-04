from typing import List, Dict
from cxone_api import CxOneClient
from cxone_api.util import json_on_ok
from sarif_om import Run, Tool, ToolComponent, ReportingDescriptor, VersionControlDetails
from jsonpath_ng import parse
from .sast_run import SastRunTransformer
from ..moveto.cxone_api.high.util import CxOneVersions


class ScanResultTransformer:
  
  
  __info_uri = "https://checkmarx.com/resource/documents/en/34965-67042-checkmarx-one.html"
  __org = "Checkmarx"


  __details_engines = parse("$.engines")

  # TODO: SCA can use the ToolComponent notification property to indicate manifest failures

  @staticmethod
  async def transform(client : CxOneClient, scan_id : str, platform : str, versions : CxOneVersions, scan_details : Dict) -> List[Run]:

    runlist = []

    engines = ScanResultTransformer.__details_engines.find(scan_details).pop().value

    # TODO: Gather these for parallel execution
    if 'sast' in engines:
      run = await SastRunTransformer.factory(client, scan_id, platform, versions.SAST, 
                                             ScanResultTransformer.__org, ScanResultTransformer.__info_uri)
      if run is not None:
        runlist.append(run)
    

    # Run
    # run.tool describes an analysis tool
    # Is there one tool for all scans or multiple runs with a tool for each engine?
    # toolComponent looks like what to use with a single tool
    #  A tool consists of one or more “tool components,” each of which consists of one or more files. We refer to the component that contains the tool’s primary executable file as the “driver.” It controls the tool’s execution and typically defines a set of analysis rules. We refer to all other tool components as “extensions.” Extensions can include:     

    # CxOne version

    # Drivers

    return runlist

