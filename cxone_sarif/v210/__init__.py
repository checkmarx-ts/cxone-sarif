from .transform import ScanResultTransformer
from cxone_api import CxOneClient
from sarif_om import Run
from typing import Dict, List
from ..moveto.cxone_api.high.util import CxOneVersions

"""
  Converts a Checkmarx One improved JSON report into a Sarif "run" element.

  Args:
    client - A CxOneClient class instance from the cxone-async-api
    scan_id - A GUID string representing a scan id in CheckmarxOne
    platform - The name of the scanning platform.
  
  Returns:
    A Run element containing data extracted from the provided Checkmarx One improved JSON reports.

"""
async def improved_report_to_sarif_run(client : CxOneClient, scan_id : str, platform : str, versions : CxOneVersions, scan_details : Dict) -> List[Run]:
  return await ScanResultTransformer.transform(client, scan_id, platform, versions, scan_details)