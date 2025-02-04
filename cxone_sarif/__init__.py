from .v210 import improved_report_to_sarif_run
from cxone_api import CxOneClient
from sarif_om import SarifLog
from .__agent__ import __agent__
from .__version__ import __version__
from typing import Union, List, Dict
from .moveto.cxone_api.high.util import CxOneVersions
from cxone_api.util import json_on_ok
from cxone_api.low.scans import retrieve_scan_details


PLATFORM_NAME="CheckmarxOne"

"""
  Maps a Checkmarx One improved JSON report to Sarif v2.1.0

  Args:
    client - A CxOneClient class instance from the cxone-async-api
    scan_id - A GUID string representing a scan id in CheckmarxOne

  Returns:
    A SarifLog element containing scan results for any engines executed during the scan.

"""
async def improved_report_to_sarif_v210(client : CxOneClient, scan_id : str) -> SarifLog:

  try:

    # Semantic versions for tooling.
    versions = await CxOneVersions.factory(client)

    # Scan details
    scan_details = json_on_ok(await retrieve_scan_details(client, scan_id))

    # 3.13.4 - runs is empty if there are no results.
    runs = await improved_report_to_sarif_run (client, scan_id, PLATFORM_NAME, versions, scan_details)
  except Exception as ex:
    # 3.13.4 - runs is null if there is an error finding the results.
    runs = None

  return SarifLog(runs = runs, 
               version="2.1.0", 
               schema_uri="https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-external-property-file-schema-2.1.0.json",
               properties=
                {"platform" : PLATFORM_NAME, 
                  "reportCompiler" : f"{__agent__}/{__version__}",
                  "scanId" : scan_id,
                  "scanDetails" : scan_details if scan_details is not None else None,
                  "versions" : versions.to_dict()
                }
               )
