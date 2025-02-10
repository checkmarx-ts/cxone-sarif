from .v210 import get_sast_run
from cxone_api import CxOneClient
from cxone_api.exceptions import ResponseException
from sarif_om import SarifLog, Run
from .__agent__ import __agent__
from .__version__ import __version__
from .moveto.cxone_api.high.util import CxOneVersions
from cxone_api.util import json_on_ok
from cxone_api.low.scans import retrieve_scan_details
from jsonpath_ng import parse
import logging, asyncio


PLATFORM_NAME="CheckmarxOne"

"""
  Maps a Checkmarx One improved JSON report to Sarif v2.1.0

  Args:
    client - A CxOneClient class instance from the cxone-async-api
    scan_id - A GUID string representing a scan id in CheckmarxOne

  Returns:
    A SarifLog element containing scan results for any engines executed during the scan.

"""
async def get_sarif_v210_log_for_scan(client : CxOneClient, skip_sast : bool, skip_sca : bool, skip_kics : bool, 
                                        skip_apisec : bool, scan_id : str) -> SarifLog:

  _log = logging.getLogger(f"improved_report_to_sarif_v210:{scan_id}")

  __info_uri = "https://checkmarx.com/resource/documents/en/34965-67042-checkmarx-one.html"
  __org = "Checkmarx"
  __details_engines = parse("$.engines")

  try:

    _log.info("Compiling SARIF log")

    # Semantic versions for tooling.
    versions = await CxOneVersions.factory(client)

    # Scan details
    scan_details = json_on_ok(await retrieve_scan_details(client, scan_id))

    engines = __details_engines.find(scan_details).pop().value

    # 3.13.4 - runs is empty if there are no results.
    futures = []
    if not skip_sast and 'sast' in engines:
      futures.append(asyncio.get_running_loop().create_task(get_sast_run(client, scan_details['projectId'], scan_id, PLATFORM_NAME, versions, __org, __info_uri)))

    completed, _ = await asyncio.wait(futures)

    _log.info("SARIF log complete")

    results = [x.result() for x in completed]

    return SarifLog(runs = [x for x in results if isinstance(x, Run)], 
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

  except ResponseException as rex:
    runs = None
    _log.exception(ex)
  except Exception as ex:
    # 3.13.4 - runs is null if there is an error finding the results.
    runs = None
    _log.exception(ex)

