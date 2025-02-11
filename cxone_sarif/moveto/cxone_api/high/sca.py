from cxone_api import CxOneClient
from cxone_api.exceptions import ResponseException
from cxone_api.util import json_on_ok
from ..low.sca import request_scan_report, get_scan_report_status, retrieve_scan_report
import requests, enum
from typing import List
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from time import perf_counter, sleep


class ScaReportType(enum.Enum):
  CycloneDxJson = "CycloneDxJson"
  CycloneDxXml = "CycloneDxXml"
  SpdxJson = "SpdxJson"
  RemediatedPackagesJson = "RemediatedPackagesJson"
  ScanReportJson = "ScanReportJson"
  ScanReportXml = "ScanReportXml"
  ScanReportCsv = "ScanReportCsv"
  ScanReportPdf = "ScanReportPdf"


@dataclass_json
@dataclass(frozen=True)
class ScaReportParameters:
        hideDevAndTestDependencies : bool = False
        showOnlyEffectiveLicenses : bool = False
        excludePackages : bool = False
        excludeLicenses : bool = False
        excludeVulnerabilities : bool = False
        excludePolicies : bool = False
        filePaths : List[str] = field(default_factory=list)
        compressOutput : bool = False 

@dataclass_json
@dataclass(frozen=True)
class ScaReportOptions:
  fileFormat : ScaReportType = field(metadata=config(encoder=lambda x: x.name))
  exportParameters : ScaReportParameters = field(default_factory=ScaReportParameters)


async def get_sca_report(client : CxOneClient, scanId : str, reportOptions : ScaReportOptions, timeout_seconds : float = 300.0) -> requests.Response:
  args = { "scanId" : scanId}
  args.update(reportOptions.to_dict())
  response = json_on_ok(await request_scan_report(client, **args))
  exportId = response['exportId']

  loop_timer = cur_timer = perf_counter()
  delay_secs = 5
  ready = False

  while cur_timer - loop_timer <= timeout_seconds + delay_secs:
      cur_timer = perf_counter()

      status = json_on_ok(await get_scan_report_status(client, exportId))
      if status['exportStatus'] == "Completed":
          ready = True
          break
      sleep(delay_secs)
      delay_secs *= 2
  
  if not ready:
      raise ResponseException(f"Unable to retrieve SCA scan report after {int(cur_timer - loop_timer)} seconds")
  
  return await retrieve_scan_report(client, exportId)

