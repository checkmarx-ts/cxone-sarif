from cxone_sarif.run_factory import RunFactory
from cxone_api import CxOneClient
from ...moveto.cxone_api.high.sca import get_sca_report, ScaReportOptions, ScaReportType
from sarif_om import (Run)



class ScaRun(RunFactory):
  @staticmethod
  async def factory(client : CxOneClient, project_id : str, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:
    scan_report = await get_sca_report(client, scan_id, ScaReportOptions(fileFormat=ScaReportType.ScanReportJson))
    pass