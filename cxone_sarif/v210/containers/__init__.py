from cxone_api import CxOneClient
from cxone_api.high.util import CxOneVersions
from sarif_om import Run
from .containers_run import ContainersRun

async def get_containers_run(client : CxOneClient, project_id : str, scan_id : str, platform : str, versions : CxOneVersions, 
                       organization : str, info_uri : str) -> Run:
  return await ContainersRun.factory(client, project_id, scan_id, platform, versions.CxOne, organization, info_uri)

