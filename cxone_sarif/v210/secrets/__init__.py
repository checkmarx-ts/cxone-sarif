from cxone_api import CxOneClient
from cxone_api.high.util import CxOneVersions
from sarif_om import Run
from cxone_sarif.utils import AllResultsCache
from .secrets_run import SecretsRun


async def get_secrets_run(
    client: CxOneClient,
    project_id: str,
    scan_id: str,
    platform: str,
    versions: CxOneVersions,
    results_cache: AllResultsCache,
    organization: str,
    info_uri: str,
) -> Run:
    return await SecretsRun.factory(
        client,
        project_id,
        scan_id,
        platform,
        versions.CxOne,
        results_cache,
        organization,
        info_uri,
    )
