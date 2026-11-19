from cxone_sarif.utils import AllResultsCache, CachedResultType
from cxone_sarif.run_factory import RunFactory
from cxone_api import CxOneClient
from sarif_om import (
    Run,
    ReportingDescriptor,
    MultiformatMessageString,
    Result,
    Message,
    Location,
    Region,
    PhysicalLocation,
    ArtifactLocation,
    RunAutomationDetails,
    Tool,
    ToolComponent,
)


class SecretsRun(RunFactory):

    @staticmethod
    def get_tool_guid() -> str:
        return "5c6031ce-338d-40a1-90b7-b27a342b55d9"

    @staticmethod
    async def factory(
        client: CxOneClient,
        project_id: str,
        scan_id: str,
        platform: str,
        version: str,
        all_results_cache: AllResultsCache,
        organization: str,
        info_uri: str,
    ) -> Run:

        results = []
        rules = {}

        async for result in await all_results_cache.results_by_type(
            CachedResultType.SECRETS
        ):
            pass
