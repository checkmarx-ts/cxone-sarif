import asyncio
from typing import AsyncGenerator, Dict, List
from enum import Enum
from cxone_api import CxOneClient
from cxone_api.util import page_generator
from cxone_api.low.all_scanners_results import retrieve_scan_results_all_scanners


class CachedResultType(Enum):
    SAST = "sast"
    SCA = "sca"
    KICS = "kics"
    CONTAINERS = "containers"
    SECRETS = "sscs-secret-detection"
    SCORECARD = "sscs-scorecard"
    AISC = "aisc"
    UNKNOWN = "unknown"


class AllResultsCache:

    def __init__(self, client: CxOneClient, scan_id: str):
        self.__cache_lock = asyncio.Lock()
        self.__client = client
        self.__scan_id = scan_id
        self.__cache = None

    async def __populate_cache(self):
        async with self.__cache_lock:
            if self.__cache is None:

                self.__cache = {}

                async for result in page_generator(
                    retrieve_scan_results_all_scanners,
                    array_element="results",
                    client=self.__client,
                    scan_id=self.__scan_id,
                    limit=100,
                    offset_is_by_count=False,
                ):
                    self.__cache.setdefault(
                        CachedResultType(
                            result.get("type", CachedResultType.UNKNOWN.value)
                        ),
                        [],
                    ).append(result)

    @staticmethod
    async def __generator(result_list: List[Dict]) -> AsyncGenerator:
        pos = 0

        while True:
            if result_list is None or len(result_list) == 0 or pos >= len(result_list):
                return

            yield result_list[pos]

            pos += 1

    async def results_by_type(
        self, results_type: CachedResultType
    ) -> AsyncGenerator[Dict, None]:
        await self.__populate_cache()
        return AllResultsCache.__generator(self.__cache.get(results_type, []))
