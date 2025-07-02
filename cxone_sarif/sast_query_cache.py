from cxone_api import CxOneClient
from typing import Iterable, Any, List
from cxone_api.util import json_on_ok
import asyncio
from cxone_api.low.sast_queries import get_sast_query_description

class QueryCache:

  def __init__(self):
    self.__cache = {}
    self.__lock = asyncio.Lock()

  async def __populate(self, client : CxOneClient, query_ids : Iterable[int]) -> None:
    async with self.__lock:
      fetch = [x for x in query_ids if x not in self.__cache.keys()]
      if len(fetch) > 0:
        response_json = json_on_ok(await get_sast_query_description(client, query_ids))
        if response_json is not None:
          for description in response_json:
            self.__cache[int(description['queryId'])] = description

  async def add(self, client : CxOneClient, query_ids : Iterable[int]) -> None:
    await self.__populate(client, query_ids)

  async def get(self, client : CxOneClient, query_id : int) -> Any:
    await self.__populate(client, [query_id])
    if query_id in self.__cache.keys():
      return self.__cache[query_id]
    else:
      return None
