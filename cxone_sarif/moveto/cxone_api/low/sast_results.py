import requests
from cxone_api import CxOneClient
from requests.compat import urljoin
from cxone_api.util import dashargs, join_query_dict

@dashargs("apply-predicates", "include-nodes", "node-ids", "query-ids", "result-id", "sink-file", "sink-file-operation",
          "sink-node", "sink-node-operation", "source-file", "source-file-operation", "source-node", "source-node-operation",
          "scan-id", "first-found-at", "first-found-at-operation", "notes-operation", "number-of-nodes", "number-of-nodes-operation",
          "preset-id", "sink-line", "sink-line-operation", "source-line", "source-line-operation", "visible-columns")
async def retrieve_sast_scan_results(client : CxOneClient, **kwargs) -> requests.Response:
    url = urljoin(client.api_endpoint, "sast-results")
    url = join_query_dict(url, kwargs)
    return await client.exec_request(requests.get, url)