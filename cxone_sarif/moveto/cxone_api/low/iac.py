import requests
from cxone_api import CxOneClient
from cxone_api.util import join_query_dict, dashargs
from requests.compat import urljoin

@dashargs("apply-predicates", "source-file")
async def retrieve_iac_security_scan_results(client : CxOneClient, scan_id : str, **kwargs) -> requests.Response:
    url = urljoin(client.api_endpoint, f"kics-results")
    q = dict(kwargs)
    q["scan-id"] =  scan_id
    url = join_query_dict(url, q)

    return await client.exec_request(requests.get, url)
