import requests
from cxone_api import CxOneClient
from cxone_api.util import join_query_dict
from requests.compat import urljoin

async def request_scan_report(client : CxOneClient, **kwargs) -> requests.Response:
    url = urljoin(client.api_endpoint, "sca/export/requests")
    return await client.exec_request(requests.post, url, json=kwargs)

async def get_scan_report_status(client : CxOneClient, exportId : str) -> requests.Response:
    url = urljoin(client.api_endpoint, "sca/export/requests")
    url = join_query_dict(url, {"exportId" : exportId} )
    return await client.exec_request(requests.get, url)

async def retrieve_scan_report(client : CxOneClient, exportId : str) -> requests.Response:
    url = urljoin(client.api_endpoint, f"sca/export/requests/{exportId}/download")
    return await client.exec_request(requests.get, url)
