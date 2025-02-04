import requests
from cxone_api import CxOneClient
from requests.compat import urljoin

async def retrieve_versions(client : CxOneClient) -> requests.Response:
    url = urljoin(client.api_endpoint, "versions")
    return await client.exec_request(requests.get, url)
