import cxone_api as cx
from cxone_api.low.scans import retrieve_list_of_scans
from cxone_api.util import json_on_ok
import os, asyncio, subprocess


async def main():
  client = cx.CxOneClient.create_with_oauth(os.environ['CXONE_CLIENT_ID'], os.environ['CXONE_CLIENT_SECRET'], "ghaction", 
    cx.AuthUS(os.environ['CXONE_TENANT']), cx.ApiUS())
  
  scans = json_on_ok(await retrieve_list_of_scans(client, limit=3))

  scan_ids = [x['id'] for x in scans['scans']]

  exit(subprocess.run(["cxone-sarif", "--tenant", os.environ['CXONE_TENANT'], "--region", "US", "--client", os.environ['CXONE_CLIENT_ID'],
                       "--secret", os.environ['CXONE_CLIENT_SECRET'] ] + scan_ids).returncode)

if __name__ == "__main__":
  asyncio.run(main())
