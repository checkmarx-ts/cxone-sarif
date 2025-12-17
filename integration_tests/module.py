import cxone_api as cx
from cxone_api.low.scans import retrieve_list_of_scans
from cxone_api.util import json_on_ok
from cxone_sarif import get_sarif_v210_log_for_scan
from cxone_sarif.opts import DEFAULT
import os, asyncio,json


async def main():
  client = cx.CxOneClient.create_with_oauth(os.environ['CXONE_CLIENT_ID'], os.environ['CXONE_CLIENT_SECRET'], "ghaction", 
    cx.AuthUS(os.environ['CXONE_TENANT']), cx.ApiUS())
  
  scans = json_on_ok(await retrieve_list_of_scans(client, limit=1, statuses="Completed"))
  scan_ids = [x['id'] for x in scans['scans']]

  sarif_log = await get_sarif_v210_log_for_scan(client, DEFAULT, scan_ids[0], True)
  j = json.loads(sarif_log.asjson())
  print(json.dumps(j, indent=2))

  exit (0 if sarif_log is not None else 1)

if __name__ == "__main__":
  asyncio.run(main())
