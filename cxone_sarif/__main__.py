import asyncio, os
import cxone_api as cx
from cxone_sarif import improved_report_to_sarif_v210
from cxone_sarif.__agent__ import __agent__
from cxone_sarif.__version__ import __version__
from jschema_to_python.to_json import to_json


async def main():

  client = cx.CxOneClient.create_with_oauth(os.environ['OAUTH_CLIENT'], os.environ['OAUTH_SECRET'], f"{__agent__}/{__version__}",
                                   cx.AuthUS("cx_ps_nathan_leach"), cx.ApiUS())

  log = await improved_report_to_sarif_v210(client, "97068a6d-f2fa-4047-bea1-bd74df3a4059")  

  with open("out.sarif", "wt") as fp:
    fp.write(to_json(log))
    fp.flush()


asyncio.run(main())
