import asyncio, os, logging, aiofiles
from asyncio import Semaphore
from pathlib import Path
from docopt import docopt
from docopt import DocoptExit
import cxone_api as cx
from cxone_sarif.cxone_sarif_logging import bootstrap
from cxone_sarif import get_sarif_v210_log_for_scan
from cxone_sarif.__agent__ import __agent__
from cxone_sarif.__version__ import __version__
from jschema_to_python.to_json import to_json

DEFAULT_LOGLEVEL="INFO"

async def main():
  """Usage: cxone-sarif --tenant TENANT (--region=REGION | (--url=URL --iam-url=IAMURL)) (--api-key APIKEY | (--client OCLIENT --secret OSECRET)) 
                   [--level LOGLEVEL] [--log-file LOGFILE] [--timeout TIMEOUT] [--retries RETRIES] [--proxy IP:PORT] 
                   [--outdir OUTDIR] [--no-sast] [--no-sca] [--no-kics] [--no-apisec] [-qk] [-t THREADS] SCANIDS... 

  SCANIDS...          One or more scan ids that will each generate a file containing a SARIF log.

  -h --help           Show this help.

  --tenant TENANT     The name of the tenant for use with the specified CheckmarxOne service endpoint.
                
  Multi-Tenant CheckmarxOne options:
  --region REGION     The multi-tenant region where the tenant is hosted.
                      Use one of: {CXREGIONS}

  Single-Tenant CheckmarxOne options:
  --url URL           The URL for the single-tenant CheckmarxOne portal.
  --iam-url IAMURL    The URL for the single-tenant CheckmarxOne IAM endpoint.

  Authorization Options:

  --api-key APIKEY    The API key to be used for authentication.

  --client OCLIENT    The name of the OAuth client to be used for authentication.
  --secret OSECRET    The OAuth secret associated with the OAuth client.

  -- Additional Options --

  CheckmarxOne API Options
  --timeout TIMEOUT   The timeout, in seconds, for API operations.  [default: 60]

  --retries RETRIES   The number of operation retries on failure.   [default: 3]

  -k                  Ignore SSL verification failures. 

  --proxy IP:PORT     A SOCKS5 proxy server to use for communication.

  
  SARIF Log Generation Options:
  --no-sast           Suppress SAST results.
  --no-sca            Suppress SCA results.
  --no-kics           Suppress KICS results.
  --no-apisec         Suppress APISEC results.
  
  --outdir OUTDIR     Directory where to write the SARIF log files.   [default: .]

  -t THREADS          The number of concurrent scan report generations.  [default: 2]
                      Keep at 2 when using with multi-tenant Checkmarx One for
                      best stability.  The maximum is 8.

  Logging Output Options:
  --level LOGLEVEL    Log level [default: INFO]
                      Use: DEBUG, INFO, WARNING, ERROR, CRITICAL
  
  --log-file LOGFILE  A file where logs are written.

  -q                  Do not output logs to the console.

  """

  try:
    args = docopt(main.__doc__.replace("{CXREGIONS}", ",".join(cx.ApiRegionEndpoints.keys())), version=__version__)

    bootstrap(DEFAULT_LOGLEVEL if args['--level'] is None else args['--level'], 
              not args['-q'], args['--log-file'])
    
    logger = logging.getLogger("main")
    logger.info(f"{__agent__}/{__version__} start...")

    if not os.path.isdir(args['--outdir']):
      logger.error(f"Output directory {args['--outdir']} does not exist, exiting...")
      exit(1)
    else:
      logger.info(f"Report files will be written at: {args['--outdir']}")


    if args['--region'] is not None:
      auth_endpoint = cx.AuthRegionEndpoints[args['--region']](args['--tenant'])
      api_endpoint = cx.ApiRegionEndpoints[args['--region']]()
    else:
      auth_endpoint = cx.CxOneAuthEndpoint(args['--tenant'], args['--iam-url'])
      api_endpoint = cx.CxOneApiEndpoint(args['--url'])

    if args['--proxy'] is not None:
      proxy = {
        "HTTP": args['--proxy'],
        "HTTPS" : args['--proxy']
      }
    else:
      proxy = None


    if args['--api-key'] is not None:
      client = cx.CxOneClient.create_with_api_key(args['--api-key'], f"{__agent__}/{__version__}", auth_endpoint,
                                                  api_endpoint, int(args['--timeout']), int(args['--retries']), proxy)
    else:
      client = cx.CxOneClient.create_with_oauth(args['--client'], args['--secret'], f"{__agent__}/{__version__}", auth_endpoint,
                                                api_endpoint, int(args['--timeout']), int(args['--retries']), proxy, not (args['-k']))

    concurrency = Semaphore(max(1, min(int(args['-t']), 8)))
  
    await asyncio.wait([asyncio.get_running_loop().create_task(execute_on_scanid(client, 
                                                                                 scanid, 
                                                                                 args['--outdir'], 
                                                                                 args['--no-sast'],  
                                                                                 args['--no-sca'],  
                                                                                 args['--no-kics'], 
                                                                                 args['--no-apisec'],
                                                                                 concurrency)) for scanid in set(args['SCANIDS'])])
    
  except DocoptExit as bad_args:
    print("Incorrect arguments provided.")
    print(bad_args)
    exit(1)
  except Exception as ex:
    print(ex)
    exit(1)


  logger.info(f"{__agent__}/{__version__} complete.")


async def execute_on_scanid(client : cx.CxOneClient, scan_id : str, outdir : str, 
                            skip_sast : bool, skip_sca : bool, skip_kics : bool,
                            skip_apisec : bool, concurrency : Semaphore) -> None:
  
  async with concurrency:
    log = logging.getLogger(f"execute_on_scanid:{scan_id}")
    try:

      sarif_log = await get_sarif_v210_log_for_scan(client, skip_sast, skip_sca, skip_kics, skip_apisec, scan_id)
      
      async with aiofiles.open(Path(outdir) / f"{scan_id}.sarif", "wt") as fp:
        await fp.write(to_json(sarif_log))
        await fp.flush()
    except Exception as ex:
      log.exception(ex)



if __name__ == "__main__":
  asyncio.run(main())
