import asyncio
import os
import logging
import sys
import argparse
from typing import Dict
from asyncio import Semaphore
from pathlib import Path
import aiofiles
import cxone_api as cx
from cxone_sarif.log import bootstrap
from cxone_sarif import get_sarif_v210_log_for_scan
from cxone_sarif.opts import ReportOpts, SastOpts
from cxone_sarif.__agent__ import __agent__
from cxone_sarif.__version__ import __version__

DEFAULT_LOGLEVEL = "INFO"


def create_parser():
    """Create the argument parser for the application."""
    parser = argparse.ArgumentParser(
        prog="cxone-sarif",
        description="Generate SARIF logs from CheckmarxOne scan results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    # Version and help
    parser.add_argument("-v", "--version", action="version", 
                       version=f"cxone-sarif {__version__}")
    
    # Required arguments
    parser.add_argument("--tenant", required=True,
                       help="The name of the tenant for use with the specified CheckmarxOne service endpoint.")
    
    # Multi-tenant vs Single-tenant options
    parser.add_argument("--region",
                       help="The multi-tenant region where the tenant is hosted. Use one of: US,US2,EU,EU2,DEU,ANZ,India,Singapore,UAE")
    
    parser.add_argument("--url",
                       help="The URL for the single-tenant CheckmarxOne portal. Must be used with --iam-url.")
    
    parser.add_argument("--iam-url", 
                       help="The URL for the single-tenant CheckmarxOne IAM endpoint. Must be used with --url.")
    
    # Authentication options
    parser.add_argument("--api-key", 
                       help="The API key to be used for authentication.")
    parser.add_argument("--use-env-api-key", action="store_true",
                       help="Retrieve the API key from the environment variable CX_APIKEY.")
    
    parser.add_argument("--client", 
                       help="The name of the OAuth client to be used for authentication. Must be used with --secret.")
    
    parser.add_argument("--use-env-oauth", action="store_true",
                       help="Retrieve the OAuth credentials from the environment variables CX_OCLIENT and CX_OSECRET.")
    
    # OAuth secret (required if --client is specified)
    parser.add_argument("--secret",
                       help="The OAuth secret associated with the OAuth client. Must be used with --client.")
    
    # CheckmarxOne API options
    parser.add_argument("--timeout", type=int, default=60,
                       help="The timeout, in seconds, for API operations. (default: 60)")
    parser.add_argument("--retries", type=int, default=3,
                       help="The number of API call retries on failure. (default: 3)")
    parser.add_argument("--delay", type=int, default=15,
                       help="The maximum seconds to delay between retries for API call failures. (default: 15)")
    parser.add_argument("-k", action="store_true",
                       help="Ignore SSL verification failures.")
    parser.add_argument("--proxy",
                       help="A value in the form of HOST:PORT that is used as a proxy server.")
    
    # SARIF Log Generation Options
    parser.add_argument("--no-sast", action="store_true",
                       help="Suppress static code analysis scan results.")
    parser.add_argument("--no-sast-apisec", action="store_true",
                       help="Do not augment SAST results with API security scan results.")
    parser.add_argument("--no-sca", action="store_true",
                       help="Suppress software composition analysis scan results.")
    parser.add_argument("--no-kics", action="store_true",
                       help="Suppress infrastructure as code scan results.")
    parser.add_argument("--no-containers", action="store_true",
                       help="Suppress container security scan results.")
    parser.add_argument("--outdir", default=".",
                       help="Directory where to write the SARIF log files. (default: .)")
    parser.add_argument("-t", type=int, default=2,
                       help="The number of concurrent scan report generations. (default: 2) Keep at 2 when using with multi-tenant Checkmarx One for best stability. The maximum is 8.")
    
    # Logging Output Options
    parser.add_argument("--level", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                       help="Log level (default: INFO)")
    parser.add_argument("--log-file",
                       help="A file where logs are written.")
    parser.add_argument("-q", action="store_true",
                       help="Do not output logs to the console.")
    
    # Scan IDs
    parser.add_argument("scanids", nargs="+", metavar="SCANIDS",
                       help="One or more space-separated scan ids that will each generate a file containing a SARIF log.")
    
    return parser


def validate_args(args):
    """Validate argument combinations that can't be handled by argparse alone."""
    # Check that we have either region OR (url + iam-url)
    if not args.region and not (args.url and args.iam_url):
        raise ValueError("Either --region OR both --url and --iam-url must be provided.")
    
    # Check that we don't have both region and single-tenant options
    if args.region and (args.url or args.iam_url):
        raise ValueError("Cannot use --region with single-tenant options (--url, --iam-url).")
    
    # If --url is provided, --iam-url must also be provided
    if args.url and not args.iam_url:
        raise ValueError("When using single-tenant options, both --url and --iam-url must be provided.")
    
    if args.iam_url and not args.url:
        raise ValueError("When using single-tenant options, both --url and --iam-url must be provided.")
    
    # If --client is provided, --secret must also be provided
    if args.client and not args.secret:
        raise ValueError("When using --client, --secret must also be provided.")
    
    if args.secret and not args.client:
        raise ValueError("When using --secret, --client must also be provided.")
    
    # Check that we have exactly one authentication method
    auth_methods = [
        args.api_key is not None,
        args.use_env_api_key,
        args.client is not None,
        args.use_env_oauth
    ]
    
    if sum(auth_methods) != 1:
        raise ValueError("Exactly one authentication method must be specified: --api-key, --use-env-api-key, --client (with --secret), or --use-env-oauth.")


async def main():
    """Main entry point for the application."""
    try:
        parser = create_parser()
        args = parser.parse_args()
        
        # Validate argument combinations
        validate_args(args)

        bootstrap(
            DEFAULT_LOGLEVEL if args.level is None else args.level,
            not args.q,
            args.log_file,
        )

        _log = logging.getLogger("main")
        _log.info(f"{__agent__}/{__version__} start...")

        if not os.path.isdir(args.outdir):
            _log.error(
                f"Output directory {args.outdir} does not exist, exiting..."
            )
            exit(1)
        else:
            _log.info(f"Report files will be written at: {args.outdir}")

        if args.region is not None:
            auth_endpoint = cx.AuthRegionEndpoints[args.region](args.tenant)
            api_endpoint = cx.ApiRegionEndpoints[args.region]()
        else:
            auth_endpoint = cx.CxOneAuthEndpoint(args.tenant, args.iam_url)
            api_endpoint = cx.CxOneApiEndpoint(args.url)

        if args.proxy is not None:
            proxy = {"http": args.proxy, "https": args.proxy}
        else:
            proxy = None

        client = cxone_client_factory(args, auth_endpoint, api_endpoint, proxy)

        concurrency = Semaphore(max(1, min(int(args.t), 8)))

        if len(args.scanids) > len(set(args.scanids)):
            _log.warning(
                "Some scan ids that were defined multiple times, only one log will be produced per unique scan id."
            )

        task_result, _ = await asyncio.wait(
            [
                asyncio.get_running_loop().create_task(
                    execute_on_scanid(
                        client,
                        scanid,
                        args.outdir,
                        ReportOpts(
                            SastOpts=SastOpts(
                                SkipSast=args.no_sast,
                                OmitApiResults=args.no_sast_apisec,
                            ),
                            SkipSca=args.no_sca,
                            SkipKics=args.no_kics,
                            SkipContainers=args.no_containers,
                        ),
                        concurrency,
                    )
                )
                for scanid in set(args.scanids)
            ]
        )

        exit(max([x.result() for x in task_result]))
    except (ValueError, SystemExit) as e:
        if isinstance(e, ValueError):
            print(f"Argument error: {e}")
            exit(1)
        else:
            # Re-raise SystemExit (this happens when argparse encounters --help, --version, or invalid args)
            raise
    except Exception as ex:
        print(ex)
        exit(1)

    _log.info(f"{__agent__}/{__version__} complete.")

    _log.info(f"{__agent__}/{__version__} complete.")


async def execute_on_scanid(
    client: cx.CxOneClient,
    scan_id: str,
    outdir: str,
    opts: ReportOpts,
    concurrency: Semaphore,
) -> int:

    async with concurrency:
        log = logging.getLogger(f"execute_on_scanid:{scan_id}")
        try:

            sarif_log = await get_sarif_v210_log_for_scan(client, opts, scan_id, True)

            async with aiofiles.open(Path(outdir) / f"{scan_id}.sarif", "wt") as fp:
                await fp.write(sarif_log.asjson())
                await fp.flush()

            return 0
        except BaseException as ex:
            log.exception(ex)
            print(scan_id, file=sys.stderr)
            return 100


def cxone_client_factory(
    args: argparse.Namespace,
    auth_endpoint: cx.CxOneAuthEndpoint,
    api_endpoint: cx.CxOneApiEndpoint,
    proxy: Dict,
) -> cx.CxOneClient:
    if args.api_key is not None or args.use_env_api_key:

        if args.api_key is not None:
            key = args.api_key
        elif "CX_APIKEY" in os.environ.keys():
            key = os.environ["CX_APIKEY"]
        else:
            raise Exception("Environment variable CX_APIKEY is not defined.")

        return cx.CxOneClient.create_with_api_key(
            key,
            f"{__agent__}/{__version__}",
            auth_endpoint,
            api_endpoint,
            timeout=int(args.timeout),
            retries=int(args.retries),
            retry_delay_s=int(args.delay),
            proxy=proxy,
            ssl_verify=not (args.k),
        )

    elif (args.client is not None and args.secret is not None) or args.use_env_oauth:

        if args.client is not None and args.secret is not None:
            client = args.client
            secret = args.secret
        elif "CX_OCLIENT" in os.environ.keys() and "CX_OSECRET" in os.environ.keys():
            client = os.environ["CX_OCLIENT"]
            secret = os.environ["CX_OSECRET"]
        else:
            raise Exception(
                "One or both environment variables CX_OCLIENT and CX_OSECRET are not defined."
            )

        return cx.CxOneClient.create_with_oauth(
            client,
            secret,
            f"{__agent__}/{__version__}",
            auth_endpoint,
            api_endpoint,
            timeout=int(args.timeout),
            retries=int(args.retries),
            retry_delay_s=int(args.delay),
            proxy=proxy,
            ssl_verify=not (args.k),
        )


if __name__ == "__main__":
    asyncio.run(main())


def cli_entry():
    asyncio.run(main())
