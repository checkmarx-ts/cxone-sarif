from cxone_sarif.run_factory import RunFactory
from cxone_api import CxOneClient
from cxone_api.util import page_generator
from cxone_api.low.iac import retrieve_iac_security_scan_results
from pathlib import Path
import urllib
from sarif_om import (Run,
                      ReportingDescriptor,
                      MultiformatMessageString,
                      Result,
                      Message,
                      Location,
                      PhysicalLocation,
                      ArtifactLocation,
                      Region,
                      ToolComponent,
                      Tool,
                      RunAutomationDetails
                     )


class IaCRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "033fb009-5cb2-4301-9ac9-62c295bcf8ff"

  @staticmethod
  async def factory(client : CxOneClient, project_id : str, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:
    rules = {}
    results = []

    async for result in page_generator(retrieve_iac_security_scan_results, "results", client=client, scan_id=scan_id):

      query_name = IaCRun.get_value_safe("queryName", result)
      query_platform = IaCRun.get_value_safe("platform", result)
      query_category = IaCRun.get_value_safe("category", result)
      vuln_id = f"{IaCRun.make_pascal_case_identifier(query_platform)}-{IaCRun.make_pascal_case_identifier(query_category)}-{IaCRun.make_pascal_case_identifier(query_name)}"

      if vuln_id not in rules.keys():
        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id,
          name = IaCRun.make_pascal_case_identifier(query_name),
          help_uri = "https://docs.kics.io/latest/queries/all-queries/",
          help = MultiformatMessageString(text=f"Use help URL to search for Query ID {IaCRun.get_value_safe('queryID', result)}"),
          short_description = MultiformatMessageString(text=IaCRun.get_value_safe("type", result)),
          full_description = MultiformatMessageString(text=IaCRun.get_value_safe("description", result)),
        )



        location = Location(
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=f"file:/{IaCRun.get_value_safe("fileName", result).lstrip("/")}"),
                region=Region(start_line=IaCRun.get_value_safe("line", result))
              ))


      results.append(Result(
        message = Message(text=IaCRun.get_value_safe("actualValue", result)),
        rule_id = vuln_id,
        locations = [location],
        hosted_viewer_uri = f"{client.display_endpoint.rstrip('/')}/{str(Path('results') / Path(scan_id) / Path (project_id))}/kics?result-id=" +
          urllib.parse.quote_plus(IaCRun.get_value_safe("ID", result)),
        partial_fingerprints={
          "similarityID" : IaCRun.get_value_safe("similarityID", result),
          "queryKey" : vuln_id
        },
        properties = {
          "severity" : IaCRun.get_value_safe("severity", result),
          "platform" : query_platform,
          "state" : IaCRun.get_value_safe("state", result),
          "status" : IaCRun.get_value_safe("status", result),
          "firstFoundAt" : IaCRun.get_value_safe("firstFoundAt", result),
          "firstScanID" : IaCRun.get_value_safe("firstScanID", result),
          "type" : IaCRun.get_value_safe("type", result),
        }
      ))

    driver = ToolComponent(name="KICS", guid=IaCRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx KICS {version}",
                           short_description=MultiformatMessageString(text="Infrastructure-As-Code scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           rules = [r for r in rules.values()])

    tool = Tool(driver=driver)

    return Run(tool=tool, 
               results=results, 
               automation_details=RunAutomationDetails(
                 description=Message(text="Infrastructure-As-Code analysis scan with CheckmarxOne KICS"),
                 id=f"projectid/{project_id}/scanid/{scan_id}",
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")

