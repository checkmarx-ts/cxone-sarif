from cxone_sarif.utils import normalize_file_uri
from cxone_sarif.run_factory import RunFactory
from cxone_api import CxOneClient
from cxone_api.util import json_on_ok
from cxone_api.high.sca import get_sca_report, ScaReportOptions, ScaReportType
from typing import Dict, List, Tuple
from pathlib import Path
import urllib
from sarif_om import (Run,
                      Tool,
                      RunAutomationDetails,
                      ToolComponent,
                      Message,
                      ArtifactLocation,
                      MultiformatMessageString,
                      ReportingDescriptor,
                      Location,
                      PhysicalLocation,
                      Region,
                      Result,
                      CodeFlow,
                      ThreadFlow,
                      ThreadFlowLocation)



class ScaRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "3535ec30-c264-4cfb-a816-67984dc28151"


  @staticmethod
  def __make_result_msg(ep_bullets : List[str], viewer_link : str) -> Message:
    desc = "Package manifest where references can be found is shown."

    if len(ep_bullets) > 0:
      desc += "\n\n"
      desc = desc + "\n\nExploitable Path found some locations where package may be referenced:\n\n"
      for bullet in ep_bullets:
        desc += "\n* " + bullet
      desc += "\n\n"

    return Message(text=desc, markdown=desc + f" [View in CheckmarxOne]({viewer_link})")


  @staticmethod
  def __get_vulnerabilities(client : CxOneClient, vulnerabilities : List[Dict], location_index : Dict[str, List[str]], project_id : str, scan_id : str) -> Tuple[List[Result], Dict[str, str]]:

    results = []
    rules = {}

    for vuln in vulnerabilities:
      cve_id = ScaRun.get_value_safe("Id", vuln)
      package_id = ScaRun.get_value_safe("PackageId", vuln)
      vuln_id = cve_id

      if vuln_id not in rules.keys():
        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id,
          name = ScaRun.make_pascal_case_identifier(f"Advisory {cve_id}"),
          help_uri = ScaRun.make_cve_help_url(client, cve_id),
          help = ScaRun.make_cve_description(cve_id, ScaRun.get_value_safe("Description", vuln), ScaRun.get_value_safe("References", vuln)),
          short_description = MultiformatMessageString(text=cve_id),
          full_description = ScaRun.make_cve_description(cve_id, ScaRun.get_value_safe("Description", vuln), ScaRun.get_value_safe("References", vuln)),
          properties = {
            "cvss2" : ScaRun.get_value_safe("Cvss2", vuln),
            "cvss3" : ScaRun.get_value_safe("Cvss3", vuln),
            "cvss4" : ScaRun.get_value_safe("Cvss4", vuln),
            "cvePublishDate" : ScaRun.get_value_safe("PublishDate", vuln),
            "cwe" : ScaRun.get_value_safe("Cwe", vuln),
            "epssValue" : str(ScaRun.get_value_safe("EpssValue", vuln)),
            "epssPercentile" : str(ScaRun.get_value_safe("EpssPercentile", vuln)),
            "security-severity" : str(ScaRun.get_value_safe("Score", vuln))
          }
        )

      exploitable_methods = ScaRun.get_value_safe("ExploitableMethods", vuln)
      code_flows = None
      ep_bullets = []
      if ScaRun.get_value_safe("ExploitablePath", vuln) and exploitable_methods is not None and len(exploitable_methods) > 0:
        code_flows = []

        ep_index = 0
        for method in exploitable_methods:
          ep_bullets.append("{}: {} Line: {}".format(
            ScaRun.get_value_safe("FullName", method), ScaRun.get_value_safe('SourceFile', method), ScaRun.get_value_safe("Line", method)))

          # Exploitable path doesn't provide enough information to get a nice flow highlight,
          # so like display is all that is shown.  EP also references code that is in the 
          # package but not in the repo.  It is not possible to tell the difference, so all
          # are shown as paths.
          loc = Location(
              id=ep_index,
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=normalize_file_uri(ScaRun.get_value_safe('SourceFile', method))
                ),
              region=Region(
                start_line=ScaRun.get_value_safe("Line", method),
                start_column=1,
                end_column=1,
                properties={
                  "NameSpace" : ScaRun.get_value_safe("NameSpace", method),
                  "FullName" : ScaRun.get_value_safe("FullName", method),
                  "ShortName" : ScaRun.get_value_safe("ShortName", method),
                })))

          code_flows.append(CodeFlow(thread_flows=[ThreadFlow(locations=[ThreadFlowLocation(location=loc)])]))

          ep_index += 1

      
      locations = None
      
      if package_id in location_index.keys():
        
        if locations is None:
          locations = []
        index = len(locations)

        # There can be many locations where this package is referenced.  Sarif
        # spec says only use more than one location if every location needs to
        # be changed to fix the issue.  GH displays only the first one,
        # but all will be put here for other Sarif consumers.
        for artifact_loc in location_index[package_id]:
          locations.append (
            Location(
              id=index,
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=normalize_file_uri(artifact_loc)),
                  region=Region(start_line=1, start_column=1, end_column=1)
              )))
          index += 1


      vuln_path = urllib.parse.quote_plus(f"/vulnerabilities/{urllib.parse.quote_plus(f'{cve_id}:{package_id}')}")

      viewer_url = client.display_endpoint.rstrip("/") + "/" + str(Path(f"results/{project_id}/{scan_id}/sca?internalPath=" + \
          f"{vuln_path}%2FvulnerabilityDetailsGql"))

      results.append(Result(
        message = ScaRun.__make_result_msg(ep_bullets, viewer_url),
        rule_id = vuln_id,
        locations = locations,
        hosted_viewer_uri = viewer_url,
        code_flows=code_flows,
        partial_fingerprints={
          "packageId" : package_id,
          "cve" : cve_id
        },
        properties = {
          "severity" : ScaRun.get_value_safe("Severity", vuln),
          "packageName" : ScaRun.get_value_safe("PackageName", vuln),
          "packageVersion" : ScaRun.get_value_safe("PackageVersion", vuln),
          "packageManager" : ScaRun.get_value_safe("PackageManager", vuln),
          "fixResolutionText" : ScaRun.get_value_safe("FixResolutionText", vuln),
          "state" : ScaRun.get_value_safe("RiskState", vuln),
          "status" : ScaRun.get_value_safe("RiskStatus", vuln),
          "firstFoundAt" : ScaRun.get_value_safe("FirstFoundAt", vuln),
          "riskType" : "package",
          "isViolatingPolicy" : str(ScaRun.get_value_safe("IsViolatingPolicy", vuln)),
        }
      ))

    return results, rules

  @staticmethod
  async def factory(client : CxOneClient, project_id : str, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:
    scan_report = json_on_ok(await get_sca_report(client, scan_id, ScaReportOptions(fileFormat=ScaReportType.ScanReportJson)))
    scan_report_summary = ScaRun.get_value_safe("RiskReportSummary", scan_report)

    packages = ScaRun.get_value_safe("Packages", scan_report)
    package_loc_index = {}

    for package in packages:
      package_loc_index[ScaRun.get_value_safe("Id", package)] = ScaRun.get_value_safe("Locations", package)

    results, rules = ScaRun.__get_vulnerabilities(client, ScaRun.get_value_safe("Vulnerabilities", scan_report), package_loc_index, project_id, scan_id)

    driver = ToolComponent(name="CheckmarxOne-SCA", guid=ScaRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx SCA {version}",
                           short_description=MultiformatMessageString(text="Software composition analysis scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           rules = [r for r in rules.values()])

    tool = Tool(driver=driver,
                properties={
                  "summary" : scan_report_summary
                  })

    return Run(tool=tool, 
               results=results, 
               automation_details=RunAutomationDetails(
                 description=Message(text="Software composition analysis scan with CheckmarxOne SCA"),
                 id=RunFactory.make_run_id(project_id, scan_id),
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")
