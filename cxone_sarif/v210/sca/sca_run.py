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
                      LogicalLocation,
                      PhysicalLocation,
                      Region,
                      Result)



class ScaRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "03040f8e-d672-4932-9429-c47cb8902357"


  @staticmethod
  def __make_full_description(cve_id : str, description : str, references : List[str]) -> MultiformatMessageString:

    return MultiformatMessageString(
      properties = { "references" : references },
      text = f"{cve_id}\n{description}\n\n{"\n".join(references)}",
      markdown = f"# {cve_id}\n## Description\n{description}\n## References\n{"\n".join([f"* [{x}]({x})" for x in references])}"
    )

  @staticmethod
  def __make_help_url(client : CxOneClient, cve_id : str) -> str:
    # CVEs can be found in the NVD.

    # Some vulnerabilities have internal advisory numbers which can be found
    # in the appsec KB.  This data requires authentication to view.

    __sca_help_base = f"{client.api_endpoint.rstrip("/")}/sca/#/appsec-knowledge-center/vulnerability/riskId/"
    __nvd_help_base = "https://nvd.nist.gov/vuln/detail/"
    __cve_prefix = "cve"

    if cve_id is None:
      return None

    if len(cve_id) > len(__cve_prefix) and cve_id.lower().startswith(__cve_prefix):
      return __nvd_help_base + cve_id
    else:
      return __sca_help_base + cve_id


  @staticmethod
  def __get_vulnerabilies(client : CxOneClient, vulnerabilities : List[Dict], location_index : Dict[str, List[str]], project_id : str, scan_id : str) -> Tuple[List[Result], Dict[str, str]]:

    results = []
    rules = {}

    for vuln in vulnerabilities:
      cve_id = ScaRun.get_value_safe("Id", vuln)
      package_id = ScaRun.get_value_safe("PackageId", vuln)
      vuln_id = f"{cve_id}.{package_id}"

      if vuln_id not in rules.keys():
        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id,
          name = ScaRun.make_pascal_case_identifier(f"Advisory {cve_id}"),
          help_uri = ScaRun.__make_help_url(client, cve_id),
          help = MultiformatMessageString(text="See published description."),
          short_description = MultiformatMessageString(text=cve_id),
          full_description = ScaRun.__make_full_description(cve_id, ScaRun.get_value_safe("Description", vuln), ScaRun.get_value_safe("References", vuln)),
          properties = {
            "cvss2" : ScaRun.get_value_safe("Cvss2", vuln),
            "cvss3" : ScaRun.get_value_safe("Cvss3", vuln),
            "cvss4" : ScaRun.get_value_safe("Cvss4", vuln),
            "cvePublishDate" : ScaRun.get_value_safe("PublishDate", vuln),
            "cwe" : ScaRun.get_value_safe("Cwe", vuln),
            "epssValue" : str(ScaRun.get_value_safe("EpssValue", vuln)),
            "epssPercentile" : str(ScaRun.get_value_safe("EpssPercentile", vuln)),
          }
        )

      exploitable_methods = ScaRun.get_value_safe("ExploitableMethods", vuln)
      logical_locations = None
      if ScaRun.get_value_safe("ExploitablePath", vuln) and exploitable_methods is not None and len(exploitable_methods) > 0:

        logical_locations = []
        for method in exploitable_methods:
          logical_locations.append(LogicalLocation(
            name = ScaRun.get_value_safe("ShortName", method),
            fully_qualified_name = ScaRun.get_value_safe("SourceFile", method),
            properties = {
              "FullName" : ScaRun.get_value_safe("FullName", method),
              "NameSpace" : ScaRun.get_value_safe("NameSpace", method),
              "Line" : str(ScaRun.get_value_safe("Line", method)),
            }
          ))
      
      locations = None

      if logical_locations is not None and len(logical_locations) > 0:
        locations = [Location(logical_locations=logical_locations)]
        
      if package_id in location_index.keys():
        for artifact_loc in location_index[package_id]:
          if locations is None:
            locations = []
          locations.append (
            Location(
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=f"file:/{artifact_loc.lstrip("/")}"),
                region=Region(start_line=1)
              )))

      results.append(Result(
        message = Message(text=ScaRun.get_value_safe("Description", vuln)),
        rule_id = vuln_id,
        locations = locations,
        hosted_viewer_uri = str(Path(client.display_endpoint) / Path(f"results/{project_id}/{scan_id}/sca?internalPath=" + 
          f"{urllib.parse.quote_plus(f"/vulnerabilities/{urllib.parse.quote_plus(f"{cve_id}:{package_id}")}")}" + 
          "/vulnerabilityDetailsGql")),
        partial_fingerprints={
          "PackageId" : package_id,
          "CVE" : cve_id
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

    results, rules = ScaRun.__get_vulnerabilies(client, ScaRun.get_value_safe("Vulnerabilities", scan_report), package_loc_index, project_id, scan_id)

    driver = ToolComponent(name="SCA", guid=ScaRun.get_tool_guid(),
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
                 id=f"projectid/{project_id}/scanid/{scan_id}",
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")
