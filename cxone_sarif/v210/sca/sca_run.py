from cxone_sarif.run_factory import RunFactory
from cxone_api import CxOneClient
from cxone_api.util import json_on_ok
from ...moveto.cxone_api.high.sca import get_sca_report, ScaReportOptions, ScaReportType
from typing import Dict, List, Tuple
from pathlib import Path
import urllib
from sarif_om import (Run, Tool, 
                      RunAutomationDetails, Message, 
                      ToolComponent, 
                      MultiformatMessageString, 
                      ReportingDescriptor,
                      Location, LogicalLocation,
                      Result)



class ScaRun(RunFactory):

  @staticmethod
  def get_tool_guid() -> str:
    return "03040f8e-d672-4932-9429-c47cb8902357"


  @staticmethod
  def make_reference_message_strings(references : List[str]) -> Dict[str, str]:
    counter = 1
    ret_val = {}

    if references is not None and len(references) > 0:
      for ref in references:
        ret_val[f"reference{counter}"] = MultiformatMessageString(text=ref)
        counter += 1

    return ret_val


  @staticmethod
  def __get_vulnerabilies(client : CxOneClient, vulnerabilities : List[Dict], project_id : str, scan_id : str) -> Tuple[List[Result], Dict[str, str]]:
    results = []
    rules = {}

    for vuln in vulnerabilities:
      vuln_id = ScaRun.get_value_safe("Id", vuln)

      if vuln_id not in rules.keys():
        rules[vuln_id] = ReportingDescriptor(
          id = vuln_id, 
          name=ScaRun.make_camel_case(vuln_id),
          short_description = MultiformatMessageString(text=vuln_id),
          full_description = MultiformatMessageString(text=ScaRun.get_value_safe("Description", vuln)),
          message_strings = ScaRun.make_reference_message_strings(ScaRun.get_value_safe("References", vuln)),
          properties = {
            "Cvss2" : ScaRun.get_value_safe("Cvss2", vuln),
            "Cvss3" : ScaRun.get_value_safe("Cvss3", vuln),
            "Cvss4" : ScaRun.get_value_safe("Cvss4", vuln),
            "CvePublishDate" : ScaRun.get_value_safe("PublishDate", vuln),
            "Cwe" : ScaRun.get_value_safe("Cwe", vuln),
            "EpssValue" : str(ScaRun.get_value_safe("EpssValue", vuln)),
            "EpssPercentile" : str(ScaRun.get_value_safe("EpssPercentile", vuln)),
          }
        )

      location = None
      exploitable_methods = ScaRun.get_value_safe("ExploitableMethods", vuln)
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
      
        location = Location(
          logical_locations=logical_locations)
      
      results.append(Result(
        message = ScaRun.get_value_safe("Description", vuln),
        rule_id = vuln_id,
        locations = [] if location is None else [location],
        hosted_viewer_uri = str(Path(client.display_endpoint) / Path(f"results/{project_id}/{scan_id}/sca?internalPath=" + 
          f"{urllib.parse.quote_plus(f"/vulnerabilities/{urllib.parse.quote_plus(f"{vuln_id}:{ScaRun.get_value_safe("PackageId", vuln)}")}")}" + 
          "/vulnerabilityDetailsGql")),
        partial_fingerprints={
          "PackageId" : ScaRun.get_value_safe("PackageId", vuln),
          "CVE" : vuln_id
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

    results = []
    rules = {}

    vuln_results, vuln_rules = ScaRun.__get_vulnerabilies(client, ScaRun.get_value_safe("Vulnerabilities", scan_report), project_id, scan_id)

    results.append(vuln_results)
    rules.update(vuln_rules)
    

    driver = ToolComponent(name="SCA", guid=ScaRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx SCA {version}",
                           short_description=MultiformatMessageString(text="A tool that performs software composition analysis."),
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
                 description=Message(text="Static analysis scan with CheckmarxOne SAST"),
                 id=f"projectid/{project_id}/scanid/{scan_id}",
                 guid=scan_id,
                 correlation_guid=project_id),  
              column_kind="unicodeCodePoints")
