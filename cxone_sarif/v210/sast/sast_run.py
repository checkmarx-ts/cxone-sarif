from typing import Dict, List, Any
from cxone_api import CxOneClient
from cxone_api.util import json_on_ok, page_generator
from sarif_om import (Run, 
                      ToolComponent, 
                      ReportingDescriptor,
                      MultiformatMessageString, 
                      Result,
                      Message,
                      Location,
                      PhysicalLocation,
                      ArtifactLocation,
                      Region,
                      RunAutomationDetails,
                      Tool)
from cxone_api.low.sast_metadata import retrieve_scan_metadata, retrieve_scan_metrics
from cxone_api.low.sast_results import retrieve_sast_scan_results
from cxone_api.low.api import retrieve_apisec_security_risks, retrieve_risk_details
from cxone_sarif.sast_query_cache import QueryCache
from cxone_sarif.run_factory import RunFactory
from jsonpath_ng import parse
import uuid,requests,hashlib,urllib
from pathlib import Path



class SastRun(RunFactory):

  __metrics_scannedFiles = parse("$.scannedFilesPerLanguage")
  __results_queryIDs = parse("$.results[*].queryID")

  __cache = QueryCache ()

  @staticmethod
  def get_tool_guid() -> str:
    return "79cc9d1f-6183-4e37-8656-ef1a16dac7eb"

  @staticmethod
  async def __partial_file_descriptor_factory(language : str, count : int) -> ReportingDescriptor:
    return ReportingDescriptor(
      id="SAST-PARTIAL-FILES-LANG",
      name="SastPartialFilesByLanguage",
      guid=str(uuid.uuid4()),
      message_strings={"language" : MultiformatMessageString(text=language),
                       "partiallyGoodFiles" : MultiformatMessageString(text=str(count))},
      short_description=MultiformatMessageString(text="Some files were only partially parsed during the scan."))

  @staticmethod
  async def __bad_file_descriptor_factory(language : str, count : int) -> ReportingDescriptor:

    return ReportingDescriptor(
      id="SAST-BAD-FILES-LANG",
      name="SastBadFilesByLanguage",
      guid=str(uuid.uuid4()),
      message_strings={"language" : MultiformatMessageString(text=language),
                       "badFiles" : MultiformatMessageString(text=str(count))},
      short_description=MultiformatMessageString(text="Some files failed to be parsed.  The contents of the file may not be syntactically valid or is not understood by the parser."))
  
  @staticmethod
  async def __notifications_factory(metrics : Dict) -> List[ReportingDescriptor]:
    descriptors = []
    found = SastRun.__metrics_scannedFiles.find(metrics)

    if len(found) > 0 and found[0].value is not None:
      reported = found[0].value
      for lang in reported.keys():
        if 'partiallyGoodFiles' in reported[lang].keys() and int(reported[lang]['partiallyGoodFiles']) > 0:
          descriptors.append(await SastRun.__partial_file_descriptor_factory(lang, int(reported[lang]['partiallyGoodFiles'])))
        if 'badFiles' in reported[lang].keys() and int(reported[lang]['badFiles']) > 0:
          descriptors.append(await SastRun.__bad_file_descriptor_factory(lang, int(reported[lang]['badFiles'])))
    
    return descriptors
  
  @staticmethod
  async def __fetch_results_with_cached_descriptions(client : CxOneClient, **kwargs) -> requests.Response:
    response = await retrieve_sast_scan_results(client, **kwargs)
    await SastRun.__cache.add (client, set([x.value for x in SastRun.__results_queryIDs.find(json_on_ok(response))]))
    return response
  
  @staticmethod
  def __sub_description_variables(description : str, source_node : Dict, sink_node : Dict) -> Message:
    text = markdown = description

    def get_or_unknown(node, key):
      if key in node.keys():
        return node[key]
      else:
        return "unknown"

    if source_node is not None:
      text = text.replace("@SourceFile", get_or_unknown(source_node, 'fileName')) \
        .replace("@SourceMethod", get_or_unknown(source_node, 'method')) \
        .replace("@SourceLine", str(get_or_unknown(source_node, 'line'))) \
        .replace("@SourceElement", get_or_unknown(source_node, 'name'))

      markdown = markdown.replace("@SourceFile", f"**{get_or_unknown(source_node, 'fileName')}**") \
        .replace("@SourceMethod", f"**{get_or_unknown(source_node, 'method')}**") \
        .replace("@SourceLine", f"**{str(get_or_unknown(source_node, 'line'))}**") \
        .replace("@SourceElement", f"**{get_or_unknown(source_node, 'name')}**")

    if sink_node is not None:
      text = text.replace("@DestinationFile", get_or_unknown(sink_node, 'fileName')) \
        .replace("@DestinationMethod", get_or_unknown(sink_node, 'method')) \
        .replace("@DestinationLine", str(get_or_unknown(sink_node, 'line'))) \
        .replace("@DestinationElement", get_or_unknown(sink_node, 'name'))

      markdown = markdown.replace("@DestinationFile", f"**{get_or_unknown(sink_node, 'fileName')}**") \
        .replace("@DestinationMethod", f"**{get_or_unknown(sink_node, 'method')}**") \
        .replace("@DestinationLine", f"**{str(get_or_unknown(sink_node, 'line'))}**") \
        .replace("@DestinationElement", f"**{get_or_unknown(sink_node, 'name')}**")

    return Message(text=text, markdown=markdown)
  

  @staticmethod
  async def __make_apisec_index(client : CxOneClient, scan_id : str) -> Dict:

    async for risk in page_generator(retrieve_apisec_security_risks, "entries", "page", 1, client=client, scan_id=scan_id):
      print(risk)
      pass



  @staticmethod
  async def factory(client : CxOneClient, omit_apisec : bool, project_id : str, scan_id : str, 
                    platform : str, version : str, organization : str, info_uri : str) -> Run:


    apisec_index = await SastRun.__make_apisec_index(client, scan_id) if not omit_apisec else {}


    # if not opts.SkipApi and 'apisec' in engines:
      # /apisec/static/api/risks/<scanid>
      # Get the risks, sast risk id appears to be the correlation to SAST results?
      #
      #/apisec/static/api/risks/risk/<riskid>
      # file location, status, state, region info, simid
      #
      # Results appear to link to SAST results and have a link to parameters.
      # use sast-results API with result-id containing urlencoded sast_risk_id value
      # 
      # pass

    metrics = json_on_ok(await retrieve_scan_metrics(client, scan_id))

    rules = {}
    results = []

    async for result in page_generator(SastRun.__fetch_results_with_cached_descriptions, "results", client=client, scan_id=scan_id):
      group = SastRun.get_value_safe("group", result)
      query_name = SastRun.get_value_safe("queryName", result)
      queryId = int(result['queryID'])
      rule_id_key = f"{group}.{query_name}"

      query_desc = await SastRun.__cache.get(client, queryId)

      if queryId not in rules.keys():
        rules[queryId] = ReportingDescriptor(
          id = rule_id_key,
          name=SastRun.make_pascal_case_identifier(query_name),
          short_description = MultiformatMessageString(text=query_desc['cause']),
          full_description = MultiformatMessageString(text=query_desc['risk']),
          help = MultiformatMessageString(text=query_desc['generalRecommendations']),
          properties = {
            "queryID" : queryId,
          })

      nodes = SastRun.get_value_safe("nodes", result)
      locations = []
      filePathsFingerprint = hashlib.sha256()
      if nodes is not None:
        index = 0
        for node in nodes:
          filePathsFingerprint.update(bytes(SastRun.get_value_safe("fileName", node), "UTF-8"))

          def calc_end_column(node : dict):
            column_val = SastRun.get_value_safe("column", node)
            if column_val is None:
              return None

            try:
              column_val = int(column_val)
            except Exception:
              return None
            
            length_val = SastRun.get_value_safe("length", node)
            if length_val is None:
              return None
            
            try:
              length_val = int(length_val)
            except Exception:
              return None
            
            return column_val + length_val
          

          locations.append(
            Location(
              id=index, 
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=f"file:{SastRun.get_value_safe("fileName", node)}"
                ),
              region=Region(
                start_line=SastRun.get_value_safe("line", node),
                start_column=SastRun.get_value_safe("column", node),
                end_column=calc_end_column(node),
                source_language=SastRun.get_value_safe("languageName", result),
                properties={
                  "methodName" : SastRun.get_value_safe("method", node),
                  "methodLine" : SastRun.get_value_safe("methodLine", node),
                  "domType" : SastRun.get_value_safe("domType", node),
                  "nodeID" : SastRun.get_value_safe("nodeID", node),
                  "fullName" : SastRun.get_value_safe("fullName", node)
                }
              ))))
          index += 1

      results.append(Result(
        message = SastRun.__sub_description_variables(query_desc['resultDescription'], nodes[0], nodes[-1:][0]),
        rule_id = rule_id_key,
        locations=locations,
        hosted_viewer_uri=str(Path(client.display_endpoint) / Path(f"sast-results/{project_id}/{scan_id}?resultId={urllib.parse.quote_plus(result['pathSystemID'])}")),
        partial_fingerprints={
          "similarityID" : str(result['similarityID']),
          "queryKey" : rule_id_key,
          "nodeFilePathsSha256" : filePathsFingerprint.hexdigest(),
        },
        properties={
          "state" : result['state'],
          "status" : result['status'],
          "severity" : result['severity'],
          "queryID" : queryId,
          "foundAt" : result['foundAt'],
          "firstScanID" : result['firstScanID'],
          "firstFoundAt" : result['firstFoundAt'],
          "cweID" : result['cweID'],
          "cvssScore" : result['cvssScore'],
          "confidenceLevel" : result['confidenceLevel'],
          "compliances" : result['compliances'],
        }
      ))
    

    driver = ToolComponent(name="SAST", guid=SastRun.get_tool_guid(),
                           product_suite=platform,
                           full_name=f"Checkmarx SAST {version}",
                           short_description=MultiformatMessageString(text="Static code analysis scanner."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           notifications = await SastRun.__notifications_factory(metrics),
                           rules = [r for r in rules.values()],
                           properties={
                             "scanMetrics" : metrics
                           })

    metadata = json_on_ok(await retrieve_scan_metadata(client, scan_id))
    tool = Tool(driver=driver,
                properties={
                  "scanMetadata" : metadata
                  })
    
    return Run(tool=tool, 
               results=results, 
               automation_details=RunAutomationDetails(
                 description=Message(text="Static analysis scan with CheckmarxOne SAST"),
                 id=f"projectid/{project_id}/scanid/{scan_id}",
                 guid=scan_id,
                 correlation_guid=project_id),  
               column_kind="unicodeCodePoints")
  