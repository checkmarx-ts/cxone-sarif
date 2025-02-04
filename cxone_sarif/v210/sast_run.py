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
from ..moveto.cxone_api.low.sast_results import retrieve_sast_scan_results
from cxone_sarif.sast_query_cache import QueryCache
from jsonpath_ng import parse
import uuid,requests,hashlib



class SastRunTransformer:

  __sast_guid = "79cc9d1f-6183-4e37-8656-ef1a16dac7eb"
  __metrics_scannedFiles = parse("$.scannedFilesPerLanguage")
  __results_queryIDs = parse("$.results[*].queryID")

  __cache = QueryCache ()

  @staticmethod
  def __safeget(key : str, json : Dict) -> Any:
    if key in json.keys():
      return json[key]
    else:
      return None

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
    found = SastRunTransformer.__metrics_scannedFiles.find(metrics)

    if len(found) > 0 and found[0].value is not None:
      reported = found[0].value
      for lang in reported.keys():
        if 'partiallyGoodFiles' in reported[lang].keys() and int(reported[lang]['partiallyGoodFiles']) > 0:
          descriptors.append(await SastRunTransformer.__partial_file_descriptor_factory(lang, int(reported[lang]['partiallyGoodFiles'])))
        if 'badFiles' in reported[lang].keys() and int(reported[lang]['badFiles']) > 0:
          descriptors.append(await SastRunTransformer.__bad_file_descriptor_factory(lang, int(reported[lang]['badFiles'])))
    
    return descriptors
  
  @staticmethod
  async def retrieve_sast_scan_results_cache_description(client : CxOneClient, **kwargs) -> requests.Response:
    response = await retrieve_sast_scan_results(client, **kwargs)
    await SastRunTransformer.__cache.add (client, set([x.value for x in SastRunTransformer.__results_queryIDs.find(json_on_ok(response))]))
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
  def __camel_case(s : str) -> str:
    return s.replace("_", " ").title().replace(" ", "")

  @staticmethod
  async def factory(client : CxOneClient, scan_id : str, platform : str, version : str, organization : str, info_uri : str) -> Run:

    metrics = json_on_ok(await retrieve_scan_metrics(client, scan_id))

    rules = {}
    results = []
    # Compile Result object array here along with an array of ReportingDescriptor objects

    async for result in page_generator(SastRunTransformer.retrieve_sast_scan_results_cache_description, "results", client=client, scan_id=scan_id):
      group = SastRunTransformer.__safeget("group", result)
      query_name = SastRunTransformer.__safeget("queryName", result)
      queryId = int(result['queryID'])
      rule_id_key = f"{group}.{query_name}"

      query_desc = await SastRunTransformer.__cache.get(client, queryId)

      if queryId not in rules.keys():
        rules[queryId] = ReportingDescriptor(
          id = rule_id_key,
          name=SastRunTransformer.__camel_case(query_name),
          short_description = MultiformatMessageString(text=query_desc['cause']),
          full_description = MultiformatMessageString(text=query_desc['risk']),
          help = MultiformatMessageString(text=query_desc['generalRecommendations']),
          properties = {
            "queryID" : queryId,
          })


      nodes = SastRunTransformer.__safeget("nodes", result)
      locations = []
      filePathsFingerprint = hashlib.sha256()
      if nodes is not None:
        index = 0
        for node in nodes:
          filePathsFingerprint.update(bytes(SastRunTransformer.__safeget("fileName", node), "UTF-8"))
          locations.append(
            Location(
              id=index, 
              physical_location=PhysicalLocation(
                artifact_location=ArtifactLocation(
                  uri=f"file:{SastRunTransformer.__safeget("fileName", node)}"
                ),
              region=Region(
                start_line=SastRunTransformer.__safeget("line", node),
                start_column=SastRunTransformer.__safeget("column", node),
                end_column=int(max(int(SastRunTransformer.__safeget("column", node)), 
                                   int(SastRunTransformer.__safeget("length", node)) - int(SastRunTransformer.__safeget("column", node)))),
                source_language=SastRunTransformer.__safeget("languageName", result),
                properties={
                  "methodName" : SastRunTransformer.__safeget("method", node),
                  "methodLine" : SastRunTransformer.__safeget("methodLine", node),
                  "domType" : SastRunTransformer.__safeget("domType", node),
                  "nodeID" : SastRunTransformer.__safeget("nodeID", node),
                  "fullName" : SastRunTransformer.__safeget("fullName", node)
                }
              ))))
          index += 1

      # partial_fingerprints
      results.append(Result(
        message = SastRunTransformer.__sub_description_variables(query_desc['resultDescription'], nodes[0], nodes[-1:][0]),
        rule_id = rule_id_key,
        locations=locations,
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
    

    driver = ToolComponent(name="SAST", guid=SastRunTransformer.__sast_guid,
                           product_suite=platform,
                           full_name=f"Checkmarx SAST {version}",
                           short_description=MultiformatMessageString(text="A tool that performs static code analysis."),
                           # 3.19.2 at least one of version or semanticVersion SHOULD be present
                           semantic_version=version,
                           information_uri=info_uri,
                           organization=organization,
                           notifications = await SastRunTransformer.__notifications_factory(metrics),
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
                 id=f"projectid/{SastRunTransformer.__safeget("projectId", metadata)}/scanid/{SastRunTransformer.__safeget("scanId", metadata)}",
                 guid=SastRunTransformer.__safeget("scanId", metadata),
                 correlation_guid=SastRunTransformer.__safeget("projectId", metadata)
               ),  
               column_kind="unicodeCodePoints")
  