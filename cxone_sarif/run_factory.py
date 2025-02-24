from typing import Dict, List, Any
from sarif_om import MultiformatMessageString
from cxone_api import CxOneClient
 

class RunFactory:

  """
  A static GUID for the tool producing the Run entry in the Sarif log.
  """
  @staticmethod
  def get_tool_guid() -> str:
    raise NotImplemented("get_tool_guid")
  

  @staticmethod
  def get_value_safe(key : str, json : Dict) -> Any:
    if key in json.keys():
      return json[key]
    else:
      return None

  @staticmethod
  def __prep_identifier(s : str) -> str:
    non_alphanum = [c for c in s if not c.isalnum() and not c.isspace()]

    clean = s

    for c in non_alphanum:
      clean = clean.replace(c, " ")

    return " ".join([item for item in clean.split(" ") if len(item) > 0])

  @staticmethod
  def make_camel_case_identifier(s : str) -> str:
    out = RunFactory.make_pascal_case_identifier(s)
    return (out[0].lower() + out[1:])
  
  @staticmethod
  def make_pascal_case_identifier(s : str) -> str:
    return "".join([x.capitalize() for x in RunFactory.__prep_identifier(s).split(" ")])


  @staticmethod
  def make_cve_description(cve_id : str, description : str, references : List[str]) -> MultiformatMessageString:

    if references is not None:
      text_references = "\n".join(references)
      markdown_references = f"## References\n{"\n".join([f"* [{x}]({x})" for x in references])}"
    else:
      text_references = ""
      markdown_references = ""

    return MultiformatMessageString(
      properties = { "references" : references },
      text = f"{cve_id}\n{description}\n\n{text_references}",
      markdown = f"# {cve_id}\n## Description\n{description}\n{markdown_references}"
    )

  @staticmethod
  def make_cve_help_url(client : CxOneClient, cve_id : str) -> str:
    # CVEs can be found in the NVD.

    # Some vulnerabilities have internal advisory numbers which can be found
    # in the Checkmarx appsec KB.  This data requires authentication to view.

    __sca_help_base = f"{client.api_endpoint.rstrip("/")}/sca/#/appsec-knowledge-center/vulnerability/riskId/"
    __nvd_help_base = "https://nvd.nist.gov/vuln/detail/"
    __cve_prefix = "cve"

    if cve_id is None:
      return None

    if len(cve_id) > len(__cve_prefix) and cve_id.lower().startswith(__cve_prefix):
      return __nvd_help_base + cve_id
    else:
      return __sca_help_base + cve_id
