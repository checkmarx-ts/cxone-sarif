from typing import Dict, Any
from sarif_om import Run

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
