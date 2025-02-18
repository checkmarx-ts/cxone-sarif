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
  def make_camel_case(s : str) -> str:
    return s.replace("_", " ").title().replace(" ", "")
  
