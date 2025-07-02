
def normalize_file_uri(fname : str) -> str:
  return fname.lstrip("/")


class SeverityTranslator:

  # GitHub's rules

  __severity_table = {
    "critical" : "9.0",
    "high" : "8.9",
    "medium" : "6.9",
    "low" : "3.9"
  }

  __default_severity = "0.0"

  @staticmethod
  def translate_severity_to_level(severity : str):
    k = severity.lower() if severity is not None else None
    
    if k is None or k not in SeverityTranslator.__severity_table.keys():
      return SeverityTranslator.__default_severity
    else:
      return SeverityTranslator.__severity_table[k]
