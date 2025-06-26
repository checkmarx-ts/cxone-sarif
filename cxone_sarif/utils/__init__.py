
def normalize_file_uri(fname : str) -> str:
  return "/" + fname.lstrip("/")