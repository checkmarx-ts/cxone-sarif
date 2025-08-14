# Release Notes

## 1.0.4

* Changes to the `get_sarif_v210_log_for_scan` entrypoint method for the module.
  * Returned `SarifLog` object is a subclass that has a `asjson()` method that serializes the log into JSON.
  * Optional parameters `clone_url` and `branch` will take precedence over values found in the scan information.

## 1.0.3

* A few bug fixes related to interpreting missing JSON fields for some SAST results.
* All "Not Exploitable" results are now excluded from all engines that support state triage.
* Added a value for the Sarif standard `level` translated from each engine's Severity concept.

## 1.0.2

* Detailed work to make the Sarif output more compatible with GitHub security result display.

