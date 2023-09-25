import os, sys, json, argparse, hashlib

def read_field(field_name, obj):
  try:
    field_value = obj[field_name]
  except Exception as e:
    return ""
  return field_value

def total_findings(json_file):
  issues = {'critical': 0, 'high': 0, 'medium': 0, 'weak': 0}
  ignored = {'critical': 0, 'high': 0, 'medium': 0, 'weak': 0}

  warn_findings_cnt = 0
  info_findings_cnt = 0
  warn_rules = []
  info_rules = []
  warn_findings = []
  info_findings = []

  with open(json_file) as json_f:
    data = json.load(json_f)

    for vulngrp in data["results"]:      
      # Extract metadata
      metadata = None
      try:
        metadata = data["results"][vulngrp]["metadata"]
      except Exception:
        pass

      if metadata != None:
        cwe = read_field("cwe", metadata)
        descr = read_field("description", metadata)
        masvs = read_field("masvs", metadata)
        owasp = read_field("owasp-mobile", metadata)
        reference = read_field("reference", metadata)
        severity = read_field("severity", metadata)

        if severity == "WARNING":
          if not masvs in warn_rules:
            warn_rules.append(masvs)
        else:
          if not masvs in info_rules:
            info_rules.append(masvs)

      # Extract files
      files = None
      try:
        files = data["results"][vulngrp]["files"]
      except Exception:
        pass
      
      # There are 2 cases. One includes both files + metadata, the other includes only metadata.
      if files != None:
        for f in files:
          file_path = read_field("file_path", f)
          match_lines = read_field("match_lines", f)
          start_line = match_lines[0]
          end_line = match_lines[1]
          match_position = read_field("match_position", f)
          start_position = match_position[0]
          end_position = match_position[1]
          match_string = read_field("match_string", f)

          # Create fingerprint
          finger_txt = vulngrp + ":" + file_path + ":" + str(start_line) + ":" + str(end_line) + ":" + str(start_position) + ":" + str(end_position)
          m = hashlib.sha256(finger_txt.encode('UTF-8'))
          vuln_hash = m.hexdigest()

          # Pack as a structure
          finding = {
            vuln_hash: {
              "warning_type": vulngrp,
              "cwe": cwe,
              "check_name": masvs,
              "message": "[" + owasp + "] " + descr,
              "file": file_path,
              "line": start_line,
              "col": start_position,
              "reference": reference,
              "severity": severity,
              "code": match_string
            }
          }

          if severity == "WARNING":
            warn_findings_cnt += 1
            warn_findings.append(finding)
          else:
            info_findings_cnt += 1
            info_findings.append(finding)
      else:
        # Create fingerprint
        finger_txt = vulngrp + ":" + cwe + ":" + masvs + ":" + severity
        m = hashlib.sha256(finger_txt.encode('UTF-8'))
        vuln_hash = m.hexdigest()

        finding = {
            vuln_hash: {
              "warning_type": vulngrp,
              "cwe": cwe,
              "check_name": masvs,
              "message": "[" + owasp + "] " + descr,
              "file": "",
              "line": -1,
              "col": -1,
              "reference": reference,
              "severity": severity,
              "code": ""
            }
          }

        if severity == "WARNING":
          warn_findings_cnt += 1
          warn_findings.append(finding)
        else:
          info_findings_cnt += 1
          info_findings.append(finding)

  # Build the final result object
  total_findings_cnt = info_findings_cnt + warn_findings_cnt
  out = {
    "warnings": {
      "warning": warn_findings_cnt,
      "info": info_findings_cnt,
      "total": total_findings_cnt
    },
    "ignored_warnings": {
      "warning": 0,
      "info": 0,
      "total": 0
    },
    "findings": {
      "warning": warn_rules,
      "info": info_rules
    },
    "fingerprints": {
      "warning": warn_findings,
      "info": info_findings
    }
  }

  return json.dumps(out, indent=2)

def write_outfile(json_obj, out_file):
  f = open(out_file, "w")
  f.write(json_obj)
  f.close()

def main():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-i', '--input', type=str, required=True, help='The insider input JSON file.')
  parser.add_argument('-o', '--output', type=str, required=False, default="stdout", help='Specify an output file. If left empty prints to stdout.')
  args = parser.parse_args()

  in_file = args.input
  out_file = args.output

  if not os.path.isfile(in_file):
    print("Please specify an existing input JSON file.")
    sys.exit(2)

  results = total_findings(in_file)

  if out_file == "stdout":
    print(results)
  else:
    write_outfile(results, out_file)

if __name__ == "__main__":
  try:
    main()
  except Exception as e:
    print("Exception occured.", str(e))
    sys.exit(1)
