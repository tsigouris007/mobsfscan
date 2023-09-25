#!/bin/sh

# Define default values for options
WORKDIR="/data"
TMPDIR="/tmp"
OUTPUT_FILE_JSON_O="${WORKDIR}/report.mobsfscan.original.json"
OUTPUT_FILE_JSON="${WORKDIR}/report.mobsfscan.json"

# Run the tool
mobsfscan --json -o $OUTPUT_FILE_JSON_O "$@"

# Format the final json report
python /report.py -i $OUTPUT_FILE_JSON_O -o $OUTPUT_FILE_JSON
