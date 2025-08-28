# CSV Merger

## Abstract
Merges multiple CSV outputs from Nessus into a single CSV file.

## How to Launch
1. Switch working directory to source directory (i.e. the directory containing *.csv to be merged).
<code>
cd path/to/source_directory
python3 another/path/to/merge_csv.py
</code>

2. Pass the path to source directory to the command line as argument.
<code>python3 path/to/merge_csv.py another/path/to/source_directory</code>

## Output File
### Default Output File
<code>${source_directory}/merge_csv_output.csv</code>

To use another filepath or filename, pass the desired filepath to the command line as the 2nd argument, following the path to source directory.

## Version
<code>python3 path/to/merge_csv.py -v</code>
or
<code>python3 path/to/merge_csv.py --version</code>

## Help
<code>python3 path/to/merge_csv.py -h</code>
or
<code>python3 path/to/merge_csv.py --help</code>