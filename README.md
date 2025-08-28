# CSV Merger

## Abstract
Merges multiple CSV outputs from Nessus into a single CSV file.  
The *.nessus files with the same names as the *.csv files in the same folder will be parsed to insert additional information to the output .csv file.  

## How to Launch
1. Switch working directory to source directory (i.e. the directory containing *.csv to be merged).  
```
cd path/to/source_directory
python3 another/path/to/merge_csv.py
```
  
or  
2. Pass the path to source directory to the command line as argument.  
`python3 path/to/merge_csv.py another/path/to/source_directory`

## Output File
### Default Output File
`${source_directory}/merge_csv_output.csv`

To use another filepath or filename, pass the desired filepath to the command line as the 2nd argument, following the path to source directory.  
  
e.g. `python3 path/to/merge_csv.py another/path/to/source_directory path/to/destination.csv`  

## Version
`python3 path/to/merge_csv.py -v`  
or  
`python3 path/to/merge_csv.py --version`  

## Help
`python3 path/to/merge_csv.py -h`  
or  
`python3 path/to/merge_csv.py --help`  