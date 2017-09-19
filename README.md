# samtools - Python tools for the SAM-O interface (NBI for Nokia NSP) 
"samtools" is a collection of Nokia SAM-O tools in Python.

## csvtool.py - CSV Tool

The csvtool can be used for automation use-cases using SAM-O.

1) Find Requests (using XML)
```
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --xml findEpipe.xml
```

2) Find Requests (using class name, filters and result filters)
```
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --class epipe.Epipe
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --class security.Span --filter "spanId>9"
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --class netw.TopologyGroup --filter "<filter><and><equal name='application' value='sam'/><not><wildcard name='description' value='Default%%'/></not><notEqual name='displayedName' value='UnmanagedNEs'/></and></filter>"
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --class trapmapper.AlarmCatalogue --children

```
After reviewing the CSV files, it is possible to use the items contained as input for a batch request against Nokia NSP. For this, an XML file needs to be specified. Every row of the CSV file is used to fill the XMLAPI template and is executed:

1) Simple Request
```
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --batch epipe.Epipe.csv --xml xml\modEpipe.xml
```

2) Combine Find/Execute in one request (no need for CSV)
```
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --class epipe.Epipe --xml xml\modEpipe.xml
```

3) Improve performance using bulk size
```
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --batch epipe.Epipe.csv --xml xml\modEpipe.xml --bulksize 100 --warn
```

4) Store failed objects in another CSV file
```
$ csvtool.py -s 10.0.0.1 -u SamOClient -p 5620Sam! --batch epipe.Epipe.csv --xml xml\modEpipe.xml --store

```

Some more options:
* Use option "--secure" if SAM security (certificate based) is enabled.
* Use option "--md5" if SAM user password is already md5 hashed.
* Use option "--csv" to define output CSV file name (default is [classname].csv)
* Use option "--help" to get some usage information
* Use option "--delay" to slow down batch execution
* Use option "--result -1" to define the XML hierarchy level to determine objects
* Use option "--separator" to specify the delimiter used in CSV files
* Use option "--interactive" to prompt interactively for username and password
* Use option "--logfile -" to write log 

