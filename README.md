# samtools - Python tools for the SAM-O interface (NBI for Nokia NSP) 
"samtools" is a collection of Nokia SAM-O tools in Python.

## csvtool.py - CSV Tool

The csvtool can be used for automation use-cases using SAM-O.

1) Find Requests (using XML)
```
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --xml findEpipe.xml
```

2) Find Requests (using class name, filters and result filters)
```
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --class epipe.Epipe
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --class security.Span --filter "spanId>9"
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --class netw.TopologyGroup --filter "<filter><and><equal name='application' value='sam'/><not><wildcard name='description' value='Default%%'/></not><notEqual name='displayedName' value='UnmanagedNEs'/></and></filter>"
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --class trapmapper.AlarmCatalogue --children

```
After reviewing/changing the CSV files they can be used for running batch requests against Nokia NSP.
An XML file needs to be specified. Every data row of the CSV file is used to fill the XMLAPI template and is executed:

3) Simple Request
```
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --batch epipe.Epipe.csv --xml xml\modEpipe.xml
```

4) Combine Find/Execute in one request (no need for CSV)
```
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --class epipe.Epipe --xml xml\modEpipe.xml
```

5) Improve performance using bulk size
```
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --batch epipe.Epipe.csv --xml xml\modEpipe.xml --bulksize 100 --warn
```

6) Store failed objects in another CSV file
```
$ csvtool.py -s 10.0.0.1 -u NbiUser -p p@ssw0rD --batch epipe.Epipe.csv --xml xml\modEpipe.xml --store

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


## License

This project is licensed under the BSD-3-Clause license - see the [LICENSE](https://github.com/nokia/samtools/blob/master/LICENSE).