Check windows files for viruses and malwares against microsoft authenticode, NIST database and virus total

Required arguments:
  -f FILE, --file FILE          Choose the NIST database file
  -d DISK, --disk DISK          Choose the disk you want to search
  -k APIKEY, --apikey APIKEY    Virus total api key

Example:
python3 forensics.py -f NSRLFile.txt -d C:\\ -k 7880e6f487c496e7cb7a048a1e1760062362ed6
