import argparse
import os
import requests
import hashlib
import time
import csv
import pefile


def hash_creator(filepath):
    h = hashlib.sha1()
    with open(filepath, 'rb') as f:
        buf = f.read(2 ** 20)  # load big files in chunks
        h.update(buf)
    return h.hexdigest()


def search_nist_db(files_dict, nist_file):
    # [sha_list.pop() for x in sha_list if x in line]
    if not os.path.isfile(nist_file):
        print("Nist database does not exist")
        return files_dict
    if len(files_dict) > 0:
        print("Checking {} files against NIST database...".format(len(files_dict)))
        with open(nist_file, 'r', encoding='latin-1') as file:
            for line in file:
                for key, value in files_dict.copy().items():
                    if key.upper() in line:
                        del files_dict[key]
        return files_dict
    return files_dict


def is_signed(filename):
    """Returns True if the file is signed with authenticode"""
    p = None
    try:
        p = pefile.PE(filename)
        # Look for a 'IMAGE_DIRECTORY_ENTRY_SECURITY' entry in the optional data directory
        for d in p.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY' and d.VirtualAddress != 0:
                return True
        return False
    except:
        return False
    finally:
        if p:
            p.close()


# process each file and produce a list of sha1 values
def process_files(path):
    print("Checking for digital signed files...")
    files_dict = {}
    for subdir, dirs, files in os.walk(path):
        for file in files:
            filepath = subdir + os.sep + file
            if is_signed(filepath):
                continue
            else:
                try:
                    hash_value = hash_creator(filepath)
                    files_dict.update({hash_value: filepath})
                except OSError as e:
                    print(e)
    return files_dict


def virus_total_check(files_dict, apikey):
    if len(files_dict) > 0:
        try:
            print("Checking {} files against virus total database...".format(len(files_dict)))
            info_list = []
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            for key, value in files_dict.items():
                params = {'apikey': apikey, 'resource': key}
                # always delay 26 seconds in each request
                time.sleep(26)
                response = requests.get(url, params=params)
                data = response.json()
                if data['response_code'] == 1:
                    if data['positives'] == 0:
                        continue
                    else:
                        record = "{0},{1},{2} of {3} engines detect this file".format(value, data['permalink'], data['positives'], data['total'])
                        info_list.append(record)
                    # write list info to csv
            if len(info_list) > 0:
                with open('files.csv', 'w', newline='') as csvfile:
                    linewriter = csv.writer(csvfile, delimiter=',',
                                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
                    linewriter.writerow(['file-path', 'permalink', 'engines-detect'])
                    for element in info_list:
                        linewriter.writerow([element])
        except:
            with open('not-checked.csv', 'w', newline='') as csvfile:
                linewriter = csv.writer(csvfile, delimiter=',',
                                        quotechar='|', quoting=csv.QUOTE_MINIMAL)
                linewriter.writerow(['file-path', 'permalink', 'engines-detect'])
                for key, value in files_dict.items():
                    linewriter.writerow([key, value])
            print("A problem occurred. Files not checked against virus total saved in not-checked.csv file")
    else:
        print("No files to scan")


def main():
    parser = argparse.ArgumentParser(description='Check windows 10 files')
    parser.add_argument('-f', '--file', help='Choose the NIST database file', required=True)
    parser.add_argument('-d', '--disk', help='Choose the disk you want to search', required=True)
    parser.add_argument('-k', '--apikey', help='Virus total api key', required=True)
    args = vars(parser.parse_args())
    nist_and_total_list = process_files(args['disk'])
    virus_total_list = search_nist_db(nist_and_total_list, args['file'])
    virus_total_check(virus_total_list, args['apikey'])


if __name__ == '__main__':
    main()
