#!/usr/bin/env python
# 
# Author: Dave Hull
# License: We don't need no stinking license. I hereby place
# this in the public domain.
#
# Todo: 
# 
# It's a secret.

# Args: arguments
# Returns: none
# Checks the arguments to make sure they are sane
def check_args(args):
    print "[+] Checking command line arguments."

    try:
        fi = open(args.filename, 'rb')
    except:
        print "[+] Could not open %s for reading." % (args.filename)
        parser.print_help()
        quit()
    if fi.read(1) == '0':
        print "[+] %s may be a bodyfile." % (args.filename)
    else:
        print "[+] %s does not appear to be a bodyfle." % (args.filename)
        parser.print_help()
        quit()
    fi.close()

    if args.meta not in ['mode', 'uid', 'gid', 'atime', 'mtime', 'ctime', 'crtime']:
        print "[+] Invalid --meta argument: %s" % args.meta
        parser.print_help()
        quit()

    return

# Args: filename
# Returns: Dictionary of dictionaries containing paths, paths contain files
# files contain metadata for each file.
def get_meta(bodyfile):
    fname_skip_cnt = bad_line = total_lines = 0
    meta = {}

    fi = open(bodyfile, 'rb')
    for line in fi:
        total_lines += 1
        try: 
            md5,ppath,inode,mode,uid,gid,size,atime,mtime,ctime,crtime = line.rstrip().split("|")
        except:
            bad_line += 1
            continue

        fname = os.path.basename(ppath).rstrip()
        if fname == ".." or fname == ".":
            fname_skip_cnt += 1
            continue

        pname = os.path.dirname(ppath).rstrip()
        if pname not in meta:
            meta[pname] = {}

        meta[pname][fname] = {}
        meta[pname][fname]['mode'] = mode
        meta[pname][fname]['uid'] = uid
        meta[pname][fname]['gid'] = gid
        meta[pname][fname]['atime'] = atime
        meta[pname][fname]['mtime'] = mtime
        meta[pname][fname]['ctime'] = ctime
        meta[pname][fname]['crtime'] = crtime

    print "[+] Discarded %d files named .. or ." % (fname_skip_cnt)
    print "[+] Discarded %d bad lines from %s." % (bad_line, args.filename)
    print "[+] Added %d paths to meta." % (len(meta))

    return meta

# Args: sorted directory listing contain unsorted dictionary 
# of files & meta data
# Returns: none
# Displays the distribution and "probability" of metadata for 
# files on a per directory basis. This has proven useful in 
# cases where an attacker has installed new files, but 
# neglected to change the metadata values to reflect the 
# "normal" values for the given directory.
def print_meta_freq_by_dir(items, id_type):
    for path_name, file_name in items:
        freq = {}
        files = [(filename, meta) for filename, meta in file_name.items()]
        files.sort()
        for filename, meta in files:
            meta_elem = meta[id_type]
            freq[meta_elem] = freq.get(meta_elem, 0) + 1
        
        # swap uid and cnt without clobbering uniques
        ugid_cnt = [(cnt, meta_elem) for meta_elem, cnt in freq.items()]
        ugid_cnt.sort()
        if len(ugid_cnt) > 1:
            print "\nPath: ",  path_name
            linesep = "-------------------------------------------"
            print "Count\t%s\t%%" % id_type
            print linesep
            ttl_files = float(len(files))
            probability = {}
            for cnt, meta_elem in ugid_cnt:
                probability[meta_elem] = cnt / ttl_files
                if id_type in ['atime', 'ctime', 'mtime', 'crtime']:
                    print "%6d\t%5s\t%.2f%%" % (cnt, strftime("%Y %m %d %H:%M:%S", gmtime(float(meta_elem))), probability[meta_elem] * 100.0)
                else:
                    print "%6d\t%5s\t%.2f%%" % (cnt, meta_elem, probability[meta_elem] * 100.0)
    return

# Args: dictionary
# Returns: sorted list of dictionaries
def get_meta_by_dir(dictionary):
    # Sort the dictionary, return a list of dictionaries
    items = [(pname, fname) for pname, fname in dictionary.items()]
    items.sort()
    return items

if __name__ == '__main__':
    import re, os, math, argparse, sys
    from time import gmtime, strftime 

    parser = argparse.ArgumentParser(description = \
        'This script parses an fls bodyfile and returns the uid or gid ' \
        'distribution on a per directory basis.')
    parser.add_argument('--meta', help = '--meta can be mode, uid, gid, atime, ' \
        'mtime, ctime, crtime. Default is "uid"', dest = 'meta', default = 'uid')
    parser.add_argument('filename', help = 'An fls bodyfile, see The Sleuth Kit.')
    if len(sys.argv) == 1:
        parser.print_help()
        quit()
    args = parser.parse_args()

    check_args(args)

    files_meta = get_meta(args.filename)

    dir_sorted_meta = get_meta_by_dir(files_meta)
    print_meta_freq_by_dir(dir_sorted_meta, args.meta)
