"""
domain_reuse_check.py
Finds domain accounts sharing the same NT hash (password reuse) in an NTDS
dump produced by impacket's secretsdump.py.
 
Prompts for: NTDS file, export file, minimum group size, include blank hash.
Exports a text report (same format as the console) plus a CSV written
alongside the export file:
    <export>.csv
 
Default export is <NTDS file name>_domain_reuse.txt next to the NTDS file
(e.g. /path/to/ntds.txt -> /path/to/ntds_domain_reuse.txt).
 
Notes:
  - Password history: if the dump was taken with -history, entries like
    user_history0 are counted as separate accounts, so a user who reused an
    old password shows up as a shared hash between user and user_history0.
  - Account status isn't checked; disabled accounts are included.
  - Compare against local SAM dumps with hash_reuse_check.py.
 
Expects secretsdump.py-format lines:
    DOMAIN\\username:RID:LMHASH:NTHASH:::
"""
