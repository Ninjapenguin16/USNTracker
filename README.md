# USN Tracker

This program uses the Windows API and the built-in USN journal to track all changes made to an NTFS formatted drive

It is ready to use out of the box but if you intend to use the blacklist or whitelist feature you must have the "Lists" folder in the same directory, "Blacklist.txt", and "Whitelist.txt"


It should be able to compile with any Windows C compiler as long as Unicode support is enabled. On GCC this is done with the -municode flag

All paths given to the program, both in the list files and with the -f flag, must not end with '\\' or it will be misread

## Program Options
-b            | Enable the blacklist\
-w            | Enable the whitelist\
-f            | Specify a custom parent folder, default is C:\ (Cannot be outside the C: Drive for now)\
-h or --help  | Display the program options shown here
