# USN Tracker

This program uses the Windows API and the built-in USN journal to track all changes made to an NTFS formatted drive

It is ready to use out of the box but if you intend to use the blacklist or whitelist feature you must have the "Lists" folder in the same directory, "Blacklist.txt", and "Whitelist.txt"


It should be able to compile with any Windows C compiler as long as Unicode support is enabled. On GCC this is done with the -municode flag
