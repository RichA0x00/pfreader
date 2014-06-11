#README.TXT - Prefetch Reader Version A1C

This program decodes Windows Prefetch files for experimental and forensic purposes. 


Some key features:

-Output to TSK Body (Time line / mactime) format.

--Shown under the Accessed time stamp.

--Windows 8 files will include multiple execute time stamps. 

--Optionally add time stamps from file system.

---Will use real create time if available (Windows API -create time- / MAC OSX -birth time-) 

---Note: If not using the time stamps from the file system then all other values are 0.

-HTML Reporting

-Verifies the hash at the end of the file name.
--Will attempt an optional list of command line arguments that would affect the hash at the end of the file name.

-Will accept multiple files as well as directories.
--Note: Will only test *.pf extensions within a directory query (example no specific file specified.)

-Optionally compile with OpenSSL to include MD5 and SHA1 Hash Files

-CYGWIN/OSX/Linux compatible

This program was written to for the purpose of learning about the structures within a prefetch file.

The concepts and reversing of this file format was completed by many 
others. So this code is not new by any means but I did incorporate aspects from many different designs and suggestions that I found on the web.

And I tried to write this up with a bit of my own flair and only taking look at some examples to get the general idea. 
But please see my links below and look at the great tools created by others. 

Just a fair warning - some aspects of this code is experimental.
If anything is questionable please verify with another tool and I welcome suggestions.

Some specific web sites that gave me some insight:
The Forensic WIKI and it's accompanying links related to prefetch files.
http://www.hexacorn.com/blog/2012/06/13/prefetch-hash-calculator-a-hash-lookup-table-xpvistaw7w2k3w2k8/


Compile instructions:
With OPEN SSL
make

Without OPEN SSL
make pfreader-simple

Do a quick 'cat Makefile' to see if any other compile options might work for you if the standard fails.

There is no make install - If you would like; just copy the binary to /usr/local/bin or other location within your path.

Please check out the --help for specific command line options.

Thanks for reading,
@RichA0x00
