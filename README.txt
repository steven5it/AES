Name: Steven Lee

EID/CSID: SCL346



*** Notes ***
Implementation of AES-128 commercial block cipher algorithm:
Given inputFile of a variable number of 32 hex character lines (128-bits) and keyFile of 32 hex characters, perform AES operations.
If e option is provided, then encryption is done and the cipherText is output to a new file called inputFile.enc.
If d option is provided, then decryption is done and the cipherText is output to a new file called inputFile.dec.

*** Speed test ***
Testing 10x on 10 random lines of valid input for inputFile:
encryption average MB/sec: 0.1080918 MB/s
decryption average MB/sec: 0.1045422 MB/s
% difference = 3.39%

There does not seem to be a significant difference between encryption and decryption speeds (could be random processor speed)
