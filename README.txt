A C implementation of the AES encryption standard. This code supports 128, 192 and 256 bit encryption.

Note that to use this you need permission to read the file, write to a new file. You might also need 
permission to delete files if you choose to delete the old files.

The necessary arguements to use this are:
	-k=key     	After the = sign you type in the key that you wish to use for encryption. 
			If it's too long the program will truncate it, if it's too short the key will 
			be padded out.

	-d		If you wish to use the decryption then add a -d, this will make the program 
			decrypt the file. Note that this should only be used on encrypted files 
			(by default: those that have a .enc at the end) as the behaviour is 
			unknown for regular files. Note that if the old file still exists with 
			the same name then the decryption will overwrite the file so either 
			rename it or delete it.

The format for calling this should be:
executable_name -k=key file_name

As the file name should be last. This program only supports 1 file and no directories.

Example use:
AES -k=test_key_ff -r -type=192 test.txt 
AES -k=test_key_ff -r -d -type=192 test.txt.enc

Extra arguements that are useful:
	-type=#		You can specify which encryption type to use, the only values that 
			can be written in the # are: 128, 192, 256.

	-r		You can have the program automatically delete the old file 
			(whether it's the encrypted file after decryption or regular 
			file after encryption).