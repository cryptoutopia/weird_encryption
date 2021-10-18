# Encrypt everything

This was sort of an assignemnt to school. Basically a random key is generated to encrypt a file or string, the key is encrypted using GPG and a recipient.
Decryption `instructions` are appennded to the file header. See for yourself.

it uses ChaCha20PolyWhatever.

##Encrypt
```
cat some.file | python app.py -e -r some@email.com
```

##Decrypt
```
cat encrypted_using_this_tool.txt | python app.py -d [-p passphrase] 
```
