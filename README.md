# Bloons TD6 Save decrypt/encrypt tool

This program will encrypt/encrypt Bloons TD6 save files (Profile.Save, identity)

Usage:

```
bloonstd6crypt [-d --decrypt | -e --encrypt] <input file> <output file>
```


To decrypt a save:


```
bloonstd6crypt -d Profile.Save Profile_decrypted.Save 
```

To encrypt:

```
bloonstd6crypt -e Profile_edited.Save Profile.Save 
```

All of files named above are JSON formatted when decrypted.
