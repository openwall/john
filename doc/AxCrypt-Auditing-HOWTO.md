# Auditing AxCrypt secrets:

According to its official website, AxCrypt "is the leading open source file
encryption software for Windows. It integrates seamlessly with Windows to
compress, encrypt, decrypt, store, send and work with individual files".

You can whether install it through provided setup or use install-free binaries
(which provide less features, like caching secrets).

AxCrypt cryptographic scheme relies on symetric cryptography using AES in ECB
mode to protect the "Data-Encryption-Key" (DEK) and AES in CBC mode to (un)cipher
data, using the DEK.
HMAC-SHA1 is used for integrity.

## Here are how interesting things work for us:

### 1) Common operations:

**Ciphering file:**

* User is prompted for a passphrase (if using GUI, otherwise it can be done
through command line)
* Passphrase is hashed using raw-SHA1
* Resultant SHA1 is truncated to 16 bytes and XORed with a random
salt (stored in the final ciphered file header)
* Resultant is used as a "Key-Encryption-Key" (KEK) for AES wrapping
algorithm, recommended by FIPS, to cipher ('0xa6'*8 | DEK)
* The previously wrapping algorithm is iterated (minimum number is set to
10000) and number of iterations depends on ciphering-computer
capabilites, which means the stronger, the higher number (this is quite odd
for a tool mainly used to share ciphered files...). Number of iterations is
stored in the registry

The user can also use a "key-file" associated with the passphrase. This key-file
can be any file and the only thing that changes in previous description is the
first step where the content of the key-file is simply appended to the
passphrase before hashing to SHA1.

AxCrypt provides the feature to create a self-decrypting file. In fact, it
creates the decrypting stub and simply appends the cipher file at the end of
the PE

*NOTE:* there is no way to know if a key-file was used or not, as any file can be
used. Nevertheless, AxCrypt can create key-files for the user. This
key file is a 56 bytes base64-encoded *".txt"* and defaults names are depending on
language:

Language=ENU:My Key-File.txt
Language=SVE:Min Nyckelfil.txt
Language=DEU:Meine Schlüssel-Datei.txt
Language=FRA:Mon fichier-clef.txt
Language=ESN:Mi Fichero llave.txt
Language=ITA:Il Mio Key-File.txt
Language=HUN:Kulcsfájlom.txt
Language=NOR:My Key-File.txt
Language=NLD:Mijn sleutelbestand.txt
Language=DNK:Min nøglefil.txt
Language=POL:Mój Plik-Klucz.txt
Language=CHI:My Key-File.txt
Language=PTG:My Key-File.txt
Language=PTB:Meu arquivo-chave.txt
Language=RUS:Мой файл ключа.txt
Language=CZH:MMůj Soubor-s-klíčem.txt
Language=FIN:Oma avaintiedostoni.txt

So if you manage to find a file matching some of these conditions, it is likely
to be the good key-file :-)

**How to get data to use with Jtr cracker:**

    $ axcrypt2john.py <axxfile> [KEY-FILE]

         <axxfile> can either be a .axx ciphered file or a self-decrypting binary
         [KEY-FILE] is optionnal


**How to crack using Jtr cracker:**

    use "--format=axcrypt" providing axcrypt2john.py's output


### Miscellaneous operations:

**Caching secrets:**

* AxCrypt provides a way to cache secrets for the end-user, so that
he will not have to type his passphrase again
* This option is the default one
* User can clear keys from cache, but if he doesn't, secrets won't
vanish from memory unless process is explicitely killed (no other method
is available to stop the process)
* Secrets are stored in the raw-SHA1 16 bytes form, "in memory"
* Theses secrets are sufficient enough to uncipher corresponding
ciphered files (remember: DEK is protected by this SHA1 XORed with
a salt, present in the ciphered file header)

**Brotip:**

* There is a file handle available to everyone to be duplicated, if you have
the right integrity level ;-)
* The method to gather those secrets is left as exercise to the reader

**How to crack these SHA1 using Jtr cracker:**

    if you really want to retrieve the passphrase:
        - use "--format=raw-sha1-axcrypt"
