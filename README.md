# Ransomware-in-Windows
<p>A Random Ransomware for Windows written in C.</p>

<h1> Description </h1>
<p> The purpose of this code was simply to learn more about WinApi encryption functions while having fun.
The Code is AWFUL LOL but bare with me, It's my first .</p>

<p> The code Encrypts all the files in a directory and its subdirectories recursively, Then it generates a RansomNote.txt file for instructions and also export the decryption key to a key.txt file. You will be asked to specifiy the key.txt file in order to decrypt all files.</p> 
 
<p> PS : you can check that your files are encrypted before decrypting them.</p>

<p> You might need to link the "comdlg32" lib in order to use the Openfile dialog box. Don't take risk and Make sure to use disposable test files.</p>

<h1> POC </h1>
Video of the usage in Poc.mp4
