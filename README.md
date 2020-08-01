# CpUpES2-Decrypt
A tool to decrypt "UpdaterES2.CpUp" from PSVita DevKit Update Files as well as the "fsimage1.trf" Encrypted AXFS Filesystem image inside it.          
             
Made possible by Zecoaxco and VVildCard777 for dumping the CP EMMC.           
And Mathieulh for helping me with stuffs, and answering all my stupid questions.              
               
Output is a tar.gz file, where fsimage1.trf is signed&encrypted, and fsimage0.trf is signed (but unencrypted) AXFS file-system image.             

For reading, try https://github.com/olebeck/axfs/releases, unless you have your own way of reading axfs t-T
