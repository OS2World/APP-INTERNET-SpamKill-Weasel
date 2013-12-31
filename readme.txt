/* readme.txt */

SpamKill is stage 4 filter for Weasel.
It use 4 technics to kill spam:
1) dns filtering on ordb.org -like servers
2) Bayesian spam filter (SpamKill2 - bogofilter)
3) Using "spam addresses" for SpamKill2 autolearning
4) History for last NN sec

Install:
Place SpamKill.exe, SpamKill.cfg, spamaddr, passwd and  SpamWords.txt
to Weasel root directory.

Look at  SpamKill.cfg, spamaddr, passwd and  SpamWords.txt
and change YOURDOMAIN and  YOUR_RELAYDOMAIN (if any) to your values
Look at external filter calls  in SpamKill.cfg and change it if your prefer
use some other filter. SpamKill2 your can take from  SpamKill2.zip at hobbes.

SY,
EK
v0.50
Added parameters ExtFilterMaxFsizeRegAsSpam and ExtFilterMaxFsizeRegAsNoSpam
due to fact that bogofilter can register binary attachments as a huge collection
of words.

v0.49
- fixed bug with trusted detection
- fixed bug with multi-users To: and CC: field

v0.48
- add mutex semaphore for reading/writing  SpamCount.cnt. This should
   solve problem when two or more e-mails are checked in the same time.
- fixed bug in textList.Checki_sep()
