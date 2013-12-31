/* SpamKill.cpp */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <io.h>
#define INCL_DOS
#define INCL_DOSERRORS          /* DOS Error values */
#include <os2.h>

#include "SK_config.hpp"
#include "Sk_mail.hpp"
#include "Sk_history.hpp"

#define APPLICATION  "SpamKiller"
#define VERS "0.50"
#define RELIZEDATA  __DATE__

/*+------------------------------------+*/
/*| Extern global variables            |*/
/*+------------------------------------+*/
/*+------------------------------------+*/
/*|   External functions prototypes    |*/
/*+------------------------------------+*/
int TestHostAtBlackList(char *HostIPQuery);

/*+------------------------------------+*/
/*| Internal global variables          |*/
/*+------------------------------------+*/
char IniFile[256] = "SpamKill.cfg";
char LogFile[256] = "SpamKill.log";
char SpamCountFile[]="SpamCount.cnt";
class SK_Config sk;
class Mail mail;
class MessageHistory history;
int CountMail=0, CountMailSpam=0;
#define CST_MUTEXSEM_NAME     "\\SEM32\\SPAMKILLCOUNT"
HMTX  SpamKillCount_hmtx     = NULLHANDLE; /* Mutex semaphore handle */

/*+------------------------------------+*/
/*|   Internal functions prototypes    |*/
/*+------------------------------------+*/
int usage(void);
int DelSpacesFromString(char *str);
int _log_print(const char *format,...);
int CopyFile(char *from, char *to);
void _Optlink SpamKill_cleanup(void);

static char *RulesInfo[] =
{  "No Spam",                    //0
   "ip found in blacklist",      //1
   "mail to relay without user", //2
   "ip found in history",        //3
   "mail to unknown relay user", //4
   "mail to spam user",          //5
   "external filter",            //6
   NULL
};
//  RuleNumber
// 1 - ip found in blacklist
// 2 - mail to relay without user
// 3 - ip found in history;
// 4 - mail to unknown relay user
// 5 - mail to spam user
// 6 - external (Bayesan) filter
int main(int n, char *par[])
{   char *mailFile;
    int rc,i,j, rcSpam = 0, historyId=0;
    int n_upsreamhost = 0, RuleNumber = 0, isMailToSpamUser = 0;
    double SpamIQ = 0.;
    char str[80];
    char cmdstr[312];

    if(n == 1)
    {   usage();
        exit(100);
    }
//   DosBeep(2000,1);
    if(n != 3)
    {  if(!stricmp(par[1],"-h") || !stricmp(par[1],"/h") || !stricmp(par[1],"/?") || !stricmp(par[1],"-help") || !stricmp(par[1],"/help") )
       {   usage();
           exit(100);
       }
    }
/********************/
    atexit(SpamKill_cleanup);
    rc = DosCreateMutexSem(CST_MUTEXSEM_NAME,      /* Semaphore name */
                           &SpamKillCount_hmtx, 0, FALSE);  /* Handle returned */
    if (rc != NO_ERROR)
    {  if(rc != ERROR_DUPLICATE_NAME)
       {   printf("DosCreateMutexSem error: return code = %u\n", rc);
          _log_print("Error: DosCreateMutexSem return code = %u\n", rc);
           exit(100);
       }
     }
    /* This would normally be done by another unit of work */
    rc = DosOpenMutexSem(CST_MUTEXSEM_NAME,      /* Semaphore name */
                         &SpamKillCount_hmtx);            /* Handle returned */
    if (rc != NO_ERROR) {
       printf("DosOpenMutexSem error: return code = %u\n", rc);
      _log_print("Error: DosOpenMutexSem return code = %u\n", rc);
       return 1;
     }

    rc = DosRequestMutexSem(SpamKillCount_hmtx,      /* Handle of semaphore */
                            (ULONG) SEM_INDEFINITE_WAIT);  /* Timeout  */
    if (rc != NO_ERROR) {
       printf("DosRequestMutexSem error: return code = %u\n", rc);
      _log_print("Error: DosRequestMutexSem return code = %u\n", rc);
       return 1;
    }

   {  FILE *fp;
//читаем счетчик
      fp=fopen(SpamCountFile,"r");
      fscanf(fp,"%d %d",&CountMail,&CountMailSpam);
      fclose(fp);
      CountMail++;
//пишем счетчик
      fp=fopen(SpamCountFile,"w");
      fprintf(fp,"%d %d\n",CountMail, CountMailSpam);
      fclose(fp);
   }
   rc = DosReleaseMutexSem(SpamKillCount_hmtx);

    strcpy(mail.fname,par[2]);
//read config
    rc = sk.Read(IniFile);
    if(rc == 1)
    {  printf("Can't read %s\n",IniFile);
      _log_print("Error: Can't read %s\n",IniFile);
           exit(99);
    }
//   DosBeep(3000,1);
//read mail header
    rc = mail.ReadHeader();
    if(rc)
    {   printf("Error reading %s\n",mail.fname);
       _log_print("Error: reading %s\n",mail.fname);
        exit(98);
    }
    mail.Close();
    history.Read(sk.historyFile);
    for(i=0; i < mail.header.nReceived; i++)
    {  int istrusted=0;
       printf("R.from: %s %s",mail.header.cReceivedFrom[i],mail.header.cReceivedFromIP[i]);
       for(j=0; j< sk.NtrustNet ;j++)
       { //  printf("mail.header.ReceivedFromIP[i]=%x\n",mail.header.ReceivedFromIP[i]);
         //  printf("sk.trusted[j].ip=%x \tsk.trusted[j].mask=%x\n",sk.trusted[j].ip, sk.trusted[j].mask);
         //  printf("mail.header.ReceivedFromIP[i] & sk.trusted[j].mask=%x\n",mail.header.ReceivedFromIP[i] & sk.trusted[j].mask);
         //  printf("sk.trusted[j].ip &  sk.trusted[j].mask=%x\n", sk.trusted[j].ip &  sk.trusted[j].mask);
//????     if(((~mail.header.ReceivedFromIP[i]) & sk.trusted[j].ip) &  sk.trusted[j].mask)  ;
           if( (mail.header.ReceivedFromIP[i] & sk.trusted[j].mask) == (sk.trusted[j].ip &  sk.trusted[j].mask))
           {  istrusted = 1;
              mail.header.lastTrustedReceivedFrom = i;
              break;
           }
       }
       if(istrusted)
                printf(" Trusted");
       else
                printf(" UnTrusted");
       if(mail.header.cReceivedFor[i]) printf(" For %s",mail.header.cReceivedFor[i]);
       printf("\n");
       mail.header.indSpamReceivedFrom = i;
       if(!istrusted) //check in history
       {  int rc1;
          rc1 =  history.CheckSpam(mail.header.ReceivedFromIP[i]);
          if(rc1 > 0) //Spam
          {     CountMailSpam++;
                rcSpam = 1;
                RuleNumber = 3;
                historyId = rc1 - 1;
                printf("Spam found in history (%s)\n",history.mhi[historyId].msgfile);
          }
       }
    }

    if(mail.header.To) printf("To: %s\n",mail.header.To);

//calc SpamIQ for header
/******************************************/
//todo: may be forged
    if(mail.header.To)
    {   char *pAt;
        int rcIn;
        if(!strnicmp(mail.header.To,"undisclosed-recipients", strlen("undisclosed-recipients")) )
                  SpamIQ += sk.Weight.ToEQundisclosed_recipients;
        else
           if(strstr(mail.header.To,"-recipients") )
                  SpamIQ += sk.Weight.ToEQundisclosed_recipients/2.;
           recipients:
//пройдем вверх по всем Received до первого for, если for = relayMailBox, то это означает, что письмо послано на деревню дедушке (неизвестному юзеру на relay)
        for(i = mail.header.nReceived - 1; i >= 0; i--)
        {  if(mail.header.cReceivedFor[i] && mail.header.ReceivedFromIP[i] != 0x7f000001)
           {  if(!stricmp(mail.header.cReceivedFor[i], sk.relayMailBox) )
              {  if(!strstr(mail.header.To, sk.relayDomain))  /* с Яндекса письма идут без for user, но в To: остается правильное имя */
                 {  SpamIQ += sk.Weight.ToNEfor * 2;
                    if(!rcSpam)
                    {    rcSpam = 2;
                         RuleNumber = 2;  //mail to relay without user
                         CountMailSpam++;
                    }
                 } else {
                    SpamIQ += sk.Weight.ToNEfor; //спамом не считаем, но коэффициент добавляем
                 }
               } else {
                  if(stricmp(mail.header.cReceivedFor[i], mail.header.To) )
                  {  if(!strstr(mail.header.To,mail.header.cReceivedFor[i]) )
                                SpamIQ += sk.Weight.ToNEfor;
                  }
               }
               break;
             }
        }

//chek for mail to SpamUser
        if(!rcSpam)
        {   rcIn = sk.UsersForSpamList.Checki_sep(mail.header.To);
            if(rcIn < 0)
            {   for(j=i; j >= 0 ; j--)
                {  if(mail.header.cReceivedFor[j])
                   {   if(!stricmp(mail.header.cReceivedFor[j], sk.relayMailBox) ) break;
                       rcIn = sk.UsersForSpamList.Checki_sep(mail.header.cReceivedFor[j]);
                       if(rcIn >= 0)
                              break;
                   }
                }
            }
            if(rcIn >= 0) //Mail To special Spam user
            {  RuleNumber = 5;  //mail to spam user
               rcSpam = 2;
               isMailToSpamUser = 1;
               SpamIQ += sk.Weight.MailToNonExistentUser;
               CountMailSpam++;
            }
        }
//chek for mail to relayMailBox
        if(!rcSpam)
        {   pAt = strstr(mail.header.To, sk.relayDomain);
            if(pAt && (*(pAt-1) == '@') )
            {
                rcIn = sk.relayUsersList.Checki_sep(mail.header.To);
                if(rcIn == -1) //Mail to non-existent user =
                {   SpamIQ += sk.Weight.MailToNonExistentUser;
                    RuleNumber = 4;
                    rcSpam = 2;
                    CountMailSpam++;
                }
            } else
                if(mail.header.cReceivedFor[i]) {
                  pAt = strstr(mail.header.cReceivedFor[i], sk.relayDomain);
                  if(pAt && (*(pAt-1) == '@') )
                  {  rcIn = sk.relayUsersList.Checki_sep(mail.header.cReceivedFor[i]);
                     if(rcIn == -1) //Mail to non-existent user =
                     {   SpamIQ += sk.Weight.MailToNonExistentUser;
                         RuleNumber = 4;
                         rcSpam = 2;
                         CountMailSpam++;
                     }
                  }
            }
       }
//ContentTransferEncoding
       if(mail.header.ContentTransferEncoding)
           if(!stricmp(mail.header.ContentTransferEncoding,"base64"))
               SpamIQ += sk.Weight.ContentTransferEncoding_base64;

    } else { //  (!mail.header.To) To: -  нет совсем!
        int rcIn;
//пройдем вверх по всем Received до первого for, если for = relayMailBox, то это означает, что письмо послано на деревню дедушке (неизвестному юзеру на relay)
        for(i = mail.header.nReceived - 1; i >= 0; i--)
        {    if(mail.header.cReceivedFor[i] && mail.header.ReceivedFromIP[i] != 0x7f000001)
             {  if(!stricmp(mail.header.cReceivedFor[i], sk.relayMailBox) )
                {   SpamIQ += sk.Weight.ToNEfor * 2;
                    if(!rcSpam)
                    {    rcSpam = 2;
                         RuleNumber = 2;  //mail to relay without user
                         CountMailSpam++;
                    }
                }
                break;
             }
        }
    } //end if(mail.header.To)
//Calc wrong words in subj
    if(mail.header.Subject && sk.WrongWordsList.n > 0)
    { SpamIQ +=  mail.CalcWeightSubjectWrongWords(&sk.WrongWordsList,sk.Weight.SubjWrongWord);
    }
//test for SubjEqUser
    if(mail.header.Subject && mail.header.To)
    {  char *username, *pAt;
       username = strdup(mail.header.To);
       pAt = strstr(username,"@");
       if(pAt) *pAt = 0;
       if(!stricmp(username,mail.header.Subject))
               SpamIQ +=  sk.Weight.SubjEqUser;
       else
       { char *tok, *tok1, *hto;
         hto = strdup(mail.header.Subject);
         tok = strtok(hto,": ");
         if(tok)
         {  tok1 = strtok(NULL," ");
            if(tok1 && !stricmp(tok,"Re"))
            {   if(!stricmp(tok1,username))
                           SpamIQ += sk.Weight.SubjEqUser;
            }
         }
         free(hto);
       }
       free(username);
    }
//test for SubjEqRe
    if(mail.header.Subject)
    {  if(!stricmp(mail.header.Subject,"Re:") || !stricmp(mail.header.Subject,"Re") )
              SpamIQ += sk.Weight.SubjEqRe;
    }
    printf("SpamIQ = %.2f\n",SpamIQ);
//    printf("sk.blacklistuse = %i  mail.header.nReceived = %i\n", sk.blacklistuse, mail.header.nReceived);
/************* blacklists check **********************************/
    if(!rcSpam && sk.blacklistuse && mail.header.nReceived > 1)
    {  int istrusted=0;

       for(i = mail.header.nReceived; i>1; i--)
       {   if(mail.header.ReceivedFromIP[i] == NULL) continue;
           if(mail.header.ReceivedFromIP[i] == 0x7f000001) continue;
           break;
       }
/* Check 3 up-stream host */
       for(n_upsreamhost = 0; n_upsreamhost < 3; n_upsreamhost++)
       {
          for(j=0; j< sk.NtrustNet ;j++)
          {   if(((~mail.header.ReceivedFromIP[i]) & sk.trusted[j].ip) &  sk.trusted[j].mask)   ;
              else
              {   istrusted = 1;
                  break;//  printf(" Trusted\n");
              }
          }
          if(istrusted)
                 break;
          {  char TestHost[512];
             unsigned int i1,i2,i3,i4;
             i4 = mail.header.ReceivedFromIP[i] & 0xff;
             i3 = (mail.header.ReceivedFromIP[i]>>8) & 0xff;
             i2 = (mail.header.ReceivedFromIP[i]>>16) & 0xff;
             i1 = (mail.header.ReceivedFromIP[i]>>24) & 0xff;
          if(i1 | i2 | i3 | i4)
             for(j=0; j < sk.nblacklists; j++)
             {
               sprintf(TestHost,"%i.%i.%i.%i.%s", i4,i3,i2,i1,sk.blacklist[j] );
               rc = TestHostAtBlackList(TestHost);
               if(rc == 1) //Yess!
               { int k;
                 printf("TestHostAtBlackList rc=%i\n",rc);
//                 for(k=0;k<10; k++)
//                      DosBeep(1000+k*40,25-k*2);
                  CountMailSpam++;
                  rcSpam = j+1;
                  mail.header.indSpamReceivedFrom = i;
                  RuleNumber = 1;
                  break;
               } else if(rc == -1) {
                 extern int ErrorGethostbyname;
                 char *ErrCodes[]={"NETDB_INTERNAL","HOST_NOT_FOUND","TRY_AGAIN","NO_RECOVERY","NO_DATA",NULL};
                 char *perrcode;
                 if(ErrorGethostbyname == -1) perrcode = ErrCodes[0];
                 else if(ErrorGethostbyname >= 1  && ErrorGethostbyname <= 4) perrcode = ErrCodes[ErrorGethostbyname];
                 printf("\n");
                 _log_print("ERROR:Gethostbyname rc = %i (%s)\n", ErrorGethostbyname, perrcode);
               } else {
                 printf("\n");
               }
             }
          }
          if(rcSpam)
                 break;
          for(--i; i>1; i--)
          {   if(mail.header.ReceivedFromIP[i] == NULL) continue;
              break;
          }
          if(i < 1)
               break;
       } //endof for(n_upsreamhost
       if(!rcSpam)
          n_upsreamhost = 0; //has no meaning in log
    }
/***** Внешний байесовский фильтр **************/
/* известно, что письмо - спам. зарегистрируем его в фильтре, если нужно */
   if(rcSpam && sk.ExtFilterRegAsSpam[0])
   { //сначала проверим - как письмо определяется фильтром
      sprintf(cmdstr,sk.ExtFilterTest,mail.fname);
      rc = system(cmdstr);
      if(rc == -1)
      { _log_print("Error system(%s) call, errno=%i\n",cmdstr, errno);
      } else {
        _log_print("Проверили спам-письмо %i, получили rc=%i\n", CountMail,rc);
        if(rc == sk.ExtFilterTestRcNoSpam)
        {  if(mail.fsize < sk.ExtFilterMaxFsizeRegAsSpam)
           {   sprintf(cmdstr,sk.ExtFilterRegAsSpam,mail.fname);
               rc = system(cmdstr);
               _log_print("Зарегистрировали спам-письмо %i как спам\n", CountMail);
           } else {
               _log_print("Размер спам-письма %i больше %iK\n", CountMail,sk.ExtFilterMaxFsizeRegAsSpam/1024);
           }
        }
     }
   }
/*  письмо - не спам, проверяем внешним фильтром */
   if(!rcSpam && sk.ExtFilterTest[0])
   {  sprintf(cmdstr,sk.ExtFilterTest,mail.fname);
      rc = system(cmdstr);
      if(rc == -1)
      { _log_print("Error system(%s) call, errno=%i\n",cmdstr, errno);
      } else  if(rc == 99)
      { _log_print("Error processing %s\n",cmdstr);
      } else {
        _log_print("Проверили письмо %i, получили rc=%i\n", CountMail,rc);
        if(rc == sk.ExtFilterTestRcSpam)
        {    rcSpam = 2;
             RuleNumber = 6;
             CountMailSpam++;
//регистрировать как спам не надо
        }
      }
   }
/*  письмо - не спам, зарегистрируем */
   if(!rcSpam && sk.ExtFilterRegAsNoSpam[0] && SpamIQ == 0.)
   {  if(mail.fsize < sk.ExtFilterMaxFsizeRegAsNoSpam)
      {  sprintf(cmdstr,sk.ExtFilterRegAsNoSpam,mail.fname);
         rc = system(cmdstr);
         if(rc == -1)
         { _log_print("Error system(%s) call, errno=%i\n",cmdstr, errno);
         } else {
           _log_print("Зарегистрировали письмо %i как неспам\n", CountMail);
         }
      } else {
               _log_print("Размер неспам-письма %i больше %iK\n", CountMail,sk.ExtFilterMaxFsizeRegAsNoSpam/1024);
      }
   }
/******************************************/
//копируем письмо
   if((sk.CopyGoodMail && !rcSpam) || (sk.CopySpamMail && rcSpam))
   {  char copyfile[_MAX_PATH], copyinffile[_MAX_PATH];
      if(rcSpam)
      {  strcpy(copyfile,sk.SpamMailDir);
      } else  {
         strcpy(copyfile,sk.GoodMailDir);
      }
      i = strlen(copyfile);
      if(copyfile[i-1] != '\\' &&  copyfile[i-1] != '/')
      {  strcat(copyfile,"\\");
      }
//копируем инф файл чтоб посмотреть, что туда пишется
      sprintf(copyinffile,"%s%d.inf",copyfile,CountMail);
      rc = CopyFile(par[1],copyinffile);

      sprintf(str,"%d.msg",CountMail);
      strcat(copyfile,str);
      rc = CopyFile(mail.fname,copyfile);
      if(rc)
      {
       _log_print("ERROR:CopyFile from %s to %s rc = %i\n", mail.fname, copyfile, rc);
      }
//пишем в лог
       str[0] = 0;
       if(RuleNumber ==  3)
       {    sprintf(str,"(msg %i)", history.mhi[historyId].msgNum);
       }

       _log_print("%s %s %i %d %d SpamIQ=%.2f %d\n", RulesInfo[RuleNumber], str, n_upsreamhost, CountMail, CountMailSpam, SpamIQ, time(NULL));
//       _log_print("%i %i %i %d %d %s SpamIQ=%.2f %d\n",rcSpam, RuleNumber , n_upsreamhost,CountMail, CountMailSpam, str,SpamIQ, time(NULL));
   } else {
//пишем в лог
       str[0] = 0;
       if(RuleNumber ==  3)
       {    sprintf(str,"(%s)", history.mhi[historyId].msgfile);
       }
       _log_print("%s %s  %d %d  SpamIQ=%.2f %d\n", RulesInfo[RuleNumber], str,  CountMail, CountMailSpam, SpamIQ, time(NULL));
   }

    history.Purge(sk.historyTime);
//add to history only untrusted
    if(mail.header.lastTrustedReceivedFrom < mail.header.nReceived)
    {  history.Add(mail.header.ReceivedFromIP[mail.header.indSpamReceivedFrom], rcSpam, mail.fname, CountMail);
    }
    history.Write(sk.historyFile);


    rc = DosRequestMutexSem(SpamKillCount_hmtx,      /* Handle of semaphore */
                            (ULONG) SEM_INDEFINITE_WAIT);  /* Timeout  */
    if (rc != NO_ERROR) {
       printf("DosRequestMutexSem error: return code = %u\n", rc);
      _log_print("Error: DosRequestMutexSem return code = %u\n", rc);
       exit(100);
    }

   {  FILE *fp;
//читаем счетчик
      fp=fopen(SpamCountFile,"r");
      fscanf(fp,"%d %d",&CountMail,&CountMailSpam);
      fclose(fp);
      if(rcSpam)
         CountMailSpam++;
//пишем счетчик
      fp=fopen(SpamCountFile,"w");
      fprintf(fp,"%d %d\n",CountMail, CountMailSpam);
      fclose(fp);
   }
   rc = DosReleaseMutexSem(SpamKillCount_hmtx);

    if(rcSpam)
        rcSpam = 3; //for Weasel
    if(isMailToSpamUser)   //Let's spammers think this is good addr
        rcSpam = 0;
    exit(rcSpam);
}

int _log_print(const char *format,...)
{  FILE *fp;
char buf[1024];
   va_list args;
   va_start(args, format);
    static char fatal_str[BUFSIZ];
    vsprintf(buf,  format, args);
    printf("%s",buf);
  fp = fopen(LogFile,"a");
  fprintf(fp, "%s", buf);
  fclose(fp);
   va_end(args);
  return 0;
}

int usage(void)
{
   printf("%s %s %s\n",APPLICATION,VERS,RELIZEDATA);
   printf("Usage:\n");
   printf("SpamKiller namefile mailfile\n");
   printf("return code is:0 - Ok, 3 - Spam found\n");

   return 0;
}

/* copy file from from to */
int CopyFile(char *from, char *to)
{  FILE *fp;
   char *buf;
   int l,rc;
   fp = fopen(from,"rb");
   if(fp == NULL)
      return 1;
   l = _filelength(fileno(fp));
   buf = (char *)malloc(l+1);
   if(buf == NULL)
   {  fclose(fp);
      return 3;
   }
   rc = fread(buf,l,1,fp);
   if(rc != 1)
   {  free(buf);
      fclose(fp);
      return 4;
   }
   fclose(fp);
   fp = fopen(to,"wb");
   if(fp == NULL)
   {  free(buf);
      return 2;
   }
   rc = fwrite(buf,l,1,fp);
   if(rc != 1)
   {  free(buf);
      fclose(fp);
      return 5;
   }
   fclose(fp);

   free(buf);
   return 0;
}


#define MAXSTR 4096*2

int Mail::ReadHeader(void)
{  int lstr,rc, FromFound=0;
   char str[MAXSTR+1];

   if(fname[0] == 0)
         return 1;
   if(fp == NULL)
   {  fp = fopen(fname,"rb");
      if(fp == NULL)
         return 2;
   }
   fsize = _filelength(fileno(fp));
   if(fsize <= 0)
   {   fclose(fp);
       return 2;
   }
   do
   {
     pos = ftell(fp);

     rc = ReadString( str, MAXSTR,  &lstr );
     if(rc == 2)
     { lstr = strlen(str);
       rc = 0;
       if(lstr == 0)
               return 0;
     }
     if(rc)
             break;

/* Пустая ли это строчка ? */
     if( lstr == 1 || lstr == 2 )
     { if( str[lstr - 1] == '\n' )
               return 0;
     }
/* анализ полей заголовка */
     if( strncmp( str, "From:", 5 ) == 0 )
     {                   header.AddFrom(str+5);
                         FromFound = 1;
     }
     else
        if( strnicmp( str, "Subject:", 8 ) == 0 )
                             header.AddSubject(str+8);
     else
        if( strnicmp( str, "Received:", 9 ) == 0 )
        {   if(!FromFound)
                         header.AddReceived(str+9);
        }
     else
        if( strnicmp( str, "Return-Path:", 12 ) == 0 )
        {   if(!FromFound)
                       header.AddReturn_Path(str+12);
        }
     else
        if( strnicmp( str, "To:", 3 ) == 0 )
                             header.AddTo(str+3);
     else
        if( strnicmp( str, "Cc:", 3 ) == 0 )
                             header.AddCC(str+3);
     else
        if(strnicmp( str, "Content-Type:",13) == 0)
                             header.AddContent_Type(str+13);
     else
        if(strnicmp( str, "Content-Transfer-Encoding:",26) == 0)
                             header.AddContentTransferEncoding(str+26);

  } while(rc == 0);

   return 0;
}

double Mail::CalcWeightSubjectWrongWords(textList *list, double w1)
{   char *subj, *tok;
    int i,rc;
    double w=0.;
    if(!header.Subject || header.Subject[0] == 0)
           return 0.;
    subj = strdup(header.Subject);
    tok=strtok(subj," ,.\t");
    if(tok)
    {  do
       {  rc = list->Checki(tok);
          if(rc >= 0)
             w += w1;
          tok=strtok(NULL," ,.\t");
       } while(tok);
    }
    free(subj);
    return w;
}

int Mail::ReadString(char *str,int maxlen, int *num)
{  int i,rc;
   char ch;
   *num = 0;
   for(i=0;i<maxlen;i++)
   {  rc=fread(&ch,1,1,fp);
      if(rc == 1) { (*num)++; readbytes++; }
      else { str[i]=0; return 1; }
      str[i] = ch;
      if(ch == '\n')
      {   str[i+1] = 0;
          readlines++;
          rc=fread(&ch,1,1,fp);
          if(rc != 1)  return 1;

          if(ch == ' ' || ch == '\t') // unfolding
          {   (*num)++; readbytes++;
              str[++i] = ch;

          } else {
             fseek(fp,-1,SEEK_CUR);
             str[i+1] = 0;
             return 0;
          }
      }
   }
   str[i] = 0;
   return 2;
}

int DelSpacesFromString(char *str)
{  int i,j,j0,l;
   unsigned char *str0,*str1;
   l = strlen(str);
   str0 = (unsigned char *)str;
   str1 = str0;
   for(i=j=j0=0;i<l;i++)
   {  if(str0[i] <32 && str0[i] != 9) continue;
      str1[j] = str[i];
      j++;
      if(str[i] > 32) j0 = j;
   }
   str1[j0] = 0;
   return 0;

}

/**************************************/

void _Optlink SpamKill_cleanup(void)
{   int rc;
/* в последнюю очередь освобождаем семафор */
    if(SpamKillCount_hmtx)
    {   rc = DosReleaseMutexSem(SpamKillCount_hmtx);        /* Relinquish ownership */
        rc = DosCloseMutexSem(SpamKillCount_hmtx);          /* Close mutex semaphore */
    }
}

