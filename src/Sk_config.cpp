/* Sk_config.cpp */
/*  SpamKill config */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Sk_config.hpp"

int SK_Config::ReadUsersList(char *fname, textList &list, char *domain )
{  int i,iscomment,l;
   char *pstr, *pstr1,str[256], addr[256];
   FILE *fp;
   fp = fopen(fname,"r");
   if(fp == NULL)
         return 1;
   for(;;)
   {
/* читаем строку */
M:   pstr= fgets(str,128,fp);
     if(pstr == NULL) break; //EOF
/* игнорируем строки нулевой длины */
     l = strlen(str);
     if(str[l-1] == '\n')
     {  str[--l] = 0;
     }
     if(l == 0) goto M;
/* игнорируем комментарии */
     iscomment = 0;
     for(i=0;i<l;i++)
     { if(str[i] > 32)
       {   if(str[i] == ';') iscomment = 1;
           else if(str[i] == '#') iscomment = 1;
           break;
       }
     }
     if(iscomment) goto M;
     pstr1 = strstr(str,":");
     if(pstr1) *pstr1 = 0;
     pstr1 = strstr(str,"@");
     if(!pstr1 && domain)
     {  sprintf(addr,"%s@%s",str,domain);
        list.Add(addr);
     } else {
        list.Add(str);
     }
   }
   fclose(fp);
   return 0;
}


int SK_Config::Read(char *fname)
{  int id,rc;
   FILE *fp;
   char str[256],nameClass[128],name[128],par[128];
   fp = fopen(fname,"r");
   if(fp == NULL)
         return 1;
   do
   {  rc = ReadStr(fp, str,nameClass,name,par);
      if(!rc)
      { //  if(!strcmpi(nameClass,"prg"))
                 AnalizeRecodrRead(name,par);
        //  else
      }
   } while(!rc);

   fclose(fp);

   if(FnameRelayUsersList[0])
      ReadUsersList(FnameRelayUsersList, relayUsersList, relayDomain);
   if(FnameForSpamList[0])
      ReadUsersList(FnameForSpamList, UsersForSpamList, NULL);

   return 0;
}

int SK_Config::ReadStr(FILE *fp, char *str, char *nameClass, char *name, char *par )
{  int i,iscomment,l;
   char *pstr;
/* читаем строку */
M: pstr= fgets(str,128,fp);
   if(pstr == NULL) return 1; //EOF
/* игнорируем строки нулевой длины */
   l = strlen(str);
   if(str[l-1] == '\n')
   {  str[--l] = 0;
   }
   if(l == 0) goto M;
/* игнорируем комментарии */
   iscomment = 0;
   for(i=0;i<l;i++)
   { if(str[i] > 32)
     {   if(str[i] == ';') iscomment = 1;
         break;
     }
   }
   if(iscomment) goto M;
   pstr = strstr(str,"=");
   if(pstr == NULL)
        goto M; // игнорируем строки без "="
   *pstr = 0;
   strcpy(par,pstr+1);      // читаем параметры
   pstr = strstr(str,".");  // ищем точку для определения имени класса
   if(pstr == NULL)
   {
//  строка без "."
      nameClass[0] = 0;
      sscanf(str,"%s",name);
   } else {
      *pstr = 0;
      sscanf(str,"%s",nameClass);
      sscanf(pstr+1,"%s",name); // читаем имя параметра
   }
   return 0;
}

int SK_Config::AnalizeRecodrRead(char *name, char *par)
{   static char *lsNames[]=
     { "debugOptions","remoute",
       "blacklistuse","blacklist","trusted","CopySpamMail","CopyGoodMail",
       "GoodMailDir","SpamMailDir","relayMailBox","relayDomain","relayUsersList",
       "AddrForSpamList","historyFile","historyTime","SubjWrongWordsFile",
       "ExtFilterTest", "ExtFilterRegAsSpam", "ExtFilterRegAsNoSpam", "ExtFilterTestRcSpam", "ExtFilterTestRcNoSpam",
       "ExtFilterMaxFsizeRegAsSpam", "ExtFilterMaxFsizeRegAsNoSpam",
       NULL
     };
      int i,i1,is=0,npar=0,rc, rc1;

     for(i=0;lsNames[i];i++)
     {   if(!strcmp(name,lsNames[i]))
         {  is = 1;
            npar = i;
            break;
         }
     }
     if(!is) return 1;
     switch(npar)
     {
        case 0:
           sscanf(par,"%s",&debugOptions);
          break;
        case 1:  /* drivepar0 */
           sscanf(par,"%s", ExternMachineName);
         break;
        case 2: //blacklistuse
           blacklistuse = 0;
           if(!stricmp(par,"yes"))
                blacklistuse = 1;
           else
           { rc =sscanf(par,"%i",&i);
             if(rc == 1)
             {  if(i == 0 || i == 1) blacklistuse = i;
             }
           }
          break;
        case 3: //blacklist
           if(nblacklists >= sizeof(blacklist)/sizeof(char *))
                                  break;
           i = strlen(par);
           blacklist[nblacklists] = (char *)calloc(i+4,1);
           strcpy(blacklist[nblacklists],par);
           nblacklists++;
          break;
       case 4: //*trusted
          if(NtrustNet >= NtrustNetAlloc)
          {  if(trusted == NULL)
             {  NtrustNetAlloc = 64;
                trusted = (trustNet *) calloc(NtrustNetAlloc, sizeof(trustNet) );
             } else {
                NtrustNetAlloc = NtrustNet + 64;
                trusted = (trustNet *) realloc((void *)trusted, NtrustNetAlloc * sizeof(trustNet) );
             }
          }
          rc = sscanf(par,"%s %s",trusted[NtrustNet].cip,trusted[NtrustNet].cmask);
          if(rc > 0)
          {  unsigned int i1=0,i2=0,i3=0,i4=0;
             rc1 = sscanf(trusted[NtrustNet].cip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4);
             trusted[NtrustNet].ip = (((((i1<<8)|i2)<<8)|i3)<<8) | i4;
             if(rc > 1)
             {  rc = sscanf(trusted[NtrustNet].cmask,"%d.%d.%d.%d",&i1,&i2,&i3,&i4);
                trusted[NtrustNet].mask = (((((i1<<8)|i2)<<8)|i3)<<8) | i4;
             } else {
               trusted[NtrustNet].mask =0xffffffff;
             }
          }
          NtrustNet++;
          break;
       case 5:
           CopySpamMail = 0;
           if(!stricmp(par,"yes"))
                CopySpamMail = 1;
           else
           { rc =sscanf(par,"%i",&i);
             if(rc == 1)
             {  if(i == 0 || i == 1) CopySpamMail = i;
             }
           }
          break;
       case 6:
           CopyGoodMail = 0;
           if(!stricmp(par,"yes"))
                CopyGoodMail = 1;
           else
           { rc =sscanf(par,"%i",&i);
             if(rc == 1)
             {  if(i == 0 || i == 1) CopyGoodMail = i;
             }
           }
          break;
       case 7:
           sscanf(par,"%s",GoodMailDir);
          break;
       case 8:
           sscanf(par,"%s",SpamMailDir);
          break;
       case 9:
           sscanf(par,"%s",relayMailBox);
          break;
       case 10:
           sscanf(par,"%s",relayDomain);
          break;
       case 11:
           sscanf(par,"%s",FnameRelayUsersList);
          break;
       case 12: //AddrForSpamList
           sscanf(par,"%s",FnameForSpamList);
          break;
       case 13:
           sscanf(par,"%s",historyFile);
          break;
       case 14:
           sscanf(par,"%d",&historyTime);
          break;
       case 15:
           sscanf(par,"%s",SubjWrongWordsFile);
           WrongWordsList.Read(SubjWrongWordsFile);
          break;
       case 16:
           strcpy(ExtFilterTest,par);
          break;
       case 17:
           strcpy(ExtFilterRegAsSpam,par);
          break;
       case 18:
           strcpy(ExtFilterRegAsNoSpam,par);
          break;
       case 19:
           sscanf(par,"%d",&ExtFilterTestRcSpam);
          break;
       case 20:
           sscanf(par,"%d",&ExtFilterTestRcNoSpam);
          break;
       case 21:
           sscanf(par,"%d",&ExtFilterMaxFsizeRegAsSpam);
          break;
       case 22:
           sscanf(par,"%d",&ExtFilterMaxFsizeRegAsNoSpam);
          break;
   }
    return 0;
}

int SK_Config::AnalizeRecodrReadWeight(char *name, char *par)
{   static char *lsNames[]=
     { "ToNEfor","ToEQundisclosed_recipients","ContentTransferEncoding_base64","MailToNonExistentUser","SubjWrongWord",
       "SubjEqUser","SubjEqRe",
       NULL
     };
      int i,i1,is=0,npar=0,rc;

     for(i=0;lsNames[i];i++)
     {   if(!strcmp(name,lsNames[i]))
         {  is = 1;
            npar = i;
            break;
         }
     }
     if(!is) return 1;
     switch(npar)
     {
        case 0:
           sscanf(par,"%lf",&Weight.ToNEfor);
          break;
        case 1:
           sscanf(par,"%lf",&Weight.ToEQundisclosed_recipients);
         break;
        case 2:
           sscanf(par,"%lf",&Weight.ContentTransferEncoding_base64);
          break;
        case 3:
           sscanf(par,"%lf",&Weight.MailToNonExistentUser);
          break;
       case 4:
           sscanf(par,"%lf",&Weight.SubjWrongWord);
          break;
       case 5:
           sscanf(par,"%lf",&Weight.SubjEqUser);
          break;
       case 6:
           sscanf(par,"%lf",&Weight.SubjEqRe);
          break;
       case 7:
          break;
       case 8:
          break;
   }
    return 0;
}



