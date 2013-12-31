/* SK_config.hpp */
/* SpamKill config */
struct trustNet
{  unsigned int ip, mask;
   char cip[20];
   char cmask[20];
};

class textList
{  public:
    int n; //�᫮ ����⮢
    int nAlloc; //
    char * *list;// array of pointers to chars
    textList(void)
    {  n = 0;
       nAlloc = 0;
       list = NULL;
    }
    ~textList(void)
    {  int i;
       if(list)
       {  if(n)
          {  for(i=0;i<n;i++) if(list[i]) free(list[i]);
          }
          free(list);
          n = 0;
          nAlloc = 0;
          list = NULL;
       }
    }
    Add(char *str)
    {   int l;
        if(n >= nAlloc)
        {  if(list == NULL)
           {   nAlloc = 256;
               list = (char * *)calloc(nAlloc,sizeof(char *));
           } else {
              nAlloc = n + 256;
               list = (char * *) realloc((void *)list,  nAlloc * sizeof(char *));
          }
        }
        l = strlen(str);
        list[n] = (char *) calloc(l+1,sizeof(char));
        strcpy(list[n],str);
        n++;
        return 0;
    }
/* Check list case insensitivily and with separates at borders */
/* return -1 - not found, else index */
    int Checki_sep(char *str)
    {    int i, is, l,l1;
         char *pstr, *pstr1;
         for(i = 0; i < n; i++)
         {  if(!stricmp(str,list[i]))
                 return i;
         }
/* str - ��ப�, � ���ன, ��������, ᮤ�ন��� ����� ᯨ᪠ */
         for(i = 0; i < n; i++)
         {  pstr = strstr(str,list[i]);
            if(pstr)
            {  /* � str ���� �����ப� list[i]. ���� �஢����, ��࠭�祭� �� �� �����ப� ࠧ����⥫ﬨ */
               is = 1;
               if(pstr != str) //�஢��塞 ��砫�
               {  pstr1 = pstr - 1;
                   if( !strchr(" <>;,",(int)*pstr1) ) is = 0;
               }
               l =  strlen(list[i]);
               if( !strchr(" <>;,",(int)pstr[l]) ) is = 0;
               if(is)
                 return i;
            }
         }
         return -1;
    }
/* Check list case insensitivily  */
    int Checki(char *str)
    {    int i, is, l,l1;
         char *pstr;
         for(i = 0; i < n; i++)
         {  if(!stricmp(str,list[i]))
                 return i;
         }
         return -1;
    }
 /* �⠥� ᯨ᮪ �� 䠩��*/
    int Read(char *fname)
    {  int i,iscomment,l;
       char *pstr, *pstr1,str[256], addr[256];
       FILE *fp;
       fp = fopen(fname,"r");
       if(fp == NULL)
          return 1;
      for(;;)
      {
/* �⠥� ��ப� */
M:       pstr= fgets(str,128,fp);
         if(pstr == NULL) break; //EOF
/* ������㥬 ��ப� �㫥��� ����� */
         l = strlen(str);
         if(str[l-1] == '\n')
         {  str[--l] = 0;
         }
         if(l == 0) goto M;
/* ������㥬 �������ਨ */
         iscomment = 0;
         for(i=0;i<l;i++)
         {  if(str[i] > 32)
            {   if(str[i] == ';') iscomment = 1;
                else if(str[i] == '#') iscomment = 1;
                break;
            }
         }
         if(iscomment) goto M;
         Add(str);
      }
      fclose(fp);
      return 0;
    }
};

class SpamWeight
{  public:
   double ToNEfor; // Received: for , if present, not equal to To:
   double ToEQundisclosed_recipients; // To: undisclosed-recipients:;
   double ContentTransferEncoding_base64; //all mesage in base64
   double MailToNonExistentUser;
   double SubjWrongWord;   //;weight of 1 WrongWord  in subj, total weight is summ
   double SubjEqUser;      // subj equal user's name
   double SubjEqRe;        // Subj equal to Re or Re:
   SpamWeight(void)
   {  ToNEfor = 1.;
      ToEQundisclosed_recipients = 1.;
      ContentTransferEncoding_base64 = 0.3;
      MailToNonExistentUser = 2.;
      SubjWrongWord = 0.1;
      SubjEqUser = 1.;
      SubjEqRe = 0.1;
   }
};

class SK_Config
{
   public:
   char ExternMachineName[_MAX_FNAME];
   char debugOptions[256];
   char GoodMailDir[_MAX_DIR];
   char SpamMailDir[_MAX_DIR];

   int blacklistuse; //blacklist usage= 1/0
   int nblacklists;  //number of blacklists
   char *blacklist[16];
   int NtrustNet;
   int NtrustNetAlloc;
   struct trustNet *trusted;
   int CopyGoodMail;
   int CopySpamMail;

   SpamWeight Weight;
   char relayMailBox[80];
   char relayDomain[80];//�����, ��� ���ண� �ਭ������� ���쬠 � relayMailBox - �ᯮ������ ��� ���᪠ ����� ॠ�쭮�� ���짮��⥫� � Received from
   char FnameRelayUsersList[_MAX_FNAME]; // 䠩� � ᯨ᪮� relayUsersList
   textList relayUsersList;
/*;ᯨ᮪ ࠧ�襭��� ���짮��⥫�� ��� relayMailBox
  ;���짮��⥫� ������ ���� ���� � For: ���� � Received ...for
  ;�� ��⠫쭮� = ���������騥 ���짮��⥫�
*/
   char FnameForSpamList[_MAX_FNAME]; // 䠩� � ᯨ᪮� ���ᮢ ��� ᯠ��
   textList UsersForSpamList;
/*
ᯥ樠��� ���� ��� ᯠ�� �� ����� - ���� �� ���� �� �⢥࣠����,
;�� ���� from �ᯮ������ ���  ��᫥����� � 㤠����� �।���� ��ᥬ
;����� ���� �� 64
*/
   char historyFile[_MAX_FNAME];//;䠩� � �।���ਥ�
   int  historyTime;            //;�६� �࠭���� ���ଠ樨 � historyFile, ᥪ
   char SubjWrongWordsFile[_MAX_FNAME];//䠩� � ᯨ᪮� ����� ᫮� � subj
   textList WrongWordsList;            //ᯨ᮪ ����� ᫮� � subj

   char ExtFilterTest[_MAX_FNAME];
   char ExtFilterRegAsSpam[_MAX_FNAME];
   char ExtFilterRegAsNoSpam[_MAX_FNAME];
   int  ExtFilterTestRcSpam;
   int  ExtFilterTestRcNoSpam;
   int  ExtFilterMaxFsizeRegAsSpam; //���ᨬ���� ࠧ��� 䠩�� ��� ॣ����樨 ��� ᯠ�
   int  ExtFilterMaxFsizeRegAsNoSpam; //���ᨬ���� ࠧ��� 䠩�� ��� ॣ����樨 ��� ��ᯠ�

   SK_Config()
   { int i;
     ExternMachineName[0] = 0;
     SubjWrongWordsFile[0] = 0;
     strcpy(debugOptions,"ALL,7");
     blacklistuse = 0;
     nblacklists = 0;
     for(i=0;i<16;i++) blacklist[i] = NULL;
     NtrustNet = 0;
     NtrustNetAlloc = 0;
     trusted = NULL;
     CopySpamMail = CopyGoodMail = 0;
     relayMailBox[0] = 0;
     relayDomain[0] = 0;
     FnameRelayUsersList[0] = 0;
     FnameForSpamList[0] = 0;
     strcpy(historyFile,"SpamKill.dat");
     historyTime = 3600;
     ExtFilterTest[0] = ExtFilterRegAsSpam[0] = ExtFilterRegAsNoSpam[0] = 0;
     ExtFilterTestRcSpam = 0;
     ExtFilterTestRcNoSpam = 1;
     ExtFilterMaxFsizeRegAsSpam = 1024*100; //100K
     ExtFilterMaxFsizeRegAsNoSpam = 1024*150; //150K
   }
   ~SK_Config()
   { int i;
     for(i=0;i<16;i++) if(blacklist[i]) free(blacklist[i]);
     if(trusted)
        free(trusted);
   }

   int ReadUsersList(char *fname, textList &list, char *domain );
   int Read(char *fname);
   int Write(char *fname);
   int AnalizeRecodrRead(char *name, char *par);
   int AnalizeRecodrReadWeight(char *name, char *par);
   int ReadStr(FILE *fp, char *str, char *nameClass, char *name, char *par );

};
