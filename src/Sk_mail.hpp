/* Sk_mail.hpp */
int DelSpacesFromString(char *str);

/********************************************************/

class MessageHeader
{
public:
   char *From;
   char *To;
   char *Subject;
   char *CC;
   char *Content_Type;
   char *Return_Path;
   int nReceived;
   char *cReceived[128];     //full Received:
   char *cReceivedFrom[128];   //from addr
   char *cReceivedFromIP[128]; //from [IPaddr] - for possible test at blacklist
   char *cReceivedFor[128];    //for
   unsigned int ReceivedFromIP[128];
   int lastTrustedReceivedFrom;
   int indSpamReceivedFrom;  //индекс ReceivedFromIP[] на котором сработал black list
   char *ContentTransferEncoding;
   MessageHeader(void)
   {  int i;
      From=NULL;
      To = NULL;
      Subject=NULL;
      CC   = NULL;
      Content_Type = NULL;
      Return_Path = NULL;
      nReceived = 0;
      for(i=0; i < sizeof(cReceived)/sizeof(char *); i++)
      {   cReceived[i] = NULL;
          cReceivedFrom[i] = NULL;
          cReceivedFromIP[i] = NULL;
          cReceivedFor[i]    = NULL;
          ReceivedFromIP[i] = 0;
          lastTrustedReceivedFrom = 0;
      }
      ContentTransferEncoding = NULL;
   }
   ~MessageHeader(void)
   {  int i;
      if(From)
           free(From);
      if(To)
           free(To);
      if(Subject)
           free(Subject);
      if(CC)
           free(CC);
      if(Return_Path)
           free(Return_Path);
      if(Content_Type)
           free(Content_Type);
      if(nReceived)
         for(i=0;i<nReceived;i++)
         {  if(cReceived[i]) free(cReceived[i]);
            if(cReceivedFrom[i]) free(cReceivedFrom[i]);
            if(cReceivedFor[i]) free(cReceivedFor[i]);
            if(cReceivedFromIP[i]) free(cReceivedFromIP[i]);
         }
      if(ContentTransferEncoding)
           free(ContentTransferEncoding);
   }
   int AddReturn_Path(char * _from)
   {  int l;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(Return_Path == NULL)
      {   Return_Path = (char *) malloc(l+1);
          strcpy(Return_Path,_from);
      } else {
          l += strlen(Return_Path);
          Return_Path = (char *)realloc((void *)Return_Path,l+2);
          strcat(Return_Path,_from);
      }
      DelSpacesFromString(Return_Path);
      return 0;
   }
   int AddFrom(char * _from)
   {  int l;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(From == NULL)
      {   From = (char *) malloc(l+1);
          strcpy(From,_from);
      } else {
          l += strlen(From);
          From = (char *)realloc((void *)From,l+2);
          strcat(From,_from);
      }
      DelSpacesFromString(From);
      return 0;
   }
   int AddTo(char * _from)
   {  int l, iscomma=0;
      char *tofull, *pstr, *pstr1,*pstr2, *pstrcomma;
      if( *_from == 32)  _from++;
      l = strlen(_from);
//todo: TO: aaa@bb, cc@dd, ...
      tofull = (char *)malloc(l+1);
      strcpy(tofull,_from);
M:
      pstr = tofull;
      pstrcomma = strrchr(tofull,(int)',');
      if(pstrcomma)
      {    iscomma = 1;
           pstr = pstrcomma+1;
           *pstrcomma = 0;
      }
        else
           iscomma = 0;

      pstr1 = strrchr(pstr,(int)'<');
      pstr2 = strrchr(pstr,(int)'>');
      if(pstr1 && pstr2) // To in form "blabla bla <addr>
      {  *(pstr2) = 0;
         pstr = pstr1+1;
      }
      l = strlen( pstr);
      if(To == NULL)
      {   To = (char *)malloc(l+1);
          strcpy(To, pstr);
      } else {
          l += strlen(To);
          To = (char *)realloc((void *)To,l+4);
          strcat(To," ");
          strcat(To, pstr);
      }
      if(iscomma ) goto M;

      free(tofull);
      DelSpacesFromString(To);
      return 0;
   }
   int AddReceived(char * _from)
   {  int i, l,l1;
      char *tok, *tok1, *pstr;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(nReceived >= sizeof(cReceived)/sizeof(char *))
            return 1;
      for(i=0; i< l; i++)
      {  if(_from[i] < 32) _from[i] = 32; //" "
      }
      if(cReceived[nReceived] == NULL)
      {   cReceived[nReceived] = (char *) malloc(l+1);
      } else {
          cReceived[nReceived] = (char *)realloc((void *)cReceived[nReceived],l+2);
          strcat(From,_from);
      }
      strcpy(cReceived[nReceived],_from);
      tok=strtok(_from," ");
      if(tok && !stricmp(tok,"from"))
      {   tok=strtok(NULL," ");
          if(tok)
          { if(cReceivedFrom[nReceived] == NULL)
            {  l1 = strlen(tok);
               cReceivedFrom[nReceived] = (char *) malloc(l1+2);
               strcpy(cReceivedFrom[nReceived],tok);
            }
            tok=strtok(NULL,"()");
            if(tok)
            {  tok1=strtok(tok,"]");
               if(tok1)
               {  tok=strstr(tok1,"[");
                  if(tok)
                  {  int l1, rc;
                     unsigned int i1=0,i2=0,i3=0,i4=0;
                     tok++;
                     l1 = strlen(tok);
                     cReceivedFromIP[nReceived] = (char *) malloc(l1+2);
                     strcpy(cReceivedFromIP[nReceived],tok);
                     rc = sscanf(cReceivedFromIP[nReceived],"%d.%d.%d.%d",&i1,&i2,&i3,&i4);
                     ReceivedFromIP[nReceived] = (((((i1<<8)|i2)<<8)|i3)<<8) | i4;
                  }
                }
            }
          }
      }
//seach for "for"
     pstr = strstr(cReceived[nReceived]," for ");
     if(pstr )
     {  char str[512];
        pstr += 5;
        strncpy(str,pstr,sizeof(str)-1);
        tok = strtok(str," <>;");
        if(tok)
        {  l1 = strlen(tok);
           cReceivedFor[nReceived] = (char *) malloc(l1+2);
           strcpy(cReceivedFor[nReceived],tok);
        }
     }
      nReceived++;
      return 0;
   }
   int AddCC(char * _from)
   {  int l;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(CC == NULL)
      {   CC = (char *)malloc(l+1);
          strcpy(CC,_from);
      } else {
          l += strlen(CC);
          CC = (char *)realloc((void *)CC,l+4);
          strcat(CC," ");
          strcat(CC,_from);
      }
      DelSpacesFromString(CC);
      AddTo(CC); // добавим в To - чтоб было вдвое меньше геммоpою


      return 0;
   }
   int AddSubject(char * _from)
   {  int l;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(Subject == NULL)
      {   Subject = (char *)malloc(l+1);
          strcpy(Subject,_from);
      } else {
          l += strlen(Subject);
          Subject = (char *)realloc((void *)Subject,l+2);
          strcat(Subject,_from);
      }
      DelSpacesFromString(Subject);
      return 0;
   }
   int AddContent_Type(char * _from)
   {  int l;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(Content_Type == NULL)
      {   Content_Type = (char *) malloc(l+1);
          strcpy(Content_Type,_from);
      } else {
          l += strlen(Content_Type);
          Content_Type = (char *)realloc((void *)Content_Type,l+2);
          strcat(Content_Type,_from);
      }
      DelSpacesFromString(Content_Type);
      return 0;
   }
   int AddContentTransferEncoding(char *_from)
   {  int l;
      if( *_from == 32)  _from++;
      l = strlen(_from);
      if(ContentTransferEncoding == NULL)
      {   ContentTransferEncoding = (char *) malloc(l+1);
          strcpy(ContentTransferEncoding,_from);
      } else {
          l += strlen(ContentTransferEncoding);
          ContentTransferEncoding = (char *)realloc((void *)Content_Type,l+2);
          strcat(ContentTransferEncoding,_from);
      }
      DelSpacesFromString(ContentTransferEncoding);
      return 0;
   }
};

class Mail
{
   public:
   char fname[256];
   FILE *fp;
   int pos,posold;
   int readbytes;
   int readlines;
   int fsize;
   MessageHeader header;
   Mail(void)
   {  fp = NULL;
      fname[0] = 0;
      pos = posold = 0;
      readlines = 0;
      readbytes = 0;
      fsize = 0;
   }
   ~Mail(void)
   {  if(fp)
        fclose(fp);
   }
   int Close(void)
   {  if(fp)
        fclose(fp);
      fp = NULL;
   }
   int ReadHeader(void);
   int ReadString(char *str,int maxlen, int *num);
   double  CalcWeightSubjectWrongWords(textList *list, double w1);

};
/*******************************************************/
class UserStatistic
{
public:
   char *username;
   unsigned int BytesPersonal;
   unsigned int BytesList;
   unsigned int NPersonal;
   unsigned int NList;

   UserStatistic(void)
   {  username=NULL;
      BytesPersonal=0;
      BytesList=0;
      NPersonal=0;
      NList=0;
   }
   UserStatistic(char *_username, int bpers,int blist,int npers,int nl)
   {
      username = new char[strlen(_username)+1];
      strcpy(username,_username);
      BytesPersonal = bpers;
      BytesList = blist;
      NPersonal = npers,
      NList = nl;
   }
   ~UserStatistic(void)
   { if(username ) delete username;
   }

};
/*******************************************************/

class Statistic
{

public:
   unsigned int BytesInput;
   unsigned int BytesOutputPersonal;
   unsigned int BytesOutputList;
   unsigned int Ninput;
   unsigned int NList;
   unsigned int NPersonal;

   int nusers;
   int allocUsers;
   class UserStatistic * * Users;

   Statistic(void)
   { allocUsers=0;
     nusers = 0;
     Users = NULL;
     BytesInput=0;
     BytesOutputPersonal=0;
     BytesOutputList=0;
     NList = 0;
     NPersonal = 0;
     Ninput=0;
   }

   ~Statistic(void)
   {  int i;
      for(i=0;i<nusers;i++)
            delete   Users[i];
      free(Users);
   }

   int AddBufferforUser(int dl)
   {  if(Users == NULL)
      {  Users = (class UserStatistic * *) calloc(dl,sizeof(class UserStatistic *));
         allocUsers = dl;
      } else {
         allocUsers += dl;
          Users  = (class UserStatistic * *) realloc((void *)Users, allocUsers * sizeof(class UserStatistic *));
      }
      return 0;
   }

   int AddUser(char *addr, int bpers,int blist,int npers,int nl)
   {  int l;
      if(nusers +1 >= allocUsers)
      {  int addtn=16;
         AddBufferforUser(addtn);
      }
      l = strlen(addr);
      Users[nusers] = new UserStatistic(addr,bpers,blist,npers,nl);
      BytesOutputPersonal += bpers;
      BytesOutputList += blist;
      nusers++;
      return 0;
   }

   int AddUser(char *addr)
   {
      AddUser(addr,0,0,0,0);
      return 0;
   }

   int AddStatisticForUser(char *addr, int bpers,int blist,int npers,int nl)
   {  int i,is;

      for(i=0;i<nusers;i++)
      {  if(!stricmp(Users[i]->username, addr) )
           {  is = 1;
              Users[i]->BytesPersonal += bpers;
              Users[i]->BytesList += blist;
              Users[i]->NPersonal += npers;
              Users[i]->NList += nl;
              NList += nl;
              NPersonal += npers;
              BytesOutputPersonal += bpers;
              BytesOutputList += blist;
              return 1;
           }
      }
      AddUser(addr, bpers, blist,npers,nl);
      NList += nl;
      NPersonal += npers;
      return 0;
   }

   int Read(char *fname);
   int Write(char *fname);
   int SortUsers(void);

};

/*******************************************************/
class MailList
{
public:
   char *addr;  // адpес лист-сеpвеpа
   char *fname; // имя файла, куда складывать
   char *fnUsers; // имя файла, c именами подписчиков
   int nUsers;              // число пользователей
   int allocUsers;          // место для числа пользователей
   char * *Users;           // указатель на лист пользователей
   MailList(void)
   {  nUsers = 0;
      allocUsers = 0;
      Users = NULL;
   }
   MailList(char *_addr, char *_fname, char *_fnUsers)
   {  nUsers = 0;
      allocUsers = 0;
      addr = (char *) malloc(strlen(_addr)+1);
      strcpy(addr,_addr);
      fname = (char *)malloc(strlen(_fname)+1);
      strcpy(fname,_fname);
      fnUsers = (char *)malloc(strlen(_fnUsers)+1);
      strcpy(fnUsers,_fnUsers);
   }

   ~MailList(void)
   {    int i;
        if(Users)
        {  for(i=0;i<nUsers;i++)
           { if(Users[i]) free(Users[i]);
           }
           free(Users);
        }
        nUsers = 0;
        free(fnUsers);
        free(fname );
        free(addr);
   }

   int AddBufferforUser(int dl)
   {  if(Users == NULL)
      {  Users = (char *  *) calloc(dl,sizeof(char *));
         allocUsers = dl;
      } else {
         allocUsers += dl;
         Users = (char * *) realloc((void *)Users, allocUsers * sizeof(char *));
      }
      return 0;
   }

   int AddUser(char *addr)
   {  int l;
      if(nUsers +1 >= allocUsers)
      {  int addtn=16;
         AddBufferforUser(addtn);
      }
      l = strlen(addr);
      Users[nUsers] = (char *)malloc(l+1);
      strcpy(Users[nUsers],addr);
      nUsers++;
      return 0;
   }
   int readListServerUsers(void);

};


class ProjectPOPBox
{
public:
   char fname[_MAX_PATH];    // имя ini
   char Inbox[_MAX_PATH];    // входной почтовый ящик
   char popfname[_MAX_PATH]; // входной ящик для POP-пользователя
   char spambox[_MAX_PATH];  // ящик для спама

   char * *PopNames;//=laser.nictl@g23.relcom.ru
   int NpopNames;
//   char *PopName1;//=laser.nictl@relcom.ru
//   char *PopName2;//=iplit.ran@g23.relcom.ru
//   char *PopName3;//=iplit.ran@relcom.ru
   char *UUPCName;//=laser.nictl.msk.su
   char *UUPCAlias;//=laser.ru

   char *RmailPath;//=rmail.exe

   int Nlist;         // число лист-сеpвеpов
   int allocNlist;
   class MailList * * list;   // описание лист-сеpвеpов

/*****************************/
/* Run-time variables */
   FILE *fp;
   int pos,posold;
/* статистика */
   int npopmail;
   int nuupcmail;
   int nlistmail;
   int nspam;
/*****************************/

   ProjectPOPBox(void)
   {  Nlist = 0;
      allocNlist=0;
      NpopNames=0;
      PopNames = NULL;
      popfname[0]=0;
      spambox[0] =0;
      npopmail=0;
      nuupcmail=0;
      nlistmail=0;
      nspam=0;
   }
   ~ProjectPOPBox(void)
   {  int i;
      for(i=0;i<Nlist;i++)
      {   delete list[i];
      }
      free((void *)list);
      for(i=0;i<NpopNames;i++)
      {   free(PopNames[i]);
      }
      free(PopNames);
   }

   int AddBufferforMailList(int dl)
   {  if(list == NULL)
      {  list = ( class MailList * *) calloc(dl,sizeof(class MailList *));
         allocNlist = dl;
      } else {
         allocNlist += dl;
         list = ( class MailList * *) realloc((void *)list, allocNlist * sizeof(class MailList *));
      }
      return 0;
   }
   int AddPopName(char *_popname)
   {  int i,l;
/* сначала пpовеpим, а нет ли уже такого ? */
      for(i=0;i<NpopNames;i++)
      {  if(!stricmp(PopNames[i], _popname) )
           {  return 1;
           }
      }
      if(PopNames == NULL)
      {  PopNames = (char * *) calloc(NpopNames+2,sizeof(char *));
      } else {
         PopNames = (char * *) realloc((void *)PopNames,(NpopNames+2) * sizeof(char *));
      }
      l = strlen(_popname);
      PopNames[NpopNames] = (char *)malloc(l+2);
      strcpy(PopNames[NpopNames],_popname);
      NpopNames++;
      return NpopNames;
   }
   int AddMailList(char *addr,char *fname, char* fnUsers)
   {   int i;
       for(i=0;i<Nlist;i++)
       {  if(!strcmp(list[i]->addr, addr) )
           {  return 1;
           }
       }
       if(Nlist +1 >= allocNlist)
       {  int addtn=16;
          AddBufferforMailList(addtn);
       }
      list[Nlist] = new MailList(addr,fname, fnUsers);
      Nlist++;
      return 0;
   }

   int Read(void);
   int StringINIanalize(char *str);
   int ReadTillHead(char *str, int &numEmptyStr);
   int ReadHead(char *str);
   int ProccessOneMail(int startPos, int lastPos, class MessageHeader *mhead);
   int AddMailToPop(int startPos, int lastPos, class MessageHeader *mhead);
   int AddMailToSPAM(int startPos, int lastPos, class MessageHeader *mhead);
   int SendMailToLocalUser(int startPos, int lastPos, class MessageHeader *mhead, char *userAddr);
   int SendMailSubscribers(int startPos, int lastPos, class MessageHeader *mhead, class MailList *plist);
   int SendListToLocalUser(int startPos, int lastPos, class MessageHeader *mhead, char *userAddr);

};
