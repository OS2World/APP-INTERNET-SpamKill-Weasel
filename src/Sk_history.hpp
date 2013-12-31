/* Sk_history.hpp */
class MessageHistoryItem
{  public:
     time_t  t; //время получения
//     int nReceived;  //сколько адресов в списке ReceivedFromIP
     unsigned int ReceivedFromIP;
     int SpamCode; //0 - нет спама, 1-зафиксирован спам
     int msgNum;    //номер мессаджа
     char msgfile[_MAX_FNAME]; //где хранится письмо
   MessageHistoryItem(void)
   {  t = 0;
      SpamCode=0;
      msgNum = 0;
      msgfile[0]=0;
   }
};

#define MUTEX_HISTORY_SEM_NAME     "\\SEM32\\SPAMKILLHISTORY"
#define NO_ERROR 0

class MessageHistory
{   public:
      int n; //число элементов в mhi
      int nAlloc; //памяти выделено под эементов в mhi
      double keeptime; //время хранения
      MessageHistoryItem *mhi;
      HMTX  hmtxFile ; /* Mutex semaphore handle семафор наличия записи в файл истории */

    MessageHistory(void)
    {  int rc;
       n = 0;
       nAlloc = 0;
       mhi = NULL;
       hmtxFile = NULLHANDLE; /* Mutex semaphore handle */
/*
       rc = DosCreateMutexSem(MUTEX_HISTORY_SEM_NAME,      / * Semaphore name * /
                           &hmtxFile, 0, FALSE);  / * Handle  returned * /
    if (rc != NO_ERROR)
    {
       if(rc == ERROR_DUPLICATE_NAME)
              printf(MUTEX_HISTORY_SEM_NAME " already running\n");
       else
              printf("DosCreateMutexSem error: return code = %u\n", rc);
       return 1;
     }
*/
    }
//добавить элемент
    Add(unsigned int _ReceivedFromIP,int _SpamCode, char *_msgfile, int msgNum)
    {   int i;
        time_t t;
        t = time(NULL);
        if(n >= nAlloc)
        {  if(mhi == NULL)
           {   nAlloc = 16;
               mhi = (MessageHistoryItem *)calloc(nAlloc,sizeof(MessageHistoryItem));
           } else {
              nAlloc = n + 32;
               mhi = (MessageHistoryItem *) realloc((void *)mhi,  nAlloc * sizeof(MessageHistoryItem));
          }
        }
        mhi[n].ReceivedFromIP = _ReceivedFromIP;
        mhi[n].SpamCode = _SpamCode;
        strcpy(mhi[n].msgfile,_msgfile);
        mhi[n].t = t;
        mhi[n].msgNum = msgNum;
        n++;
        return 0;
    }
    int Purge(double maxdiff)
    {  int i,nn;
       double diff;
       time_t t;
       t = time(NULL);
       for(i=nn=0; i < n; i++)
       {  diff = difftime(t, mhi[i].t);
          if(diff <= maxdiff)
               mhi[nn++] = mhi[i];
       }
       n = nn;
       return 0;
    }

/* rc = 0 - нет, index+1 - есть спам */
    int CheckSpam(unsigned int ip)
    {  int i,j;
     if(ip)
       for(i=0; i < n; i++)
       {  if(ip == mhi[i].ReceivedFromIP && mhi[i].SpamCode)
          {   return i + 1;
          }
       }
       return 0;
    }

/* rc = 0 - нет, index+1 - есть такой */
    int Check(unsigned int ip, int start)
    {  int i;
     if(ip)
       for(i=start; i < n; i++)
       {  if(ip == mhi[i].ReceivedFromIP)
          {   return i + 1;
          }
       }
       return 0;
    }
    int Write(char *fname)
    {   FILE *fp;
        int i,j;

        fp = fopen(fname,"w");
        if(fp == NULL)
            return 1;
        fprintf(fp,"%d\n",n);

        for(i=0;i<n;i++)
        {
           fprintf(fp,"%d ",mhi[i].SpamCode);
//           fprintf(fp,"%d ",mhi[i].nReceived);
           fprintf(fp,"%x ",mhi[i].t);
//           for(j = 0; j < mhi[i].nReceived; j++)
//                  fprintf(fp,"%x ",mhi[i].ReceivedFromIP[j]);
           fprintf(fp,"%x %i",mhi[i].ReceivedFromIP, mhi[i].msgNum);
           fprintf(fp,"\n");
           fprintf(fp,"%s\n",mhi[i].msgfile);
        }
        fclose(fp);
        return 0;
    }
    int Read(char *fname)
    {   FILE *fp;
        int i,j;

        fp = fopen(fname,"r");
        if(fp == NULL)
            return 1;
        fscanf(fp,"%d\n",&n);
        if(n >= nAlloc)
        {  nAlloc = n + 32;
           if(nAlloc > 128) nAlloc += n / 4;
           if(mhi == NULL)
           {   mhi = (MessageHistoryItem *)calloc(nAlloc,sizeof(MessageHistoryItem));
           } else {
               mhi = (MessageHistoryItem *) realloc((void *)mhi,  nAlloc * sizeof(MessageHistoryItem));
          }
        }

        for(i=0;i<n;i++)
        {
           fscanf(fp,"%d ",&mhi[i].SpamCode);
//           fscanf(fp,"%d ",&mhi[i].nReceived);
           fscanf(fp,"%x ",&mhi[i].t);
//           for(j = 0; j < mhi[i].nReceived; j++)
//                  fscanf(fp,"%x ",&mhi[i].ReceivedFromIP[j]);
           fscanf(fp,"%x ",&mhi[i].ReceivedFromIP);
           fscanf(fp,"%i", &mhi[i].msgNum);
           fscanf(fp,"%s ",mhi[i].msgfile);
        }
        fclose(fp);
        return 0;
    }
};

