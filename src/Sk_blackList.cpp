
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <types.h>
 #include <arpa\inet.h>
 #include <netinet\in.h>

 #include <netdb.h>
// struct hostent *gethostbyname(char *name);

//struct  hostent {
//        char    *h_name;        /* official name of host */
//        char    **h_aliases;    /* alias list */
//        int     h_addrtype;     /* host address type */
//        int     h_length;       /* length of address */
//        char    **h_addr_list;  /* list of addresses from name server */
//#define h_addr  h_addr_list[0]  /* address, for backward compatiblity */
//};

struct hostent *host;
int ErrorGethostbyname=0;

int TestHostAtBlackList(char *HostIPQuery)
{  int i,rc=0;
   struct sockaddr_in sock_name;
   struct in_addr in;
   char *ptr, *paddr, *paddr1;
   printf("Get info for %s ",HostIPQuery);

//Debug
/*
{ static int raz=0;
printf("!!!Debug!!!");
  raz++;
  if(!(raz%5))
      return 1;
  else
      return 0;
}
*/
  ErrorGethostbyname = 0;
  host = gethostbyname(HostIPQuery);
//  printf("h_errno=%i\n",h_errno);
  ErrorGethostbyname = h_errno;
  if(ErrorGethostbyname)
  {   if(ErrorGethostbyname == 1) rc = 0;
      else rc = -1;
      return rc;
  }
/*
  printf(" h_name=%s\n",host->h_name);
  if(host->h_aliases)
  {   printf("Aliases=");
      for(i=0;host->h_aliases[i];i++)
      {   printf(" %s",host->h_aliases[i]);
      }
       printf("\n");
  }
*/
//  printf("h_addrtype=%x\n",host->h_addrtype);
//  printf("h_length=%i\n",host->h_length);
  if(host->h_addr_list)
  {   int *piadr;
      printf("Addresses=");
      piadr =(int *) *host->h_addr_list;

      for(i=0; *piadr;i++, piadr++ )
      {    ptr = (char *)piadr;
           memcpy( &sock_name.sin_addr.s_addr , ptr , sizeof(sock_name.sin_addr.s_addr ) );
           paddr = inet_ntoa( *((in_addr *)&sock_name.sin_addr.s_addr));
           printf(" %s ",paddr);
           if(!stricmp(paddr,"127.0.0.2"))
                 rc = 1;
      }

  }
  return rc;
}
