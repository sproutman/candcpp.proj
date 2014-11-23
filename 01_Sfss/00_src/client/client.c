#include "client.h"

//----------------------������---------------------------
void mainMenu();//���˵�
void log();			//��ʾlog
int connectto(int argc,char *args[]);           //���������������
int login(char username[],char userpasswd[]);		//��½
int senddata(struct FilePackage data);     			//�������ݰ�
int recvdata(struct FilePackage *data);        	//��������
void Show(char temp[100]);											//��ʾ�ͻ����Լ�������Ŀ¼
void * UpdateF(void *);																	//�ϴ��ļ�
void * DownloadF(void *);															  //�����ļ�
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

//~~~~~~~~~~~~~~~~~~~~~~ȫ�ֱ���~~~~~~~~~~~~~~~~~~~~~~~~~~~
char username[50];
char tempuname[50];
char userpasswd[20];
int  sockclient;
struct sockaddr_in sockaddr1;
char ipaddr[15];
SSL_CTX *ctx;
SSL *ssl;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
void ShowCerts(SSL * ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    printf("Digital certificate information:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Certificate: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  }
  else
    printf("No certificate information��\n");
}

//~~~~~~~~~~~~~~~~~~~~~~~��ʾLOG~~~~~~~~~~~~~~~~~~~~~~~~~~~

void log()
{
	system("clear");
	printf("       \033[36m***********\033[0m\033[34mWelcome to Secure File Storage System\033[0m\033[36m***********\n\033[0m");
	printf("       \033[36m*\033[0m \033[31m        ******     ******     ******     ******   \033[0m  \033[36m    *\n\033[0m\033[0m");
	printf("       \033[36m*\033[0m \033[31m       **          *         **         **        \033[0m  \033[36m    *\n\033[0m\033[0m");
	printf("       \033[36m*\033[0m \033[31m        *****      ******     *****      *****    \033[0m  \033[36m    *\n\033[0m\033[0m");
	printf("       \033[36m*\033[0m \033[31m            **     *              **         **   \033[0m  \033[36m    *\n\033[0m\033[0m");
	printf("       \033[36m*\033[0m \033[31m       ******      *         ******     ******  \033[0m \033[34mKJC  \033[0m  \033[36m*\n\033[0m\033[0m");
	printf("       \033[36m***********************************************************\n\033[0m");
	sleep(1);
}
//~~~~~~~~~~~~~~~~~~~~~connect to server~~~~~~~~~~~~~~~~~~~
//�ɹ�����1��ʧ�ܷ���0�����˳�
int connectto(int argc,char *args[]) 
{
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~�ж�����ɣ��Ƿ���ȷ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	int i,count=0;
	if(argc!=2)
		{
			printf("format error: you mast enter ipaddr like this : client 192.168.0.6\n");
			exit(0);
		}
	for(i=0;*(args[1]+i)!='\0';i++)
		{
			if(*(args[1]+i)=='.')
				count++;
		}
	if(count!=3)
		{
			printf("IP format error\n");
			exit(0);
		}
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	if((sockclient=socket(AF_INET,SOCK_STREAM,0))==-1)
		{
			perror("socket");	
			exit(0);
		}
	memset(&sockaddr1,0,sizeof(sockaddr1));
	sockaddr1.sin_family = AF_INET;
	sockaddr1.sin_addr.s_addr = inet_addr(args[1]);
	sockaddr1.sin_port = htons(port);
	
	if(connect(sockclient,(struct sockaddr* )&sockaddr1,sizeof(sockaddr1))==-1)
		{
			perror("connect");
			exit(0);
		}
		//-----------------------------------------------------------------------
	/* ���� ctx ����һ���µ� SSL */
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockclient);
  /* ���� SSL ���� */
  if (SSL_connect(ssl) == -1)
    ERR_print_errors_fp(stderr);
  else
  {
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts(ssl);
  }
	return 1;
}
//~~~~~~~~~~~~~~~~~~~~~~~�������ݰ�~~~~~~~~~~~~~~~~~~~~~~~~
int senddata(struct FilePackage data)
{
	if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
		{	
			perror("send login message:");
			return 0;
		}
	return 1;
}
//~~~~~~~~~~~~~~~~~~~~~~~�������ݰ�~~~~~~~~~~~~~~~~~~~~~~~
int recvdata(struct FilePackage *data)
{
	if((SSL_read(ssl,data,sizeof(struct FilePackage)))==-1)
	{	
		perror("recv login message:");
		return 0;
	}
	return 1;
}

//~~~~~~~~~~~~~~~~~~~~~�û���½~~~~~~~~~~~~~~~~~~~~~~~~~~~
//���͸�ʽusername*userpasswd#
int login(char username[20],char userpasswd[10])
{

top:	printf("ID: ");
	scanf("%s",username);
	strcpy(tempuname,username);
	printf("PASSWD: ");
	scanf("%s",userpasswd);
	strcat(username,"*");
	strcat(username,userpasswd);
	strcat(username,"#");
//	printf("%s\n",username);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~	
	struct FilePackage data;
	data=pack('L', username, " ",  0, 9,strlen(username),tempuname);
//	printf("%s\n",username);
	if(senddata(data)==0)
		exit(0);
//	printf("%s\n",username);
	if(recvdata(&data)==0)
		exit(0);
//	printf("%s\n",username);
//	printf("%s\n",data.buf);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	if(data.cmd == 'L' && data.ack == 0)
		{
			printf("\n\033[33mUsername or Password error!\033[0m\n\n");
			goto top;
		}
	if(data.cmd == 'L' && data.ack == 1)
		{
			printf("Login Success\n");
			printf("%s\n",data.buf);
			
//			SSL_shutdown(ssl);
// 			SSL_free(ssl);
// 			close(sockclient);
// 			SSL_CTX_free(ctx);
			return 1;
		}
	if(data.cmd == 'L' && data.ack == 2)
		{
			printf("\n\033[32mMaxnum connection!\033[0m\n\n");
			exit(0);
		}
	return 0;
}

//~~~~~~~~~~~~~~~~~~~~~~~��ʾ�ͻ���Ŀ¼~~~~~~~~~~~~~~~~~~~
void Show(char temp[100])
{
	char command [2];
	if((strncpy(command,temp,1),*command)=='1'||(strncpy(command,temp,1),*command)=='2'||(strncpy(command,temp,1),*command)=='3')
		return;
	if(strncmp(temp,"cd",2)==0)
		{
			char dir[40]={'\0'};
			temp[strlen(temp)-1]='\0';
			strncpy(dir,(&(*temp)+3),strlen(&(*temp)+3));
		
			/*
			printf("%d%s",strlen((&(*temp)+3)),(&(*temp)+3));
			printf("%d%s",strlen(dir),dir);
			if(dir[strlen(dir)]=='\0')
				printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
			*/
			
			chdir(dir);
			strcpy(temp,"ls");
		}
	system("clear");
	printf("\n\033[34m-----------------------------   \033[31mClient Files List   \033[34m----------------------------\033[0m\n");
	system(temp);
//	printf("\033[34m*******************************************************************************\033[0m\n");
	
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~��ʾ������Ŀ¼~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	senddata(pack('S', " ", " ",  0, 9,1,tempuname));
	struct FilePackage data;
	if(recvdata(&data)==0)
		exit(0);
	if(data.cmd=='S')
		{
			printf("\033[34m-----------------------------   \033[31mServer Files List   \033[34m----------------------------\033[0m\n");
			printf("%s\n",data.buf);
			printf("\033[34m--------------------------------------------------------------------------------\033[0m\n");
		}
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
}
//~~~~~~~~~~~~~~~~~~~~~~~�ϴ��ļ�~~~~~~~~~~~~~~~~~~~~~~~~~
void * UpdateF(void *filename)
{
usleep(500);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
char *Files=(char *)filename;
	
int  sockclient;
struct sockaddr_in sockaddr1;
SSL_CTX *ctx;
SSL *ssl;

//printf("~2~ %s  %d\n",Files,strlen(Files));
if((sockclient=socket(AF_INET,SOCK_STREAM,0))==-1)
		{
			perror("socket");	
			exit(0);
		}

	memset(&sockaddr1,0,sizeof(sockaddr1));
	sockaddr1.sin_family = AF_INET;
	sockaddr1.sin_addr.s_addr = inet_addr(ipaddr);
	sockaddr1.sin_port = htons(port);
	
	if(connect(sockclient,(struct sockaddr* )&sockaddr1,sizeof(sockaddr1))==-1)
		{
			perror("connect");
			exit(0);
		}

		//-----------------------------------------------------------------------
	 /* SSL ���ʼ�� */
//  SSL_library_init();
//  OpenSSL_add_all_algorithms();
//  SSL_load_error_strings();
  ctx = SSL_CTX_new(SSLv23_client_method());
  if (ctx == NULL)
  {
    ERR_print_errors_fp(stdout);
    exit(1);
  }
	/* ���� ctx ����һ���µ� SSL */
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockclient);
  /* ���� SSL ���� */

  if (SSL_connect(ssl) == -1)
    ERR_print_errors_fp(stderr);
 
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	int Fd;
	char buf[1025]={'\0'};
	int count=0;
	int temp=0;
	struct stat statbuf;
	struct FilePackage data;
	
	if(stat(Files,&statbuf)==-1)
		{
			perror("*");
			return 0;
		}
	if(!S_ISREG(statbuf.st_mode))
		perror("*");
		
		data=pack('U', " ", Files, statbuf.st_size , 9,0,tempuname);
		if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
			perror("send login message:");

	if((SSL_read(ssl,&data,sizeof(struct FilePackage)))==-1)
	{	
		perror("recv login message:");
	}
	
	if(data.cmd == 'U' && data.ack == 1)
		{
			printf("���������̲���\n");
			return 0;
		}

	if(data.cmd == 'U' && data.ack == 0)
		{
			//do noting; 
		}
	if((Fd=open(Files,O_RDONLY))==-1)
		perror("open: ");
//	printf("~3~ %s  %d\n",Files,strlen(Files));
	while((count=read(Fd,(void *)buf,1024))>0)
		{
//			int i=0;
//			buf[count]='\0';
//			printf("count~~~~~~~~~~~~~~~~~~%d   %d\n",count,temp++);
//			printf("%s\n",buf);
//			printf("%s",buf);
			data=pack('U', buf, Files, count , 2,count,tempuname);
			if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
				perror("send login message:");
//			printf("~~~~~%s~~~~~~\n",Files);
				/*
			int i=0;
			for(;i<1024;++i)
				{
					printf("%c",data.buf[i]);	
				}
				*/
		}
		

	data=pack('U', " ", Files, statbuf.st_size , 4,1,tempuname);
	if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
			perror("send login message:");

	if((SSL_read(ssl,&data,sizeof(struct FilePackage)))==-1)
	{	
		perror("recv login message:");
	}
	if(data.cmd == 'U' && data.ack == 3)
		{
			printf("\n\033[31mUpdate Files over\033[0m\n");
		}
	
	data=pack('Q', " ", " ", 0 , 9,0,tempuname);
	if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
			perror("send login message:");	
	close(Fd);
	close(sockclient);
	return (void *)1;
}
//~~~~~~~~~~~~~~~~~~~~~~~�����ļ�~~~~~~~~~~~~~~~~~~~~~~~~~

void * DownloadF(void *filename)
{
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
char *Files=(char *)filename;
int  sockclient;
struct sockaddr_in sockaddr1;
SSL_CTX *ctx;
SSL *ssl;
usleep(500);
//printf("~2~ %s  %d\n",Files,strlen(Files));
if((sockclient=socket(AF_INET,SOCK_STREAM,0))==-1)
		{
			perror("socket");	
			exit(0);
		}
	memset(&sockaddr1,0,sizeof(sockaddr1));
	sockaddr1.sin_family = AF_INET;
	sockaddr1.sin_addr.s_addr = inet_addr(ipaddr);
	sockaddr1.sin_port = htons(port);
	
	if(connect(sockclient,(struct sockaddr* )&sockaddr1,sizeof(sockaddr1))==-1)
		{
			perror("connect");
			exit(0);
		}
		//-----------------------------------------------------------------------
	ctx = SSL_CTX_new(SSLv23_client_method());
	/* ���� ctx ����һ���µ� SSL */
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockclient);
  /* ���� SSL ���� */
  if (SSL_connect(ssl) == -1)
    ERR_print_errors_fp(stderr);
//  else
//  {
//    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
//    ShowCerts(ssl);
//  }
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	int Fd;
	char buf[1024];
	int count=0;
	int temp=0;
	struct statfs statfsbuf;
	struct FilePackage data;
	struct stat statbuf;
	if(stat(Files,&statbuf)==0)
		{
			printf("�ļ�����\n");
			return 0;
		}

	data=pack('D', " ", Files, 0 , 9,1,tempuname);
	if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
			perror("send login message:");	
	if((SSL_read(ssl,&data,sizeof(struct FilePackage)))==-1)
	{	
		perror("recv login message:");
	}
	if(data.cmd == 'D' && data.ack == 0)
		{
			statfs("./",&statfsbuf);
			if((statfsbuf.f_bsize*statfsbuf.f_bfree)<=data.filesize)
				{
					printf("\033[31m���̿ռ䲻��\033[0m\n");
					return 0;
				}
		}
	if(data.cmd == 'D' && data.ack == 8)
		{
			printf("\033[33mNo such file or directory\033[0m\n");
			return 0;
		}
	if((Fd=open(Files,O_RDWR|O_CREAT,0777))==-1)
		perror("open: ");
//	printf("\033[33mStart Download Files\033[0m\n");
	if(SSL_read(ssl,&data,sizeof(struct FilePackage))==-1)
		{
			perror("read error:\n");
		}
	while(data.ack==2)
		{
			count=data.filesize;
			if(write(Fd,data.buf,count)==-1)
			{
				perror("wirte error:\n");	
			}
			if(SSL_read(ssl,&data,sizeof(struct FilePackage))==-1)
			{
				perror("read error:\n");
			}
		}
	if(data.ack==4)
			{	
					printf("\033[31mDownload Files over\033[0m\n");
					data=pack('D', " ", Files, 0 , 3,1,tempuname);
					if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
						perror("send login message:");	
						
					data=pack('Q', " ", " ", 0 , 9,0,tempuname);
					if((SSL_write(ssl,&data,sizeof(struct FilePackage)))==-1)
						perror("send login message:");	
					close(sockclient);
					close(Fd);
		  }

	return (void *)1;
}

//~~~~~~~~~~~~~~~~~~~~~~~���˵�~~~~~~~~~~~~~~~~~~~~~~~~~~~
void mainMenu()
{
	char temp[100];
	char command [2];
	char Files[100];
	char Files1[100];
	pthread_t pthreadt;
	strcpy(temp,"ls");
	while(1)
	{
		int count;
		int temp1;
		count=0;
		temp1=0;
		if(strncmp(temp,"\n",1)!=0)
			Show(temp);
		else
			goto top;
//			usleep(500);
//	  printf("\033[34m*****************************\033[31mClient  console\033[34m*****************************\033[0m\n");
		printf("   \033[34m------------------------------\033[31mClient  console\033[34m-----------------------------\033[0m\n");
		printf("   \033[34m|\033[0m                1.Update Files   2.Download Files  3.Exit               \033[34m|\033[0m\n");
		printf("   \033[34m--------------   \033[36mUse \033[31mls \033[36mor \033[31mcd \033[36mto \033[31mdisplayer \033[36mand \033[31mchange dir   \033[34m--------------\033[0m\n");
		printf("  Please input the Client command:");	
top:		fgets(temp,sizeof(temp),stdin);
		switch(strncpy(command,temp,1),*command)
		{
			case '1':
				{
					printf("\033[33mUpdate Files:\033[0m ");
					fgets(Files,sizeof(Files),stdin);
//					printf("%d\n",strlen(Files));
					Files[strlen(Files)-1]='\0';
					while(Files[count]!='\0' && Files[count]!='\n')
					{
						if(Files[count]==' ')
							{
								Files[count]='\0';
//								printf("~1~ %s\n",&Files[temp1]);
								pthread_create(&pthreadt,NULL,UpdateF,(void *)&Files[temp1]);
								temp1=count+1;
							}
							count++;
					}
					pthread_create(&pthreadt,NULL,UpdateF,(void *)&Files[temp1]);

		  	}

				strcpy(temp,"ls");
				break;
				
			case '2':
				{
					printf("\033[33mDownloadF Files:\033[0m ");
					fgets(Files1,sizeof(Files1),stdin);
					Files1[strlen(Files1)-1]='\0';
					while(Files1[count]!='\0' && Files1[count]!='\n')
					{
						if(Files1[count]==' ')
							{
								Files1[count]='\0';
								pthread_create(&pthreadt,NULL,DownloadF,(void *)&Files1[temp1]);
								temp1=count+1;
							}
							count++;
					}
					pthread_create(&pthreadt,NULL,DownloadF,(void *)&Files1[temp1]);
			  }
				break;
				
			case '3':
				system("clear");
				
				exit(0);
				break;
		}
	}
}
int main(int argc,char *args[])
{
	//----------------------------------------------------------
	  /* SSL ���ʼ�� */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(SSLv23_client_method());
  if (ctx == NULL)
  {
    ERR_print_errors_fp(stdout);
    exit(1);
  }
  //----------------------------------------------------------
  strcpy(ipaddr,args[1]);
	if((connectto(argc,args))!=1)
		exit(0);
	if(login(username,userpasswd)==0)
		{
			printf("login error");
			exit(0);
		}
	
	log();
	mainMenu();
	return 0;
}
