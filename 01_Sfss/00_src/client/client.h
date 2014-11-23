#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define port 3333



struct FilePackage
{
	char cmd;
	int  filesize;
	int  ack;
	char username[50];
	char filename[125];
	char buf[1024];  
};


//~~~~~~~~~~~~~~~~~~~~~~~~�������~~~~~~~~~~~~~~~~~~~~~~~~~
struct FilePackage pack(char tCmd, char* tBuf, char* tFilename, int tFilesize, int tAck,int count,char *uname)
{
	struct FilePackage tPackage;
	tPackage.cmd = tCmd;
//	strcpy(tPackage.buf, tBuf);
//	strncpy(tPackage.buf, tBuf,1024);
	memcpy(tPackage.buf,tBuf,count);
	strcpy(tPackage.filename, tFilename);
	strcpy(tPackage.username, uname);
	tPackage.filesize = tFilesize;
	tPackage.ack = tAck; 
	return tPackage;
}

/*
����
Cmd��R
�ͷ��˷������ݰ���0 ��������

�������������ݰ���1��Ӧ����


��½: 
Cmd:L    �û������������buf����*�Ÿ����� admin*123
�������������ݰ���ACK��0 �û������������
     	       	         1 ��½�ɹ�
     	                 2 �ͻ������������

�ͷ��˷������ݰ���ACK��9 ��½������  


���أ�
Cmd��D
�������������ݰ���ACK��0 �������أ����ش������ļ���С
		       						 2 ��ʼ����
											 4 �������
											 		
�ͷ��˷������ݰ���ACK��9 ��������
		       						 1 ���ش��̿ռ䲻��
		       						 3 �������


�ϴ���
Cmd��U
�������������ݰ���ACK��0 �����ϴ�����
		                   1 ���ش��̿ռ䲻��
		                   3 �������

�ͷ��˷������ݰ���ACK��9 �����ϴ����ϴ��ļ���С,�ļ���
		                   2 ��ʼ�ϴ��ļ�
		                   4 �ϴ����
		       

��ʾ�ļ��б�
Cmd��S
�������������ݰ���ACK: 0 ��һ����ʾ�ļ��б�
		                  

�ͷ��˷������ݰ���ACK��9 ������ʾ

�˳�
Cmd: Q
�ͷ��˷������ݰ���ACK��0
*/
