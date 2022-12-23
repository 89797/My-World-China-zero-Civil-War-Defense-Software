#include "FunDef.h"
int main (int argc, char *argv[])
{
if (argc==1)
{
    Usage(argv[0]);
return 0;
}
if (!(ScanFileVXER(argv[1])))
{
printf("ScanFileVXER() GetLastError reports %d\n",erron);
return 0;
}
if (!(ProcessVXER()))
{
printf("Processes() GetLastError reports %d\n",erron);
return 0;
}
if (!(RegDelVXER()))
{
printf("RegDelVXER() GetLastError reports %d\n",erron);
return 0;
}
return 0;
}
BOOL ScanFileVXER (char *FileName)
int count=LOW;
WIN32_FIND_DATA FindFileData;
HANDLE hFind;
BOOL returnvalue=FALSE;
DWORD lpBufferLength=HIGH;
char lpBuffer[HIGH]={LOW};
char DirBuffer[MAX_PATH];
long FileOffset=0x1784; //偏移地址
int FileLength=0x77; //长度
unsigned char Contents[]={
0x49, 0x20, 0x6A, 0x75, 0x73, 0x74, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x74, 0x6F, 0x20, 0x73, 0x61, 0x79, 0x20, 0x4C, 0x4
F, 0x56, 0x45, 0x20, 0x59, 0x4F, 0x55, 0x20, 0x53, 0x41, 0x4E, 0x21, 0x21, 0x20, 0x62, 0x69, 0x6C, 0x6C, 0x79, 0x20, 0x67,
0x61, 0x74, 0x65, 0x73, 0x20, 0x77, 0x68, 0x79, 0x20, 0x64, 0x6F, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x6D, 0x61, 0x6B, 0x65, 0x2
0, 0x74, 0x68, 0x69, 0x73, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x69, 0x62, 0x6C, 0x65, 0x20, 0x3F, 0x20, 0x53, 0x74, 0x6F, 0x70,
0x20, 0x6D, 0x61, 0x6B, 0x69, 0x6E, 0x67, 0x20, 0x6D, 0x6F, 0x6E, 0x65, 0x79, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x66, 0x69, 0x7
8, 0x20, 0x79, 0x6F, 0x75, 0x72, 0x20, 0x73, 0x6F, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x21, 0x21};
//具体内容，⼗六进制
//获取系统⽬录的完整路径
if (GetSystemDirectory(DirBuffer,lpBufferLength)!=LOW)
{
if (SetCurrentDirectory(DirBuffer)!=LOW) //设置为当前⽬录
{
hFind=FindFirstFile(FileName,&FindFileData); //查找⽂件
if (hFind==INVALID_HANDLE_VALUE)
{
printf("FindFirstFile() GetLastError reports %d\n",erron);
FindClose(hFind);
return returnvalue;
}
else
{
count++;
//获得⽂件的完整路径
if (GetFullPathName(FindFileData.cFileName,lpBufferLength,lpBuffer,NULL)!=LOW)
printf("FilePath:%s\n",lpBuffer);
else
{
printf("GetFullPathName() GetLastError reports %d\n",erron);
FindClose(hFind);
return returnvalue;
}
}
//进⾏特征码的匹配⼯作
ScanVXER(FindFileData.cFileName,FileOffset,FileLength,Contents);
}
}
while (FindNextFile(hFind,&FindFileData)) //继续查找⽂件
{
count++;
//以"."和".."除外
if (strcmp(".",FindFileData.cFileName)==LOW||strcmp("..",FindFileData.cFileName)==LOW)
{
printf("File no include \".\" and \"..\"\n");
exit(0);
}
if (GetFullPathName(FindFileData.cFileName,lpBufferLength,lpBuffer,NULL)!=LOW) printf("Next FilePath:%s\n",lpBuffer);
else
{
printf("GetFullPathName() GetLastError reports %d\n",erron);
FindClose(hFind);
exit(0);
}
ScanVXER(FindFileData.cFileName,FileOffset,FileLength,Contents);
}
printf("File Total:%d\n",count); //打印出查找到的⽂件各数
FindClose(hFind); //关闭搜索句柄
returnvalue=TRUE;
return returnvalue;
}
BOOL ScanVXER (
char *V_FileName, //⽂件名
long V_FileOffset, //偏移地址
int V_Length, //长度
void *V_Contents) //具体内容
{
int cmpreturn=LOW;
char FileContents[HIGH]={LOW};
BOOL returnvalue=FALSE;
FILE *fp=NULL;
fp=fopen(V_FileName,"rb"); //以⼆进制只读⽅式打开
if (fp==NULL)
{
printf("File open FAIL\n");
fclose(fp);
return returnvalue;
}
fseek(fp,V_FileOffset,SEEK_SET); //把⽂件指针指向特征码在⽂件的偏移地址处
fread(FileContents,V_Length,1,fp);//读取长度为特征码长度的内容
cmpreturn=memcmp(V_Contents,FileContents,V_Length);
//进⾏特征码匹配。失败返回FALSE
if (cmpreturn==LOW)
{
printf("File Match completely\n"); //打印⽂件匹配消息
strcpy(name,V_FileName); //将⽂件名保存在全局变量name中
exit(0);
}
else
returnvalue=FALSE;
}
BOOL ProcessVXER (void)
{
DWORD lpidProcess[1024],cbNeeded_1,cbNeeded_2;
HANDLE hProc;
HMODULE hMod[1024];
char ProcFile[MAX_PATH];
char FileName[FIVE]={LOW};
BOOL returnvalue=FALSE;
int Pcount=LOW;
int i;
EnablePrivilege(SE_DEBUG_NAME); //提升权限
//枚举进程
if (!(EnumProcesses(lpidProcess,sizeof(lpidProcess),&cbNeeded_1))) {
printf("EnumProcesses() GetLastError reports %d\n",erron);
return 0;
for (i=LOW;i<(int)cbNeeded_1/4;i++)
{
//打开找到的第⼀个进程
hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,lpidProcess[i]); if (hProc)
{
//枚举进程模块
if (EnumProcessModules(hProc,hMod,sizeof(hMod),&cbNeeded_2)) {
//枚举进程模块⽂件名，包含全路径
if (GetModuleFileNameEx(hProc,hMod[0],ProcFile,sizeof(ProcFile))) {
printf("[%5d]\t%s\n",lpidProcess[i],ProcFile); //输出进程
//可以考虑将其注释掉，这样就不会输出进程列表了
Pcount++;
strcpy(FileName,"C:\\WINNT\\system32\\");
strcat(FileName,name);//把⽂件名+路径复制到FileName变量中
//查找进程中是否包含FileName
if (strcmp(FileName,ProcFile)==LOW)
{
//如果包含，则杀掉。KillProc为⾃定义的杀进程函数
if (!(KillProc(lpidProcess[i])))
{
printf("KillProc() GetLastError reports %d\n",erron);
CloseHandle(hProc);
exit(0);
}
DeleteFile(FileName); //进程杀掉后，再将⽂件删除
}
}
}
}
}
CloseHandle(hProc); //关闭进程句柄
printf("\nProcess total:%d\n",Pcount); //打印进程各数
returnvalue=TRUE;
return 0;
}
BOOL KillProc (DWORD *ProcessID)
{
HANDLE hProc;
