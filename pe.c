#include<windows.h>
#include<stdio.h>
#include "pe.h"

int main(){

	PVOID pFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	DWORD BufferLenth = 0;
	
	MyReadFile(&pFileBuffer,&BufferLenth);

	//CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	//FileBufferToAddShellcode(pFileBuffer);
	
	//NewBufferSize = CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);

	AddNewSection(pFileBuffer,&BufferLenth,&pNewBuffer);

	MyWriteFile(pNewBuffer,BufferLenth);

	printf("%x",BufferLenth);



	return 0;
}