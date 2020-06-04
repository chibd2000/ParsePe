#include<windows.h>
#include<stdio.h>
#include "pe.h"

int main(){

	PVOID pFileBuffer; // 空指针 pFileBuffer = 0x00000000 &pFileBuffer = 0012f7c
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	DWORD BufferLength = 0;
	char MyFunctionName[] = "mul";

	// 读取文件到内存中 此时内存中的大小是文件对齐大小
	MyReadFile(&pFileBuffer,&BufferLength);

	// 打印PE结构，包括导出表 导入表
	printfPE(pFileBuffer);

	// 打印重定位表
	//printfRELOCATION(pFileBuffer);

	// 文件大小到内存大小
	//CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	// 添加shellcode
	//FileBufferToAddShellcode(pFileBuffer);
	
	// 扩大imagebase 
	//NewBufferSize = CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);

	// 新增节
	//AddNewSection(pFileBuffer,&BufferLength,&pNewBuffer);

	// 扩大节
	//ExpandSection(pFileBuffer,&BufferLength,&pNewBuffer);


	//MyWriteFile(pNewBuffer,BufferLength);



	return 0;
}