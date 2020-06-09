#include<windows.h>
#include<stdio.h>
#include "pe.h"

int main(){
	PVOID pFileBuffer = NULL;
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	DWORD BufferLength = 0;

	// 读取文件到内存中 此时内存中的大小是文件对齐大小
	MyReadFile(&pFileBuffer,&BufferLength);

	// 打印PE结构，包括导出表
	//printfPE(pFileBuffer);

	// 打印重定位表 ，打印的时候记得把RVA_TO_FOA前面的判断注释掉，原因是可能文件对齐和内存对齐一样 但是可能全局变量的原因导致不一样
	//PrintRelocation(pFileBuffer);

	// 打印导入表
	//PrintfImportTable(pFileBuffer);

	// 打印绑定导入表
	//PrintBindImportTable(pFileBuffer);

	// 移动导入表，并且进行注入操作
	MoveAndInjectImportTable(pFileBuffer,&BufferLength,&pNewBuffer);

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

	//保存文件
	//MyWriteFile(pNewBuffer,BufferLength);

	//移动导出表 这个还有问题 自己移动的数据都放到节表里面了， 其实放的位置是对应节表里面的节数据的位置。。。。
	//MoveExportTable(pFileBuffer,&BufferLength,&pNewBuffer);

	//移动重定位表
	//MoveRelocationTable(pFileBuffer,&BufferLength, &pNewBuffer);

	return 0;
}