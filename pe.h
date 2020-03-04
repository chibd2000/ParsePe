DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer,PVOID pImageBuffer);		
DWORD CopyImageBufferToNewBuffer(PVOID pImageBuffer,PVOID* pNewBuffer);
void FileBufferToAddShellcode(PVOID pFileBuffer);
void AddNewSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer);
								
DWORD FOA_TO_RVA(PVOID FileAddress, DWORD FOA,PDWORD pRVA);
DWORD RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA);
void MyReadFile(PVOID* pFileBuffer,PDWORD BufferLenth);
void MyWriteFile(PVOID pMemBuffer,size_t size);
int GetBufferLength(PVOID Buffer);

#define FILENAME "C:\\Documents and Settings\\Administrator\\桌面\\ipmsg.exe"
#define NEWFILENAME "C:\\Documents and Settings\\Administrator\\桌面\\NEW_ipmsg.exe"


int GetBufferLength(PVOID Buffer){
	int BufferLength;
	BufferLength = ftell(Buffer);
	return BufferLength;
}

//ReadPEFile:将文件读取到缓冲区				
//参数说明：				
//lpszFile 文件路径				
//pFileBuffer 缓冲区指针				
//返回值说明：				
//读取失败返回0  否则返回实际读取的大小				
void MyReadFile(PVOID* pFileBuffer,PDWORD BufferLenth){
	FILE* File;
	File = fopen(FILENAME,"rb");

	if(File == NULL){
		printf("文件句柄打开失败");
		return;
	}

	//读取文件
	fseek(File,0,SEEK_END);
	*BufferLenth = ftell(File);
	fseek(File,0,SEEK_SET);

	//开辟新空间
	*pFileBuffer = (PVOID)malloc(*BufferLenth);

	//内存清零
	memset(*pFileBuffer,0,*BufferLenth);

	//读取到内存缓冲区
	fread(*pFileBuffer,*BufferLenth,1,File);

	//关闭文件句柄
	fclose(File);
}

//**************************************************************************								
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer								
//参数说明：								
//pFileBuffer  FileBuffer指针								
//pImageBuffer ImageBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
						
DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer,PVOID* pImageBuffer){
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	DWORD ImageBufferSize = 0;
	int i=0;
	

	// DOS头
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	// 标准PE
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);

	// 可选PE
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	//节表组
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);

	//获取ImageBufffer的内存大小
	ImageBufferSize = pImageOptionalHeader->SizeOfImage;
	
	//为pImageBuffer分配内存空间
	*pImageBuffer = (PVOID)malloc(ImageBufferSize);

	if (*pImageBuffer == NULL)
	{
		printf("malloc failed");
		return -1;
	}

	//清零
	memset(*pImageBuffer, 0, ImageBufferSize);
	
	// 拷贝头+节表
	memcpy(*pImageBuffer, pFileBuffer, pImageOptionalHeader->SizeOfHeaders);


	//循环拷贝节表

	for(i=0;i<pImageFileHeader->NumberOfSections;i++){
		memcpy(
			(PVOID)((DWORD)*pImageBuffer + pImageSectionHeaderGroup[i].VirtualAddress), // 要拷贝的位置 ImageBuffer中的每个节数据的偏移位置
			(PVOID)((DWORD)pFileBuffer + pImageSectionHeaderGroup[i].PointerToRawData), // 被拷贝的位置是 Filebuffer中的每个节数据的偏移位置
			pImageSectionHeaderGroup[i].SizeOfRawData // 被拷贝的大小为 每个节数据的文件对齐大小
		);
	}

	return 0;
}						


//**************************************************************************								
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区								
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pNewBuffer NewBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小															
DWORD CopyImageBufferToNewBuffer(PVOID pImageBuffer,PVOID* pNewBuffer){
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	DWORD NewBufferSize = 0;
	int i;
	int j;
	
	// DOS头
	pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	
	//pImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew);
	
	// 标准PE
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	
	// 可选PE
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	
	//节表组
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	//获取NewBufferSize的内存大小
	NewBufferSize = pImageOptionalHeader->SizeOfHeaders;


	//再循环加上节数据的大小
	for(j=0;j<pImageFileHeader->NumberOfSections;j++){
		NewBufferSize += pImageSectionHeaderGroup[j].SizeOfRawData;
	}


	//为NewBufferSize分配内存空间
	*pNewBuffer = (PVOID)malloc(NewBufferSize);
		
	if (*pNewBuffer == NULL)
	{
		printf("malloc failed");
		return -1;
	}

	//清零
	memset(*pNewBuffer, 0, NewBufferSize);
	
	// 拷贝头+节表
	memcpy(*pNewBuffer, pImageBuffer, pImageOptionalHeader->SizeOfHeaders);
	
	
	//循环拷贝节表
	for(i=0;i<pImageFileHeader->NumberOfSections;i++){
		memcpy(
			(PVOID)((DWORD)*pNewBuffer + pImageSectionHeaderGroup[j].PointerToRawData),
			(PVOID)((DWORD)pImageBuffer + pImageSectionHeaderGroup[j].VirtualAddress),
			pImageSectionHeaderGroup[j].SizeOfRawData
		);
	}

	return NewBufferSize;
}	


//功能：FOA 转换 RVA

DWORD FOA_TO_RVA(PVOID FileAddress, DWORD FOA,PDWORD pRVA)
{
	int ret = 0;
	int i;
	
	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	
	//RVA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (FOA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pRVA = FOA;
		return ret;
	}
	
	//循环判断FOA在节区中
	for (i=0;i < pFileHeader->NumberOfSections; i++)
	{
		if (FOA >= pSectionGroup[i].PointerToRawData && FOA < pSectionGroup[i].PointerToRawData + pSectionGroup[i].SizeOfRawData)
		{
			*pRVA = FOA - pSectionGroup[i].PointerToRawData + pSectionGroup[i].VirtualAddress;
			
			return *pRVA;
		}
	}
	
	//没有找到地址
	ret = -4;
	printf("func FOA_TO_RVA() Error: %d 地址转换失败！\n", ret);
	return ret;
}


//功能：RVA 转换 FOA
DWORD RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
	int ret = 0;
	int i=0;
	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	
	//RVA在文件头中 或 SectionAlignment 等于 FileAlignment 时RVA等于FOA
	if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		*pFOA = RVA;
		return ret;
	}
	
	//循环判断RVA在节区中
	for (i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
		{
			*pFOA = pSectionGroup[i].PointerToRawData + RVA - pSectionGroup[i].VirtualAddress;
			return ret;
		}
	}
	
	//没有找到地址
	ret = -4;
	printf("func RAV_TO_FOA() Error: %d 地址转换失败！\n", ret);
	return ret;
}
								

//功能：保存文件 
void MyWriteFile(PVOID pMemBuffer,size_t size){
	
	FILE* File;
	File = fopen(NEWFILENAME,"wb");
	if(File == NULL){
		printf("文件句柄打开失败");
		return;
	}
	fwrite(pMemBuffer,size,1,File);
	printf("文件保存成功!");
	fclose(File);

}


//功能：添加shellcode
void FileBufferToAddShellcode(PVOID pFileBuffer){
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;

	DWORD CodeAddress = 0; //要添加shellcode的地址
	DWORD FuncAddress; //MESSAGEBOX地址
	HMODULE hModule; //加载User32

	DWORD FOA = 0;
	DWORD RVA = 0;

	BYTE SHELLCODE[] = {
		0X6A,0X00,0X6A,0X00,0X6A,0X00,0X6A,0X00,
		0XE8,0X00,0X00,0X00,0X00,
		0XE9,0X00,0X00,0X00,0X00
	};

	DWORD E8_Next_Address;
	DWORD E9_Next_Address;
	DWORD EntryOfAddress;



	// DOS头
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	// 标准PE
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	
	// 可选PE
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	
	//节表组
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);

	//获取Messagebox的地址
	hModule = LoadLibrary("User32.dll");
	FuncAddress = (DWORD)GetProcAddress(hModule, "MessageBoxA");


	// CodeAddress为SHELLCODE在文件中的起始地址
	CodeAddress = (DWORD)pImageSectionHeaderGroup[0].PointerToRawData + (DWORD)pImageSectionHeaderGroup[0].Misc.VirtualSize;


	// 计算E8这条指令的下一行地址的RVA
	E8_Next_Address = CodeAddress + 13;
	
	FOA_TO_RVA(pFileBuffer,E8_Next_Address,&RVA);


	// X = 真正要跳转的地址 - E8这条指令的下一行地址
	E8_Next_Address = FuncAddress - (RVA + pImageOptionalHeader->ImageBase);

	//填充E8空白的空白部分
	memcpy(&SHELLCODE[9], &E8_Next_Address, 4);


	// 计算E9这条指令的下一行地址的RVA
	E9_Next_Address = CodeAddress + 18;

	FOA_TO_RVA(pFileBuffer,E9_Next_Address,&RVA);

	//再获取原来入口地址的VA
	EntryOfAddress = pImageOptionalHeader->AddressOfEntryPoint;


	// X = 真正要跳转的地址 - E9这条指令的下一行地址
	E9_Next_Address = EntryOfAddress - RVA;

	memcpy(&SHELLCODE[14],&E9_Next_Address,4);

	//填充完了shellcode，最后再把shellcode放进去
	memcpy((PVOID)((DWORD)pFileBuffer+CodeAddress),SHELLCODE,0x20);
	
	//最后替换OEP的位置，替换为shellcode的地址

	FOA_TO_RVA(pFileBuffer,CodeAddress,&RVA);

	pImageOptionalHeader->AddressOfEntryPoint = RVA;

}

void AddNewSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer){
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;

	DWORD isOk;
	DWORD NewLength=0;
	PVOID LastSection = NULL;
	PVOID CodeSection = NULL;

	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);

	//判断是否可以容纳相应的节表
	isOk = (DWORD)pImageOptionalHeader->SizeOfHeaders - ((DWORD)pImageDosHeader->e_lfanew + IMAGE_SIZEOF_FILE_HEADER + pImageFileHeader->SizeOfOptionalHeader + 40*pImageFileHeader->NumberOfSections);
	if(isOk < 80){
		printf("空间太小 无法进行添加!");
		return;
	}

	//生成对应的内存大小的空间
	NewLength += *OldBufferSize + 0x1000;
	*pNewBuffer = (PVOID)malloc(NewLength);
	ZeroMemory(*pNewBuffer,NewLength);

	//拷贝之前内存空间 到 当前新生成的内存空间
	memcpy(*pNewBuffer,pFileBuffer,*OldBufferSize);

	//获取新的结构体
	pImageDosHeader = (PIMAGE_DOS_HEADER)(*pNewBuffer);
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);

	// pImageFileHeader->NumberOfSections修改
	pImageFileHeader->NumberOfSections = pImageFileHeader->NumberOfSections + 1;
	
	// pImageOptionalHeader->SizeOfImage修改
	pImageOptionalHeader->SizeOfImage = (DWORD)pImageOptionalHeader->SizeOfImage + 0x1000;

	// 复制代码段的节数据到 当前最后一个节数据后面
	CodeSection = (PVOID)(&pImageSectionHeaderGroup[0]);
	LastSection = (PVOID)(DWORD)(&pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1]);
	memcpy(LastSection,CodeSection,40);
	
	//修正相关属性
 	NewSec = (PIMAGE_SECTION_HEADER)LastSection;
	strcpy(NewSec,".NewSec");
	NewSec->Misc.VirtualSize = 0x1000;
	NewSec->SizeOfRawData = 0x1000;
	NewSec->VirtualAddress = pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].VirtualAddress + pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].SizeOfRawData;
	NewSec->PointerToRawData = pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].PointerToRawData + pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].SizeOfRawData;
	*OldBufferSize = NewLength;
}