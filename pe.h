DWORD CopyFileBufferToImageBuffer(PVOID pFileBuffer,PVOID pImageBuffer);		
DWORD CopyImageBufferToNewBuffer(PVOID pImageBuffer,PVOID* pNewBuffer);
void FileBufferToAddShellcode(PVOID pFileBuffer);
void AddNewSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer);
void ExpandSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer);
void printfPE(PVOID pFileBuffer);
void PrintRelocation(PVOID pFileBuffer); //打印重定位表
DWORD FOA_TO_RVA(PVOID FileAddress, DWORD FOA,PDWORD pRVA);
DWORD RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA);
void MyReadFile(PVOID *pFileBuffer,PDWORD BufferLenth);
void MyWriteFile(PVOID pMemBuffer,DWORD BufferLenth);
int GetBufferLength(PVOID Buffer);
void PrintfImportTable(PVOID pFileBuffer); //打印导入表
void MoveExportTable(PVOID pFileBuffer, PDWORD OldBufferSize,PVOID* pNewBuffer); //移动导出表
void MoveRelocationTable(PVOID pFileBuffer, PDWORD OldBufferSize,PVOID* pNewBuffer); //移动重定位表
void PrintBindImportTable(PVOID pFileBuffer); //打印绑定导入表
void MoveAndInjectImportTable(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer); //移动导入表、并且尝试进行注入



//#define FILENAME "C:\\Documents and Settings\\Administrator\\桌面\\mydell.dll"
#define FILENAME "C:\\Documents and Settings\\Administrator\\桌面\\ipmsg.exe"
#define NEWFILENAME "C:\\Documents and Settings\\Administrator\\桌面\\ipmsg_new.exe"

int GetBufferLength(PVOID Buffer){
	int BufferLength;
	BufferLength = ftell(Buffer);
	return BufferLength;
}

//**************************************************************************
//ReadPEFile:将文件读取到缓冲区
//参数说明:			
//lpszFile 文件路径
//pFileBuffer 缓冲区指针
//返回值说明:	
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

	//重新把File指针指向文件的开头
	fseek(File,0,SEEK_SET);

	//开辟新空间
	*pFileBuffer = (PVOID)malloc(*BufferLenth);

	//内存清零
	memset(*pFileBuffer,0,*BufferLenth);

	//读取到内存缓冲区
	fread(*pFileBuffer,*BufferLenth,1,File);// 一次读入*bufferlenth个字节，重复1次

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


								
//FOA_TO_RVA:FOA 转换 RVA							
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
// RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress,&FOA);
DWORD RVA_TO_FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
	int ret = 0;
	int i=0;
	PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
	PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	
	
	//RVA在文件头中 或 SectionAlignment(内存对齐) 等于 FileAlignment(文件对齐) 时 RVA等于FOA
	if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
	{
		// 37000
		*pFOA = RVA;
		return ret;
	}
	
	/*
		第一步：指定节.VirtualAddress <= RVA <= 指定节.VirtualAddress + Misc.VirtualSize(当前节内存实际大小)
		第二步：差值 = RVA - 指定节.VirtualAddress
		第三步：FOA = 指定节.PointerToRawData + 差值
	*/

	//循环判断RVA在节区中
	for (i=0;i<pFileHeader->NumberOfSections; i++)
	{
		// RVA > 当前节在内存中的偏移地址 并且 RVA < 当前节的内存偏移地址+文件偏移地址
		if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
		{
			*pFOA =  RVA - pSectionGroup[i].VirtualAddress + pSectionGroup[i].PointerToRawData;
			return ret;
		}
	}
	
	//没有找到地址
	ret = -4;
	printf("func RVA_TO_FOA() Error: %d 地址转换失败！\n", ret);
	return ret;
}
								

//功能：保存文件 
void MyWriteFile(PVOID pNewBuffer,size_t size){
	
	FILE* File;
	File = fopen(NEWFILENAME,"wb");
	if(File == NULL){
		printf("文件句柄打开失败");
		return;
	}
	fwrite(pNewBuffer,size,1,File);
	printf("文件保存成功!");
	fclose(File);
	free(pNewBuffer);


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


//功能：添加新节
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

	//修改大小长度
	*OldBufferSize = NewLength;
}

//功能：扩大节
void ExpandSection(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer){

	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;

	DWORD TheBiggerOfSizeOfRawDataOrVirtualSize = 0;
	DWORD NewLength=0;
	
	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);

	
	//生成对应的内存大小的空间
	NewLength += *OldBufferSize + 0x1000;
	*pNewBuffer = (PVOID)malloc(NewLength);
	ZeroMemory(*pNewBuffer,NewLength);
	
	//拷贝之前内存空间 到 当前新生成的内存空间
	memcpy(*pNewBuffer,pFileBuffer,*OldBufferSize);

	//修改节数据的偏移
	if(pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1].Misc.VirtualSize > pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1].SizeOfRawData){
		TheBiggerOfSizeOfRawDataOrVirtualSize = pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1].Misc.VirtualSize;
	}else{
		TheBiggerOfSizeOfRawDataOrVirtualSize = pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1].SizeOfRawData;
	}

	pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1].Misc.VirtualSize = TheBiggerOfSizeOfRawDataOrVirtualSize;
	pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1].SizeOfRawData = TheBiggerOfSizeOfRawDataOrVirtualSize;

	// pImageOptionalHeader->SizeOfImage修改
	pImageOptionalHeader->SizeOfImage = (DWORD)pImageOptionalHeader->SizeOfImage + 0x1000;

	*OldBufferSize = NewLength;
}

// 功能：打印PE结构
void printfPE(PVOID pFileBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PVOID AddressOfNamesTable = NULL;
	DWORD AddressOfNameOrdinalsNumber = NULL;
	PVOID FunctionOfAddress = NULL;
	char FunName[10] = {0};
	int i,j;

	DWORD FOA;
	char SectionName[9] = {0};

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);


    //判断是否是有效的MZ标志，也就是0x5A4D，取前四个字节
    if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)    
    {   
        printf("不是有效的MZ标志\n");
        free(pFileBuffer);
        return ; 
    }   
	

    
    //打印DOS头    
    printf("********************DOS头********************\n\n"); 
    printf("_IMAGE_DOS_HEADERMZ->e_magic MZ标志：0x%x\n",pDosHeader->e_magic);
    printf("_IMAGE_DOS_HEADERMZ->e_lfanew指向PE标志：0x%x\n",pDosHeader->e_lfanew);
    printf("\n");
	
    //判断是否是有效的PE标志  
    if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)  
    {   
        printf("不是有效的PE标志\n");
        free(pFileBuffer);
        return ;
    }   
	
    
    //打印NT头 
    printf("********************NT头********************\n\n");  
    printf("_IMAGE_NT_HEADERS->Signature文件PE标识：0x%x\n",pNTHeader->Signature);
    printf("\n");
	

    printf("********************PE头********************\n\n");  
    printf("_IMAGE_FILE_HEADER->Machine支持的CPU：0x%x\n",pPEHeader->Machine);
    printf("_IMAGE_FILE_HEADER->NumberOfSections节的数量：0x%x\n",pPEHeader->NumberOfSections);
    printf("_IMAGE_FILE_HEADER->SizeOfOptionalHeader可选PE头的大小：0x%x\n",pPEHeader->SizeOfOptionalHeader);
    printf("\n");

	
    printf("********************OPTIOIN_PE头********************\n\n");  
    printf("_IMAGE_OPTIONAL_HEADER->Magic分辨系统位数:0x%x\n",pOptionHeader->Magic);
    printf("_IMAGE_OPTIONAL_HEADER->AddressOfEntryPoint程序入口:0x%x\n",pOptionHeader->AddressOfEntryPoint);
    printf("_IMAGE_OPTIONAL_HEADER->ImageBase内存镜像基址:0x%x\n",pOptionHeader->ImageBase);
    printf("_IMAGE_OPTIONAL_HEADER->SectionAlignment内存对齐大小:0x%x\n",pOptionHeader->SectionAlignment);
    printf("_IMAGE_OPTIONAL_HEADER->FileAlignment文件对齐大小:0x%x\n",pOptionHeader->FileAlignment);
    printf("_IMAGE_OPTIONAL_HEADER->SizeOfImage内存中PE的大小(SectionAlignment整数倍):0x%x\n",pOptionHeader->SizeOfImage);
    printf("_IMAGE_OPTIONAL_HEADER->SizeOfHeaders头+节表按照文件对齐的大小:0x%x\n",pOptionHeader->SizeOfImage);
    printf("_IMAGE_OPTIONAL_HEADER->NumberOfRvaAndSizes目录项数目:0x%x\n",pOptionHeader->NumberOfRvaAndSizes);
	
    printf("\n");
	
    //节表
    printf("********************节表********************\n\n");
    
    for(i=1;i<=pPEHeader->NumberOfSections;i++){
        char SectionName[9] ={0};
        strcpy(SectionName,(char *)pSectionHeader->Name);
        printf("_IMAGE_SECTION_HEADER->Name:%s\n",SectionName);
        printf("_IMAGE_SECTION_HEADER->VirtualSize:0x%x\n",pSectionHeader->Misc);
        printf("_IMAGE_SECTION_HEADER->VirtualAddress:0x%x\n",pSectionHeader->VirtualAddress);
        printf("_IMAGE_SECTION_HEADER->SizeOfRawData:0x%x\n",pSectionHeader->SizeOfRawData);
        printf("_IMAGE_SECTION_HEADER->PointerToRawData:0x%x\n",pSectionHeader->PointerToRawData);
        printf("_IMAGE_SECTION_HEADER->Characteristics:0x%x\n",pSectionHeader->Characteristics);
        pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
        printf("\n");
    }


	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress,&FOA);
	
	//导出表的地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + FOA);
	
	//目录表中的16张表的解析
	
	//先解析第一张表《导出表》
	printf("********************导出表********************\n\n");
	printf("导出表的虚拟地址:%x\n",pOptionHeader->DataDirectory[0].VirtualAddress);
	printf("导出表的大小:%x\n",pOptionHeader->DataDirectory[0].Size);
	printf("_IMAGE_EXPORT_DIRECTORY->Characteristics: 0x%x\n",pExportDirectory->Characteristics);
	printf("_IMAGE_EXPORT_DIRECTORY->TimeDateStamp时间戳: 0x%x\n",pExportDirectory->TimeDateStamp);
	printf("_IMAGE_EXPORT_DIRECTORY->MajorVersion: 0x%x\n",pExportDirectory->MajorVersion);
	printf("_IMAGE_EXPORT_DIRECTORY->MinorVersion: 0x%x\n",pExportDirectory->MinorVersion);
	printf("_IMAGE_EXPORT_DIRECTORY->Name指向该导出表文件名字符串: 0x%x\n",pExportDirectory->Name);
	printf("_IMAGE_EXPORT_DIRECTORY->Base导出函数起始序号: 0x%x\n",pExportDirectory->Base);
	printf("_IMAGE_EXPORT_DIRECTORY->NumberOfFunctions所有导出函数的个数: 0x%x\n",pExportDirectory->NumberOfFunctions);
	printf("_IMAGE_EXPORT_DIRECTORY->NumberOfNames以函数名字导出的函数个数: 0x%x\n",pExportDirectory->NumberOfNames);
	printf("_IMAGE_EXPORT_DIRECTORY->RVA_AddressOfFunctions导出函数地址表: 0x%x\n",pExportDirectory->AddressOfFunctions);
	printf("_IMAGE_EXPORT_DIRECTORY->RAV_AddressOfNames导出函数名称表: 0x%x\n",pExportDirectory->AddressOfNames);
	printf("_IMAGE_EXPORT_DIRECTORY->RVA_AddressOfNameOrdinals导出函数序号表: 0x%x\n",pExportDirectory->AddressOfNameOrdinals);	

	printf("\n");




	//1、导出函数名称表来寻找导出函数地址表，AddressOfNames是一个指向函数名称的RVA地址，需要先转换为 文件偏移地址
	RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfNames,&FOA);

	//printf("pExportDirectory->AddressOfNames导出函数名称表: 0x%x\n",FOA);

	//2、再加上pFileBuffer，转换为文件地址，得到函数名称存储的地方的首地址，当前的首地址是RVA，也需要进行RVA -> FOA转换
	AddressOfNamesTable = (PVOID)(*(PDWORD)((DWORD)pFileBuffer+(DWORD)FOA)); 
	RVA_TO_FOA(pFileBuffer,(DWORD)AddressOfNamesTable,&FOA); // // 导出函数名称表中函数名称的FOA

	//AddressOfNamesTable = (PVOID)FOA;
	AddressOfNamesTable = (PVOID)((DWORD)pFileBuffer + (DWORD)FOA); // 加上pFileBuffer位置就到了真正的函数名称表的地址
	printf("\n");
	
	//3、得到函数名称表的文件地址，每个函数的名称 占四个字节，然后进行遍历判断	
	for(j=0;j<pExportDirectory->NumberOfNames;j++){
		//(PDWORD)((DWORD)AddressOfNamesTable + 4*j);
		//获取当前函数名称表中的函数名称，然后循环判断
		//printf("this is my test:%s \n", (PVOID)((DWORD)AddressOfNamesTable));
		strcpy(FunName,(PVOID)((DWORD)AddressOfNamesTable)); //这里+1 是最后一个字节为空字节 那么就为结束符
		if(0 == memcmp((PDWORD)((DWORD)AddressOfNamesTable),(PDWORD)FunName,strlen(FunName))){
			AddressOfNamesTable = (PVOID)((DWORD)AddressOfNamesTable + (DWORD)(strlen(AddressOfNamesTable)+1));			
			//4、找到序号表AddressOfNameOrdinals下标所对应的的值，序号表中每个成员占2字节 word类型
			RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfNameOrdinals,&FOA);
			AddressOfNameOrdinalsNumber = *(PWORD)((DWORD)FOA + (DWORD)pFileBuffer + (DWORD)j*2);
			//5、通过序号表中下标对用的值去导出函数地址表AddressOfFunctions中寻找 该值下标对应的值
			RVA_TO_FOA(pFileBuffer,pExportDirectory->AddressOfFunctions,&FOA);
			printf("函数序号: %d\t",AddressOfNameOrdinalsNumber);
			printf("函数名称为: %s\t",FunName);
			printf("导出函数地址表的地址为：0x%.8x\n",*(PDWORD)(PVOID)((DWORD)FOA + (DWORD)pFileBuffer + AddressOfNameOrdinalsNumber*4));
		}
	}
	
	printf("\n");

	printf("********************导入表********************\n\n");
	printf("导入表的虚拟地址:%x\n",pOptionHeader->DataDirectory[1].VirtualAddress);
	printf("导入表的大小:%x\n",pOptionHeader->DataDirectory[1].Size);

	
	printf("\n");

	printf("********************资源表********************\n\n");
	printf("资源表的虚拟地址:%x\n",pOptionHeader->DataDirectory[2].VirtualAddress);
	printf("资源表的大小:%x\n",pOptionHeader->DataDirectory[2].Size);
	printf("\n");

    //释放内存  
    free(pFileBuffer);  
}

// 功能：打印重定位表
void PrintRelocation(PVOID pFileBuffer){

	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_BASE_RELOCATION pRelocationDirectory = NULL;
	DWORD FOA;
	DWORD RVA_Data;
	WORD reloData;
	int NumberOfRelocation = 0;
	PWORD Location = NULL;
	int i;

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	// _IMAGE_DATA_DIRECTORY中的指向重定位表的虚拟地址转换为FOA地址
	//printf("%x\n",pOptionHeader->DataDirectory[5].VirtualAddress);

	printf("pRelocationDirectory_RVA:%x\n",pOptionHeader->DataDirectory[5].VirtualAddress);
	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress,&FOA);
	printf("pRelocationDirectory_FOA:%x\n", FOA);

	pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer+(DWORD)FOA); //定位第一张重定位表 文件中的地址

	while(pRelocationDirectory->SizeOfBlock && pRelocationDirectory->VirtualAddress){
		printf("VirtualAddress    :%08X\n", pRelocationDirectory->VirtualAddress);
		printf("SizeOfBlock       :%08X\n", pRelocationDirectory->SizeOfBlock);
		printf("================= BlockData Start ======================\n");

		
		NumberOfRelocation = (pRelocationDirectory->SizeOfBlock - 8)/2;// 每个重定位块中的数据项的数量

		Location = (PWORD)((DWORD)pRelocationDirectory + 8); // 加上8个字节

		for(i=0;i<NumberOfRelocation;i++){
			if(Location[i] >> 12 != 0){ //判断是否是垃圾数据
				// WORD类型的变量进行接收
				reloData = (Location[i] & 0xFFF); //这里进行与操作 只取4字节 二进制的后12位
				RVA_Data = pRelocationDirectory->VirtualAddress + reloData; //这个是RVA的地址
				RVA_TO_FOA(pFileBuffer,RVA_Data,&FOA);
				printf("第[%04X]项  数据项的数据为:[%04X]  数据属性为:[%X]  RVA的地址为:[%08X]  重定位的数据:[%08X]\n",i+1,reloData,(Location[i] >> 12),RVA_Data,*(PDWORD)((DWORD)pFileBuffer+FOA));
			}
		}
		pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationDirectory + (DWORD)pRelocationDirectory->SizeOfBlock); //上面的for循环完成之后，跳转到下个重定位块 继续如上的操作
	}
}

// 功能：移动导入表
void MoveExportTable(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer){
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;

	PIMAGE_EXPORT_DIRECTORY EXPORT_TABLE = NULL;
	PIMAGE_EXPORT_DIRECTORY EXPORT_TABLE_NewBuffer = NULL;

	PDWORD AddressFunctionName;
	DWORD RVA = 0;
	DWORD FOA = 0;
	PDWORD pTempAddress;

	int FunNameLen = 0;

	char FunName[10] = {0};

	int i = 0;
	int j = 0;
	int all_num = 0;


	DWORD isOk;
	DWORD NewLength=0;
	PVOID LastSection = NULL;

	pImageDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	/*
	第一步：新增节
	*/

	//判断是否可以容纳相应的节表
	isOk = (DWORD)pImageOptionalHeader->SizeOfHeaders - ((DWORD)pImageDosHeader->e_lfanew + IMAGE_SIZEOF_FILE_HEADER + pImageFileHeader->SizeOfOptionalHeader + 40*pImageFileHeader->NumberOfSections);
	if(isOk < 80){
		printf("空间太小 无法进行添加!");
		return;
	}

	//申请对应的内存大小的空间
	NewLength += *OldBufferSize + 0x1000;
	*pNewBuffer = (PVOID)malloc(NewLength);
	ZeroMemory(*pNewBuffer,NewLength);

	//拷贝之前内存空间 到 当前新生成的内存空间
	memcpy(*pNewBuffer,pFileBuffer,*OldBufferSize);

	//获取新的空间中的PE结构体
	pImageDosHeader = (PIMAGE_DOS_HEADER)(*pNewBuffer);
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew + 4);
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeaderGroup = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	
	// pImageFileHeader->NumberOfSections修改
	pImageFileHeader->NumberOfSections = pImageFileHeader->NumberOfSections + 1;
	
	// pImageOptionalHeader->SizeOfImage修改
	pImageOptionalHeader->SizeOfImage = (DWORD)pImageOptionalHeader->SizeOfImage + 0x1000;

	// 得到新增节的地址,LastSection
	LastSection = (PVOID)(DWORD)(&pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1]);
	RVA_TO_FOA(*pNewBuffer,pImageOptionalHeader->DataDirectory[0].VirtualAddress,&FOA);
	EXPORT_TABLE = (PIMAGE_EXPORT_DIRECTORY)((DWORD)*pNewBuffer + (DWORD)FOA);

	/*
	第二步：复制AddressOfFunctions
	长度：4*NumberOfFunctions		
	*/
	printf("AddressOfFunctions个数: %d 每个占4字节\n", EXPORT_TABLE->NumberOfFunctions);
	RVA_TO_FOA(*pNewBuffer,EXPORT_TABLE->AddressOfFunctions,&FOA);
	memcpy(LastSection,(PVOID)((DWORD)*pNewBuffer + FOA),((DWORD)EXPORT_TABLE->NumberOfFunctions)*4);

	/*
	第三步：复制AddressOfNameOrdinals				
	长度：NumberOfNames*2			
	*/
	printf("AddressOfNameOrdinals个数: %d 每个占2字节\n", EXPORT_TABLE->NumberOfNames);

	RVA_TO_FOA(*pNewBuffer, EXPORT_TABLE->AddressOfNameOrdinals,&FOA);
	memcpy((PVOID)((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4),(PVOID)((DWORD)*pNewBuffer + FOA),((DWORD)EXPORT_TABLE->NumberOfNames)*2);

	/*
	第四步：复制AddressOfNames
	长度：NumberOfNames*4		
	*/
	printf("AddressOfNames个数: %d 每个占4字节\n", EXPORT_TABLE->NumberOfNames);
	RVA_TO_FOA(*pNewBuffer, EXPORT_TABLE->AddressOfNames,&FOA);
	memcpy((PVOID)((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 + ((DWORD)EXPORT_TABLE->NumberOfNames)*2),(PVOID)((DWORD)*pNewBuffer + FOA),(DWORD)EXPORT_TABLE->NumberOfNames*4);

	/*
	第五步：复制所有的函数名
	长度不确定，复制时直接修复AddressOfNames				
	*/

	for(j=0;j<EXPORT_TABLE->NumberOfNames;j++){
		//获得函数名称表的RVA，将其转换为FOA
		RVA_TO_FOA(*pNewBuffer, EXPORT_TABLE->AddressOfNames,&FOA);

		// 每个函数的RVA转换为FOA
		RVA_TO_FOA(*pNewBuffer, FOA, &FOA);
		
		//获取当前函数名称的偏移地址
		AddressFunctionName = (PDWORD)(*(PDWORD)((DWORD)*pNewBuffer + (DWORD)FOA + (DWORD)all_num));
		//printf("%x",AddressFunctionName);

		//将当前的函数名称的偏移地址加上 pNewBuffer 得到对应的内存地址 ，通过strcpy来获取当前地址保存的函数名称
		strcpy(FunName,(PVOID)((DWORD)*pNewBuffer + (DWORD)AddressFunctionName));
		//printf("%s",FunName);

		//得到当前函数名称的长度
		FunNameLen = strlen(FunName) + 1; //最后结尾需要+1，原因\0 空字节
		
		//拿到函数的长度和名称之后需要进行复制
		memcpy(
			(PVOID)((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 + ((DWORD)EXPORT_TABLE->NumberOfNames)*2 + ((DWORD)EXPORT_TABLE->NumberOfNames)*4 + (DWORD)all_num) //这里到时候加循环来进行偏移复制
			,(PVOID)((DWORD)*pNewBuffer + (DWORD)AddressFunctionName)
			,FunNameLen);
		
		//接下来需要进行修复

		//过程：每次复制完 还需要修复下之前刚复制AddressOfNames中的对应的地址 让它里面的值 保存为当前复制的函数地址
		
		//通过all_num来进行偏移 从而获得当前的地址是指向第j个函数的地址
		pTempAddress = (PDWORD)((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 + ((DWORD)EXPORT_TABLE->NumberOfNames)*2 + (DWORD)all_num);

		//上面获得的地址是VA 还需要减去pNewBuffer变成FOA 然后再转换为RVA 最后存储到新复制的函数名称表对应的地址当中
		FOA_TO_RVA(*pNewBuffer
			,((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 + ((DWORD)EXPORT_TABLE->NumberOfNames)*2 + ((DWORD)EXPORT_TABLE->NumberOfNames)*4 + (DWORD)all_num) -(DWORD)*pNewBuffer
			,&RVA);
		
		//修改当前pTempAddress指向的地址中的值，修改为之前每个函数名称的的地址
		*pTempAddress = RVA;
		
		// all_num用来保存复制函数名称的时候一共用了多少个字节
		all_num += FunNameLen;
  }

	/*
	第六步：复制IMAGE_EXPORT_DIRECTORY结构				
	*/
	memcpy((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 + ((DWORD)EXPORT_TABLE->NumberOfNames)*2 + ((DWORD)EXPORT_TABLE->NumberOfNames)*4 + (DWORD)all_num
		,EXPORT_TABLE
		,40
		);

	
	/*
	第七步：修复IMAGE_EXPORT_DIRECTORY结构中的

	AddressOfFunctions					
	AddressOfNameOrdinals										
	AddressOfNames					
	*/
	EXPORT_TABLE_NewBuffer = (PIMAGE_EXPORT_DIRECTORY)((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 
		+ ((DWORD)EXPORT_TABLE->NumberOfNames)*2 
		+ ((DWORD)EXPORT_TABLE->NumberOfNames)*4 
		+ (DWORD)all_num);

	
	//将新的缓冲区中的三个表中存储的地址都进行修改为上面移动好的位置
	EXPORT_TABLE_NewBuffer->AddressOfFunctions = (DWORD)LastSection;
	EXPORT_TABLE_NewBuffer->AddressOfNameOrdinals = ((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4);
	EXPORT_TABLE_NewBuffer->AddressOfNames = ((DWORD)LastSection + ((DWORD)EXPORT_TABLE->NumberOfFunctions)*4 + ((DWORD)EXPORT_TABLE->NumberOfNames)*2);
	
	/*
	第八步：修复目录项中的值，指向新的IMAGE_EXPORT_DIRECTORY						
	*/
	
	FOA_TO_RVA(*pNewBuffer,(DWORD)EXPORT_TABLE_NewBuffer - (DWORD)*pNewBuffer,&RVA);
	pImageOptionalHeader->DataDirectory[0].VirtualAddress = RVA;

	/*
	第九步：将pNewBuffer缓冲区的地址保存为新的文件
	*/
	MyWriteFile(*pNewBuffer, NewLength);
		
}

void MoveRelocationTable(PVOID pFileBuffer, PDWORD OldBufferSize,PVOID* pNewBuffer){
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;
	PIMAGE_BASE_RELOCATION pRelocationDirectory = NULL;
	
	DWORD isOk;
	DWORD NewLength=0;
	PVOID LastSection = NULL;
	PVOID CodeSection = NULL;
	PVOID AddressOfSectionTable = NULL;
	PVOID pTemp;

	DWORD AllSizeOfBlock = 0;
	DWORD RVA = 0;
	DWORD FOA = 0;

	int NumberOfRelocation=0;
	PWORD Location = NULL;
	int i = 0;
	DWORD RVA_Data;
	WORD reloData;



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

	//到这里新增节已经完成了
	AddressOfSectionTable = (PVOID)((DWORD)*pNewBuffer + (DWORD)NewSec->PointerToRawData);
	
	//printf("%x",AddressOfSectionTable);

	//重定位表的FOA
	RVA_TO_FOA(*pNewBuffer,pImageOptionalHeader->DataDirectory[5].VirtualAddress,&FOA);
	
	//获取结构
	pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)*pNewBuffer + FOA);

	pTemp = pRelocationDirectory;
	
	//printf("%x",pRelocationDirectory->VirtualAddress);
	
	//获取重定位表大小
	while(pRelocationDirectory->SizeOfBlock && pRelocationDirectory->VirtualAddress){
		AllSizeOfBlock = pRelocationDirectory->SizeOfBlock;
		pRelocationDirectory = ((DWORD)pRelocationDirectory + (DWORD)pRelocationDirectory->SizeOfBlock);
	}
	
	//复制重定位表到新增的节数据中
	memcpy(AddressOfSectionTable,pTemp,AllSizeOfBlock);

	//将PE可选头中的重定位的地址指向新增节数据的起始地址
	pImageOptionalHeader->DataDirectory[5].VirtualAddress = (DWORD)AddressOfSectionTable;

	
	//修改DLL的ImageBase	
	//pImageOptionalHeader->ImageBase += 1000;

	//=============================================================
	//=============================================================
	//=============================================================
	//=============================================================

		
	printf("pRelocationDirectory_RVA:%x\n",pImageOptionalHeader->DataDirectory[5].VirtualAddress);
	RVA_TO_FOA(pFileBuffer,pImageOptionalHeader->DataDirectory[5].VirtualAddress,&FOA);
	printf("pRelocationDirectory_FOA:%x\n", FOA);
	
	pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer+(DWORD)FOA); //定位第一张重定位表 文件中的地址
	
	while(pRelocationDirectory->SizeOfBlock && pRelocationDirectory->VirtualAddress){
		printf("VirtualAddress    :%08X\n", pRelocationDirectory->VirtualAddress);
		printf("SizeOfBlock       :%08X\n", pRelocationDirectory->SizeOfBlock);
		printf("================= BlockData Start ======================\n");
		
		
		NumberOfRelocation = (pRelocationDirectory->SizeOfBlock - 8)/2;// 每个重定位块中的数据项的数量
		
		Location = (PWORD)((DWORD)pRelocationDirectory + 8); // 加上8个字节
		
		for(i=0;i<NumberOfRelocation;i++){
			if(Location[i] >> 12 != 0){ //判断是否是垃圾数据
				// WORD类型的变量进行接收
				reloData = (Location[i] & 0xFFF); //这里进行与操作 只取4字节 二进制的后12位
				RVA_Data = pRelocationDirectory->VirtualAddress + reloData; //这个是RVA的地址
				RVA_TO_FOA(pFileBuffer,RVA_Data,&FOA);
				printf("第[%04X]项  数据项的数据为:[%04X]  数据属性为:[%X]  RVA的地址为:[%08X]  重定位的数据:[%08X]\n"
					,i+1
					,reloData
					,(Location[i] >> 12)
					,RVA_Data
					,*(PDWORD)((DWORD)pFileBuffer+(DWORD)FOA));

				//这里是自增的 进行修复重定位，上面的Imagebase我们自增了1000，那么要修复的地址都需要自增1000
				*(PDWORD)((DWORD)pFileBuffer+(DWORD)FOA) = *(PDWORD)((DWORD)pFileBuffer+(DWORD)FOA) + 1000;				
			}
		}
		pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationDirectory + (DWORD)pRelocationDirectory->SizeOfBlock); //上面的for循环完成之后，跳转到下个重定位块 继续如上的操作
	}

	//=============================================================
	//=============================================================
	//=============================================================
	//=============================================================
	//保存文件
	MyWriteFile(*pNewBuffer,NewLength);
}

void PrintfImportTable(PVOID pFileBuffer){
    PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR;
	PIMAGE_IMPORT_BY_NAME pImage_IMPORT_BY_NAME;


	char ImportTableDllName[10] = {0};
	char FunctionName[20] = {0};

	PDWORD OriginalFirstThunk_INT = NULL;
	PDWORD FirstThunk_IAT = NULL;

	DWORD RVA = 0;
	DWORD FOA = 0;
	DWORD Original = 0;
	
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);

	//获取导入表的位置
	RVA_TO_FOA(pFileBuffer,pOptionHeader->DataDirectory[1].VirtualAddress,&FOA);


	//每个导入表的相关信息占20个字节
	pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + (DWORD)FOA);
	
	//这里可以进行while操作，这里while的判断依据为 pIMPORT_DESCRIPTOR个数

	printf("=========================================");
	
	while(pIMPORT_DESCRIPTOR->FirstThunk && pIMPORT_DESCRIPTOR->OriginalFirstThunk){
		//这里打印的是INT表
		//获取当前导入表DLL的名字
		strcpy(ImportTableDllName,(PVOID)((DWORD)pFileBuffer + (DWORD)pIMPORT_DESCRIPTOR->Name));
		
		printf("当前打印的导出表的DLL为: %s \n", ImportTableDllName);
		printf("\n");

		//printf("TimeDateStamp: %x\n",pIMPORT_DESCRIPTOR->TimeDateStamp);
		

		printf("INT表打印\n");
		//OriginalFirstThunk转换FOA
		RVA_TO_FOA(pFileBuffer,pIMPORT_DESCRIPTOR->OriginalFirstThunk,&FOA);
		
		OriginalFirstThunk_INT = (PDWORD)((DWORD)pFileBuffer + (DWORD)FOA);
		
		//printf("%x",*OriginalFirstThunk_INT);
		printf("\n");
		while(*OriginalFirstThunk_INT){
			//printf("%x\n ",*OriginalFirstThunk_INT);
			if((*OriginalFirstThunk_INT) & 0X80000000){
				//高位为1 则 除去最高位的值就是函数的导出序号
				Original = *OriginalFirstThunk_INT & 0xFFF;	//去除最高标志位。
				printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
			}else{
				//高位不为1 则指向IMAGE_IMPORT_BY_NAME
				RVA_TO_FOA(pFileBuffer,*OriginalFirstThunk_INT,&FOA);
				pImage_IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)FOA;
				strcpy(FunctionName,(PVOID)((DWORD)pFileBuffer + (DWORD)&(pImage_IMPORT_BY_NAME->Name)));
				printf("按函数名导入 函数名为: %s \n",FunctionName);
			}
			OriginalFirstThunk_INT++;
		}

		printf("\n");
		

		//继续如上操作进行打印操作
		//这里打印的是iat表

		printf("IAT表打印\n");
		//FirstThunk转换FOA
		RVA_TO_FOA(pFileBuffer,pIMPORT_DESCRIPTOR->FirstThunk,&FOA);

		FirstThunk_IAT = (PDWORD)((DWORD)pFileBuffer + (DWORD)FOA);
		
		//printf("%x",*OriginalFirstThunk_INT);
		printf("\n");
		while(*FirstThunk_IAT){
			printf("%x\n ",*FirstThunk_IAT);

			
			if((*FirstThunk_IAT) & 0X80000000){
				//高位为1 则 除去最高位的值就是函数的导出序号
				Original = *FirstThunk_IAT & 0xFFF;	//去除最高标志位。
				printf("按序号导入: %08Xh -- %08dd\n", Original, Original);	//16进制 -- 10 进制
			}else{
				//高位不为1 则指向IMAGE_IMPORT_BY_NAME
				RVA_TO_FOA(pFileBuffer,*FirstThunk_IAT,&FOA);
				pImage_IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)FOA;
				strcpy(FunctionName,(PVOID)((DWORD)pFileBuffer + (DWORD)&(pImage_IMPORT_BY_NAME->Name)));
				printf("按函数名导入 函数名为: %s \n",FunctionName);
			}
			
			FirstThunk_IAT++;
		}
		
		printf("=========================================");
		printf("\n");
		
		pIMPORT_DESCRIPTOR++;		
	}
}

void PrintBindImportTable(PVOID pFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;    
    PIMAGE_NT_HEADERS pNTHeader = NULL; 
    PIMAGE_FILE_HEADER pPEHeader = NULL;    
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;  
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pIMAGE_BOUND_IMPORT_DESCRIPTOR = NULL;
	PIMAGE_BOUND_FORWARDER_REF pIMAGE_BOUND_FORWARDER_REF = NULL;

	char ModuleName[20] = {0};
	DWORD BOUNG_IMPORT_DESCRIPTOR_TEMP = NULL;
	int i = 0;
	DWORD RVA = 0;
	DWORD FOA = 0;
	
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER); 
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + IMAGE_SIZEOF_NT_OPTIONAL_HEADER);
	
	RVA_TO_FOA(pFileBuffer, pOptionHeader->DataDirectory[11].VirtualAddress,&FOA);

	//保存第一个DESCRIPTOR的地址 后面加OffsetModuleName来进行使用
	BOUNG_IMPORT_DESCRIPTOR_TEMP = (DWORD)pFileBuffer+(DWORD)FOA;

	
	//开始进行打印操作
	pIMAGE_BOUND_IMPORT_DESCRIPTOR = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer+(DWORD)FOA);
	
	while (*(PDWORD)pIMAGE_BOUND_IMPORT_DESCRIPTOR)
	{
		printf("\n");
		strcpy(ModuleName, (PVOID)((DWORD)BOUNG_IMPORT_DESCRIPTOR_TEMP + (DWORD)pIMAGE_BOUND_IMPORT_DESCRIPTOR->OffsetModuleName));
		printf("模块名称: %s \n",ModuleName);
		printf("模块的时间戳为: %x \n", pIMAGE_BOUND_IMPORT_DESCRIPTOR->TimeDateStamp);
		printf("当前模块引用的dll的数量为: %x\n",pIMAGE_BOUND_IMPORT_DESCRIPTOR->NumberOfModuleForwarderRefs);

		for(i=0;i<pIMAGE_BOUND_IMPORT_DESCRIPTOR->NumberOfModuleForwarderRefs;i++){
			pIMAGE_BOUND_IMPORT_DESCRIPTOR++;
			pIMAGE_BOUND_FORWARDER_REF = (PIMAGE_BOUND_FORWARDER_REF)pIMAGE_BOUND_IMPORT_DESCRIPTOR;
			strcpy(ModuleName, (PVOID)((DWORD)BOUNG_IMPORT_DESCRIPTOR_TEMP + (DWORD)pIMAGE_BOUND_FORWARDER_REF->OffsetModuleName));
			printf("\t引用的模块名称: %s \n",ModuleName);
			printf("\t引用的模块的时间戳: %x\n", pIMAGE_BOUND_FORWARDER_REF->TimeDateStamp);
		}
	
		pIMAGE_BOUND_IMPORT_DESCRIPTOR++;
	}
}

void MoveAndInjectImportTable(PVOID pFileBuffer,PDWORD OldBufferSize,PVOID* pNewBuffer){

	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_FILE_HEADER pImageFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pImageOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pImageSectionHeaderGroup = NULL;
	PIMAGE_SECTION_HEADER NewSec = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR_Temp = NULL;
	PIMAGE_IMPORT_BY_NAME IMPORT_BY_NAME = NULL;

	
	DWORD RVA = 0;
	DWORD FOA = 0;
	DWORD isOk;
	DWORD NewLength=0;
	PVOID LastSection = NULL;
	PVOID CodeSection = NULL;
	PVOID SectionOfNew= NULL;
	PVOID SectionOfNewTemp = NULL;

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
	
	//新增节的位置
	LastSection = (PVOID)(DWORD)(&pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-1]);
	memcpy(LastSection,CodeSection,40);
	
	//修正相关属性
	NewSec = (PIMAGE_SECTION_HEADER)LastSection;
	strcpy(NewSec,".NewSec");
	NewSec->Misc.VirtualSize = 0x1000;
	NewSec->SizeOfRawData = 0x1000;
	NewSec->VirtualAddress = pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].VirtualAddress + pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].SizeOfRawData;
	NewSec->PointerToRawData = pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].PointerToRawData + pImageSectionHeaderGroup[pImageFileHeader->NumberOfSections-2].SizeOfRawData;
	
	//修改大小长度
	*OldBufferSize = NewLength;

	//这里得到新节位置的指针
	SectionOfNew = (PVOID)((DWORD)*pNewBuffer + (DWORD)NewSec->PointerToRawData);

	//先获取导入表的地址
	RVA_TO_FOA(*pNewBuffer,pImageOptionalHeader->DataDirectory[1].VirtualAddress,&FOA);
	pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)*pNewBuffer + (DWORD)FOA);
	//printf("start:%x\n", pIMPORT_DESCRIPTOR);

	/*
	第三步：			
	将原导入表全部Copy到空白区			
	*/

	SectionOfNewTemp = SectionOfNew;

	while (pIMPORT_DESCRIPTOR->OriginalFirstThunk && pIMPORT_DESCRIPTOR->FirstThunk)
	{
		//printf("%x\n", (DWORD)SectionOfNewTemp - (DWORD)*pNewBuffer);
		memcpy(SectionOfNewTemp,pIMPORT_DESCRIPTOR,20);
		pIMPORT_DESCRIPTOR++;
		SectionOfNewTemp = (PVOID)((DWORD)SectionOfNewTemp + 20);
	}
	
	//保存复制完导入表之后的地址
	pIMPORT_DESCRIPTOR_Temp = SectionOfNewTemp;
	printf("开始添加自己的导入表的地址:%x\n",(DWORD)SectionOfNewTemp-(DWORD)*pNewBuffer);


	/*
	第四步：				
	在新的导入表后面，追加一个导入表.
	  typedef struct _IMAGE_IMPORT_DESCRIPTOR {							
	  union {							
	  DWORD   Characteristics;           							
	  DWORD   OriginalFirstThunk;         							
	  };							
	  DWORD   TimeDateStamp;               							
	  DWORD   ForwarderChain;              							
	  DWORD   Name;							
	  DWORD   FirstThunk;                 							
	  } IMAGE_IMPORT_DESCRIPTOR;							
	  typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;							
	*/

	pIMPORT_DESCRIPTOR->TimeDateStamp = 0;
	
	pIMPORT_DESCRIPTOR->ForwarderChain = -1;

	FOA_TO_RVA(*pNewBuffer,(DWORD)pIMPORT_DESCRIPTOR_Temp + 40 - (DWORD)*pNewBuffer,&RVA); // INT表占8个字节
	pIMPORT_DESCRIPTOR_Temp->OriginalFirstThunk = RVA;  //这个是指向导入表相关INT表 存的是RVA，所以前面还需要转换下

	FOA_TO_RVA(*pNewBuffer,(DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 8 - (DWORD)*pNewBuffer,&RVA); // IAT表占8个字节
	pIMPORT_DESCRIPTOR_Temp->FirstThunk = RVA;// 这个是指向导入表相关的IAT 存的是RVA，所以前面还需要转换下

	FOA_TO_RVA(*pNewBuffer,(DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 16 - (DWORD)*pNewBuffer,&RVA); // dll函数名占8个字节，这里自己就模拟 dll名称为abc.dll 长度为7个字节 最后一个字节为\0
	pIMPORT_DESCRIPTOR_Temp->Name = RVA; // 这个是指向导入表相关的DLL名称 存的是RVA 所以前面还需要转换下

	strcpy((PVOID)((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 16),"abc.dll");

	
	/*
	第五步：			
	追加8个字节的INT表  8个字节的IAT表	，一个_IMAGE_THUNK_DATA32结构是4个字节 但是还需要4个字节来作为结束的标识符	所以这里总共是占16个字节	
	*/
	
	FOA_TO_RVA(*pNewBuffer, ((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 24 - (DWORD)*pNewBuffer),&RVA);

	*(PDWORD)((DWORD)pIMPORT_DESCRIPTOR_Temp + 40) = RVA; //_IMAGE_THUNK_DATA32结构中的属性指向PIMAGE_IMPORT_BY_NAME 存的是RVA 所以前面需要转换下

	FOA_TO_RVA(*pNewBuffer, ((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 24 - (DWORD)*pNewBuffer),&RVA);
	
	*(PDWORD)((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 8) = RVA; //指向PIMAGE_IMPORT_BY_NAME 存的是RVA 所以前面需要转换下

	/*
	第六步：							
	  追加一个IMAGE_IMPORT_BY_NAME 结构，前2个字节是0 后面是函数名称字符串							
	*/

	//IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 26);

	//IMPORT_BY_NAME->Hint = 0;
	//IMPORT_BY_NAME->Name = "myFun";
	//strcpy(&IMPORT_BY_NAME->Name,"myFun");

	*(PWORD)((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 26) = 0;
	strcpy((PVOID)((DWORD)pIMPORT_DESCRIPTOR_Temp + 40 + 26),"myFun");//这里写死了，函数的名称为myFun

	/*
	第七步：								
	  修正IMAGE_DATA_DIRECTORY结构的VirtualAddress和Size
	*/

	
	FOA_TO_RVA(*pNewBuffer,(DWORD)SectionOfNew - (DWORD)*pNewBuffer,&RVA);
	pImageOptionalHeader->DataDirectory[1].VirtualAddress = RVA;
	pImageOptionalHeader->DataDirectory[1].Size = (DWORD)pImageOptionalHeader->DataDirectory[1].Size + 20;

	//最后进行存盘操作
	MyWriteFile(*pNewBuffer, NewLength);
}