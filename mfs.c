
/*
* CSE 3320-003
* Names: Jaehee Seh and Utibeabasi Eno Obot
* ID #s: 1000942800 and 1001541097
* Assignment 4: FAT32 File System
* Description: You will implement a user space shell application that is 
* capable of interpreting a FAT32 file system image. The utility must not 
* corrupt the file system image and should be robust. No existing kernel 
* code or any other FAT 32 utility code may be used in your program.
*/

// -------------------------------------------------------------------------

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

#define WHITESPACE " \t\n" // We want to split our command line up into tokens \
                           // so we need to define what delimits our tokens.   \
                           // In this case  white space                        \
                           // will separate the tokens on our command line

#define MAX_COMMAND_SIZE 255 // The maximum command-line size
FILE *fp;
FILE *of, *rf;

#define MAX_NUM_ARGUMENTS 5 // Mav shell only supports five arguments
#define Offset_BPB_BytesPerSec_ 11
#define Siz_BPB_BytesPerSec 2

#define Offset_BPB_SecPerClus 13
#define Siz_BPB_SecPerClus 1

#define Offset_BPB_RsvdSecCnt 14
#define Siz_BPB_RsvdSecCnt 2

#define Offset_BPB_NumFAT 16
#define Siz_BPB_NumFAT 1

#define Offset_BPB_RootEntCnt 17
#define Siz_BPB_RootEntCnt 2

#define Offset_BPB_FATSz32 36
#define Siz_BPB_FATSz32 4

#define Entry_Len 16

/*
#define BS_Vollab_Offset 71
#define BS_Vollab_Size 11

#define Volume_Name_Offset 71 // volume label/name offset
#define Volume_Name_Size 11   // volume length

#define MAX_FILE_NAME_SIZE 20
#define MAX_COMMAND_SIZE 200
#define MAX_NUM_ARGUMENTS 5
#define WHITESPACE " \t\n"

#define NUMBER_OF_ENTRIES 16 // fixed number of entries
#define LENTH_OF_DIR_NAME 11 // fixed length of directory/file name
*/

int if_open;
int close_f;

uint16_t BPB_BytesPerSec;
uint8_t BPB_SecPerClus;
uint16_t BPB_RsvdSecCnt;
uint8_t BPB_NumFATs;
uint16_t BPB_RootEntCnt;
uint32_t BPB_FATSz32;

// ************************************
// **** Change names on all var !!! ******
// ************************************
struct __attribute__((__packed__)) DirectoryEntry
{
  char DIR_Name[11];
  uint8_t Dir_Attr;
  uint8_t Unused1[8];
  uint16_t DIR_FirstClusterHigh;
  uint8_t Unused[4];
  uint16_t DIR_FirstClusterLow;
  uint32_t DIR_FileSize;
};

struct DirectoryEntry dir[16];

// This function deals with  printing out information about the file system in both hexadecimal and base 10//
void Info()
{

  fseek(fp, Offset_BPB_BytesPerSec_, SEEK_SET);
  fread(&BPB_BytesPerSec, Siz_BPB_BytesPerSec, 1, fp);

  fseek(fp, Offset_BPB_SecPerClus, SEEK_SET);
  fread(&BPB_SecPerClus, Siz_BPB_SecPerClus, 1, fp);

  fseek(fp, Offset_BPB_RsvdSecCnt, SEEK_SET);
  fread(&BPB_RsvdSecCnt, Siz_BPB_RsvdSecCnt, 1, fp);

  fseek(fp, Offset_BPB_NumFAT, SEEK_SET);
  fread(&BPB_NumFATs, Siz_BPB_NumFAT, 1, fp);

  fseek(fp, Offset_BPB_RootEntCnt, SEEK_SET);
  fread(&BPB_RootEntCnt, Siz_BPB_RootEntCnt, 1, fp);

  fseek(fp, Offset_BPB_FATSz32, SEEK_SET);
  fread(&BPB_FATSz32, Siz_BPB_FATSz32, 1, fp);

  // print root cluster
  int root_cluster = (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec) + (BPB_RsvdSecCnt * BPB_BytesPerSec);
  // printf("Root directory location: %x\n", root_cluster);
}

int OffBal_Sec(int32_t sec)
{
  if ( sec == 0 )
	return (sec * BPB_BytesPerSec) + (BPB_BytesPerSec * BPB_RsvdSecCnt) + (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec);
  return ((sec - 2) * BPB_BytesPerSec) + (BPB_BytesPerSec * BPB_RsvdSecCnt) + (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec);
}

int16_t Next_Sec( uint32_t sec)
{
  uint32_t address_FAT = (BPB_BytesPerSec * BPB_RsvdSecCnt) + (sec * 4);
  int16_t val;
  fseek(fp, address_FAT, SEEK_SET);
  fread( &val, 2, 1, fp );
  return val;
}

void Print_Info()
{

  printf("BPB_BytesPerSec: %d\n", BPB_BytesPerSec);
  printf("BPB_BytesPerSec: %x\n\n", BPB_BytesPerSec);

  printf("BPB_SecPerClus: %d\n", BPB_SecPerClus);
  printf("BPB_SecPerClus: %x\n\n", BPB_SecPerClus);

  printf("BPB_RsvdSecCnt: %d\n", BPB_RsvdSecCnt);
  printf("BPB_RsvdSecCnt: %x\n\n", BPB_RsvdSecCnt);

  printf("BPB_NumFATs: %d\n", BPB_NumFATs);
  printf("BPB_NumFATs: %x\n\n", BPB_NumFATs);

  printf("BPB_FATSz32: %d\n", BPB_FATSz32);
  printf("BPB_FATSz32: %x\n\n", BPB_FATSz32);
}

void close_Image()
{

  if (if_open == 0)
  {
    printf("Error: File system not open.\n");
  }

  else
  {

    fclose(fp);
    fp = NULL;
    if_open = 0;
    close_f = 1;
  }
}

void open_file(char *filename)
{
  if (if_open == 1)
  {
    printf("Error: File system image already open.\n");
  }

  else
  {
    fp = fopen(filename, "r");

    if (fp == NULL)
    {
      printf("Error: File system image not found.\n");
    }

    else
    {

      if_open = 1;
      close_f = 0;

      fseek(fp, Offset_BPB_BytesPerSec_, SEEK_SET);
      fread(&BPB_BytesPerSec, Siz_BPB_BytesPerSec, 1, fp);

      fseek(fp, Offset_BPB_SecPerClus, SEEK_SET);
      fread(&BPB_SecPerClus, Siz_BPB_SecPerClus, 1, fp);

      fseek(fp, Offset_BPB_RsvdSecCnt, SEEK_SET);
      fread(&BPB_RsvdSecCnt, Siz_BPB_RsvdSecCnt, 1, fp);

      fseek(fp, Offset_BPB_NumFAT, SEEK_SET);
      fread(&BPB_NumFATs, Siz_BPB_NumFAT, 1, fp);

      fseek(fp, Offset_BPB_RootEntCnt, SEEK_SET);
      fread(&BPB_RootEntCnt, Siz_BPB_RootEntCnt, 1, fp);

      fseek(fp, Offset_BPB_FATSz32, SEEK_SET);
      fread(&BPB_FATSz32, Siz_BPB_FATSz32, 1, fp);

      // print root cluster
      int root_cluster = (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec) + (BPB_RsvdSecCnt * BPB_BytesPerSec);
      fseek(fp, root_cluster, SEEK_SET);
      fread(&dir[0], sizeof(struct DirectoryEntry), 16, fp);
    }
  }
}

void ls_code()
{
  int i;
  for (i = 0; i < 16; i++)
  {

    if ((dir[i].Dir_Attr == 0x01 || dir[i].Dir_Attr == 0x10 || dir[i].Dir_Attr == 0x20 || dir[i].Dir_Attr == 0x30) && dir[i].DIR_Name[0] != 0xffffffe5)
    {
      char name[12];
      memset(&name, 0, 12);

      strncpy(name, dir[i].DIR_Name, 11);
      printf("%s\n", name);
    }
  }
}
//Taken from compare.c file
void compare(char *fName, char *fullname)
{

  char expanded_name[12];
  memset(expanded_name, ' ', 12);

  char *token = strtok(fName, ".");
  strncpy(expanded_name, token, strlen(token));
  token = strtok(NULL, ".");
  if (token)
  {
    strncpy((char *)(expanded_name + 8), token, strlen(token));
  }
  int i;
  for (i = 0; i < 11; i++)
  {
    expanded_name[i] = toupper(expanded_name[i]);
  }
  strncpy(fullname, expanded_name, strlen(expanded_name));
}

void Print_stat(char *fName)
{
  int i;
  char temp_name[12];
  //Taken from compare.c
  char expanded_name[12];
  compare(fName, &expanded_name[0]);
  expanded_name[11] = '\0';

  for (i = 0; i < Entry_Len; i++)
  {
    memcpy(temp_name, dir[i].DIR_Name, 11);
    temp_name[11] = '\0';

    if (dir[i].Dir_Attr == 0x01 || dir[i].Dir_Attr == 0x10 || dir[i].Dir_Attr == 0x20)
    {

      if (strcmp(expanded_name, temp_name) == 0)
      {

        printf("Attribute:\t %d\t", dir[i].Dir_Attr);
        printf("Size:\t %d\t", dir[i].DIR_FileSize);
        printf("Starting Cluster Number: \t %d\t \n", dir[i].DIR_FirstClusterLow);
      }
    }
  }
}

//This function shall retrieve the file from the FAT 32 image and 
// place it in your current working directory. If the file or 
// directory does not exist then your program shall output “Error: File not found”.

void get_file(char *filename)
{
  int i;
  char expanded_name[12];
  char temp_name[12];
  int file_size = 0;
  int detected = 0;
  int dir_cluster, off_bal;
  //rf = fp;

  for(i = 0; i < 16; i++)
  {
    strncpy(temp_name,dir[i].DIR_Name,12);
    temp_name[11] = '\0';

    if(strcmp(temp_name, expanded_name) == 0)
    {
      detected = dir[i].DIR_FirstClusterLow;
      file_size = dir[i].DIR_FileSize;
      break;
      
    }
  }
  if(detected == 0)
  {
    printf("Error: File not found.\n");
  }

	char buffer[512];
  dir_cluster = dir[i].DIR_FirstClusterLow;
  file_size = dir[i].DIR_FileSize;
  off_bal = OffBal_Sec(detected);
  fseek(rf, off_bal, SEEK_SET);
  //rf = fopen(token[1],"w");
	fread(&buffer[0],512,'1',of);
	fwrite(&buffer[0],512,'1',rf);
	file_size = file_size-512;
	//strncpy(temp_name, token[1], 12);
	rf = fopen(temp_name, "w");

  while(file_size > 0)
  {
    int location = LBAToOffset(dir_cluster);
		fseek(fp, location, SEEK_SET);
		fread(&buffer[0],file_size,'1',of);
		fwrite(&buffer[0],file_size,'1',rf);
		file_size = file_size - 512;
  }

}

void cd(char *input)
{
  int i;
  int detected = 0;
  int file_size = 0;
  int off_bal;
  char temp_name[12];
  char expanded_name[12];
  expanded_name[11] = '\0';

  for(i = 0; i < 16; i++)
  {
    strncpy(temp_name, dir[i].DIR_Name, 12);
    temp_name[11] = '\0';
    if(strcmp(expanded_name, temp_name) == 0)
    {
      detected = dir[i].DIR_FirstClusterLow;
    }
  }
  if(detected != -1)
  {
    off_bal = OffBal_Sec(detected);
		fseek(fp, off_bal, SEEK_SET);
		
    for(i = 0; i < 16; i++)
		{
			fread(&dir[i],sizeof(struct DirectoryEntry),1,fp);
			memcpy(temp_name,dir[i].DIR_Name,11);
			temp_name[11] = '\0';
		}
  }
  else
  {
    printf("Error: Could not find directory.\n");
  }
}


void read(char *input)
{ 
	int i, place, byte_size;
  int detected = -1;
  int size_file = -1;
  char temp_name[12];
  char expanded_name[12]; 
	expanded_name[11] = '\0';
  int dir_cluster, off_bal;
			
	//int place = atoi(token[2]);
	//int byte_size = atoi(token[3]);

    for(i = 0; i < 16; i++)
		{
			strncpy(temp_name, dir[i].DIR_Name,12);
			temp_name[11] = '\0';
			if(strcmp(expanded_name, temp_name) == 0)
			{
				detected = dir[i].DIR_FirstClusterLow;
				size_file = byte_size;
			}
		}
			
		char buffer[512];
		off_bal = OffBal_Sec(detected) + place;
    dir_cluster = detected;
		//strncpy(temp_name, token[1],12);
		of = fopen(temp_name, "w");
		size_file = size_file - 512;
			
		while(size_file > 512)
		{
			fseek(fp, off_bal, SEEK_SET);
			fread(&buffer[0],1,512,fp);
				
			int j;
				
			for(j = 0; j < 512; j++)
			{
				printf(" %x ",buffer[j]);
			}
				size_file = size_file - 512;
				dir_cluster = Next_Sec(dir_cluster);
				off_bal = OffBal_Sec(dir_cluster);
				
		}
		if(size_file > 0)
		{
      int k; 
			fseek(fp, off_bal, SEEK_SET);
			fread(&buffer[0], size_file, 1, fp);
			for(k = 0; k < size_file; k++)
			{
				printf("%x ", buffer[k]);
      }
		}
		
    fclose(of);
			
	}


int main()
{

  char *cmd_str = (char *)malloc(MAX_COMMAND_SIZE);

  while (1)
  {
    // Print out the mfs prompt
    printf("mfs> ");

    // Read the command from the commandline.  The
    // maximum command that will be read is MAX_COMMAND_SIZE
    // This while command will wait here until the user
    // inputs something since fgets returns NULL when there
    // is no input
    while (!fgets(cmd_str, MAX_COMMAND_SIZE, stdin))
      ;

    /* Parse input */
    char *token[MAX_NUM_ARGUMENTS];

    int token_count = 0;

    // Pointer to point to the token
    // parsed by strsep
    char *arg_ptr;

    char *working_str = strdup(cmd_str);

    // we are going to move the working_str pointer so
    // keep track of its original value so we can deallocate
    // the correct amount at the end
    char *working_root = working_str;

    // Tokenize the input stringswith whitespace used as the delimiter
    while (((arg_ptr = strsep(&working_str, WHITESPACE)) != NULL) &&
           (token_count < MAX_NUM_ARGUMENTS))
    {
      token[token_count] = strndup(arg_ptr, MAX_COMMAND_SIZE);
      if (strlen(token[token_count]) == 0)
      {
        token[token_count] = NULL;
      }
      token_count++;
    }
    if (token[0] != NULL)
    {
      if (!strcmp(token[0], "open"))
      {
        if (if_open == 1)
        {
          printf("Error: File system image already open.\n");
        }

        else if (token[1] == NULL)
        {
          if (close_f == 1)
          {
            printf("Error: File system image must be opened first.\n");
            continue;
          }

          printf("Specify a file to open.\n\n");
        }

        else
        {
          open_file(token[1]);
          continue;
        }
      }

      if (!strcmp(token[0], "close"))
      {
        close_Image();
        continue;
      }

      if (!strcmp(token[0], "ls"))
      {
        ls_code();
      }
      if (!strcmp(token[0], "info"))
      {
        if (fp != NULL)
        {
          Print_Info();
        }
        else
        {
          printf("Error: File system must be opened first.\n");
        }
      }

      if (!strcmp(token[0], "stat"))
      {
        if (fp != NULL)
        {
          Print_stat(token[1]);
        }
        else
        {
          printf("Error: File system must be opened first.\n");
        }
      }
      if (!strcmp(token[0], "cd"))
      {
        cd(token[1]);
      }
      if (!strcmp(token[0], "get"))
      {
        get_file(token[1]);
      }
      if (!strcmp(token[0], "read"))
      {
        read(token[1]);
      }
    }
    free(working_root);
  }

  return 0;
}
