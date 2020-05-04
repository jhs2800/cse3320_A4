
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

#define WHITESPACE " \t\n" // We want to split our command line up into tokens \
                           // so we need to define what delimits our tokens.   \
                           // In this case  white space                        \
                           // will separate the tokens on our command line

#define MAX_COMMAND_SIZE 255 // The maximum command-line size
FILE *fp;

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

void Print_Info()
{

  printf("BPB_BytesPerSec: %d\n", BPB_BytesPerSec);
  printf("BPB_BytesPerSec: %x\n", BPB_BytesPerSec);

  printf("BPB_SecPerClus: %d\n", BPB_SecPerClus);
  printf("BPB_SecPerClus: %x\n", BPB_SecPerClus);

  printf("BPB_RsvdSecCnt: %d\n", BPB_RsvdSecCnt);
  printf("BPB_RsvdSecCnt: %x\n", BPB_RsvdSecCnt);

  printf("BPB_FATSz32: %d\n", BPB_FATSz32);
  printf("BPB_FATSz32: %x\n", BPB_FATSz32);

  printf("BPB_NumFATs: %d\n", BPB_NumFATs);
  printf("BPB_NumFATs: %x\n", BPB_NumFATs);
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

      Info();
    }
  }
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
        //continue;
      }
    }
    free(working_root);
  }

  return 0;
}
