/*
This file is part of pfreader.

pfreader free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pfreader is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pfreader.  If not, see <http://www.gnu.org/licenses/>.

Copyright 2014 Richard Alcalde
@RichA0x00

This is released under GPL. If you have any suggestions or comments or if you make improvements to the code; please drop me a line. Also, I cannot guarantee anything! Use this software at your own risk! 

Sometimes, you just have to make something yourself. 
This code was a lesson for myself and a custom tool. But I hope that it will be helpful to you too.
Please see the README.TXT file for more details.  
*/

#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<limits.h> //For File System Info
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <time.h>
#include <dirent.h>


#ifdef MINIGWPATH
#define DWINPATH 1
#define __CYGWIN__ 1
int _CRT_glob = 1;
//int _dowildcard = 1;
#else
#define DWINPATH 0
#endif

#if defined(__solaris__)
#include <inttypes.h>
#else
#include <stdint.h>
#endif


#ifdef OPENSSL_EN
#include <openssl/evp.h>
//#include<math.h>
#endif

#ifdef __CYGWIN__
#define TRUE_CRTIME 1
#define ALT_CRTIME 0
#include <windows.h>
#define STRING_TS_HELP "Using Windows API / Create time is valid."
#else
#define TRUE_CRTIME 0
#ifdef _DARWIN_FEATURE_64_BIT_INODE
#define D_birthtime(x) x.st_birthtime
#define STRING_TS_HELP "Using Mac OSX Birth time."
#define ALT_CRTIME 1
#else
#ifdef HAVE_ST_BIRTHTIME
#define D_birthtime(x) x.st_birthtime
#define ALT_CRTIME 1
#define STRING_TS_HELP "Using BSD Birth time."
#endif
#define birthtime(x) x.st_ctime
#define STRING_TS_HELP "Using POSIX stat function. (No Create time)"
#define ALT_CRTIME 0
#endif
#endif


#define VERSION "Ver A.1C"
//Options
FILE* fp_output;
short int GLOBAL_MACTIME = 0;
short int GLOBAL_FILEREF = 0;
short int GLOBAL_SHOWPATH = 0;
short int GLOBAL_STRINGS = 1;
short int GLOBAL_STD_DISPLAY = 1;
short int GLOBAL_TIMESTAMP = 0;
short int GLOBAL_FILEHASH = 1;
short int GLOBAL_HTML = 0;

char HTML_H1_PRE[255];
char HTML_H1_POST[255];
char HTML_H2_PRE[255];
char HTML_H2_POST[255];
char HTML_PRE_PRE[255];
char HTML_PRE_POST[255];

#define MACTIME_PREFIX "Win PF:" 

#ifndef __CYGWIN__
typedef uint32_t  DWORD;
#endif

typedef struct __FILETIME {
	DWORD dwLow;
	DWORD dwHigh;
} MY_FILETIME;


struct vol_information_xp
{
	DWORD offset_vol_path;
	DWORD length_vol_path;
	MY_FILETIME vol_creation_time;
	uint8_t vol_serial[4];
	DWORD offset_E;
	DWORD length_E;
	DWORD offset_F;
	DWORD count_F;
	DWORD unknown;
};

struct sub_header_xp {
	DWORD offset_A;
	DWORD entries_A;
	DWORD offset_B;
	DWORD entries_B;
	DWORD offset_C;
	DWORD length_C;
	DWORD offset_D;
	DWORD count_D;
	DWORD length_D;
	MY_FILETIME filetime;
	uint8_t unknown[16];
	DWORD exe_counter;
	DWORD unknown2;
};

struct sub_header_win7 {
	DWORD offset_A;
	DWORD entries_A;
	DWORD offset_B;
	DWORD entries_B;
	DWORD offset_C;
	DWORD length_C;
	DWORD offset_D;
	DWORD count_D;
	DWORD length_D;
	uint8_t unknown3[8];
	MY_FILETIME filetime;
	uint8_t unknown[16];
	DWORD exe_counter;
	DWORD unknown2;
};

struct sub_header_win8 {
	DWORD offset_A;
	DWORD entries_A;
	DWORD offset_B;
	DWORD entries_B;
	DWORD offset_C;
	DWORD length_C;
	DWORD offset_D;
	DWORD count_D;
	DWORD length_D;
	uint8_t unknown3[8];
	MY_FILETIME filetime;
	MY_FILETIME older_filetimes[7];
	uint8_t unknown[16];
	DWORD exe_counter;
	DWORD unknown2;
};


struct header_struct {
  DWORD version;
  uint8_t signature[4];
  DWORD version_two;
  DWORD file_size;
  uint16_t ustr[30];
  uint8_t hash[4];
  DWORD options;
};

int checkfile(const char *);
uint32_t do_xp_hash(char *);
uint32_t do_vista_hash(char *);
//uint32_t do_win8_hash(char *);
int do_hash(uint8_t, char *, char *, uint32_t );
#ifdef OPENSSL_EN
int hashfile(char *, char *, char *);
#endif
int poormanUnicode(uint16_t *, int, char *);
int printBytes(uint8_t *, int, int);
time_t ft_to_unix(MY_FILETIME);
#ifdef __CYGWIN__
time_t realft_to_unix(FILETIME);
#endif
int ObtainFileTime(char *, time_t *, time_t *, time_t *);
int ObtainFileTime(char *, time_t *, time_t *, time_t *);
int print_at_offset(FILE *, off_t, int);
int strings_at_offset(FILE *, off_t, int, char *, char *);
int dir_offset(FILE *, off_t, int);
int readFileRecord(FILE *, off_t, int,int);
int parseReg(char *, char *);
int parseDir(char *, char *);
void printhelp();


int checkfile(const char *file)
{
	struct stat buf;
	char fullname[PATH_MAX+1];
	char currentdir[PATH_MAX+1];
	if( getcwd(currentdir,PATH_MAX) == NULL)
		{fprintf(stderr,"Failed to get Current Working directory or directory from command line.\n"); exit(1);}

	if(*file != '/' && DWINPATH == 0)
	{
		snprintf(fullname,PATH_MAX,"%s/%s",currentdir,file);
	}
	else
	{
		snprintf(fullname,PATH_MAX,"%s",file);
	}
	if((stat(fullname, &buf)) < 0) return 0;
	else if(S_ISREG(buf.st_mode)) return 1;
	else if(S_ISDIR(buf.st_mode)) return 2;
	
	else return 0;	
}


void setupHTML(short int en)
{
	if(en == 1)
	{
		snprintf(HTML_H1_PRE, 255,"\n<H1>\n");
		snprintf(HTML_H1_POST, 255,"\n</H1>\n");
		snprintf(HTML_H2_PRE, 255,"\n<H2>\n");
		snprintf(HTML_H2_POST, 255,"\n</H2>\n");
		snprintf(HTML_PRE_PRE, 255,"\n<PRE>\n"); 
		snprintf(HTML_PRE_POST, 255,"\n</PRE>\n");			
	}
	else
	{
		snprintf(HTML_H1_PRE, 255,"");
		snprintf(HTML_H1_POST, 255,"");
		snprintf(HTML_H2_PRE, 255,"");
		snprintf(HTML_H2_POST, 255,"");
		snprintf(HTML_PRE_PRE, 255,""); 
		snprintf(HTML_PRE_POST, 255,"");	
	}


}
uint32_t do_xp_hash(char *txt)
{
	int c;
	uint32_t hash = 0;
	for(c=0; c < strlen(txt); c++)
	{
		hash = (  (hash * 37) + txt[c]) % 0x100000000;
		hash = (  (hash * 37) + 0) % 0x100000000;
	}
	hash = (hash * 314159269) % 0x100000000;
	if (hash > 0x80000000)
		hash = 0x100000000 - hash;
	hash = (labs(hash) % 1000000007) % 0x100000000;	
	
	return hash;
}

uint32_t do_vista_hash(char *txt)
{
	int c;
	uint32_t hash = 314159;
	for(c=0; c < strlen(txt); c++)
	{
		hash = (  (hash * 37) + txt[c]) % 0x100000000;
		hash = (  (hash * 37) + 0) % 0x100000000;
	}
	return hash;
}

uint32_t do_win8_hash(char *txt, short int right)
{
	uint32_t hash = 314159;
	uint32_t charvalue = 0;
	int c =0;
	c=0;
	while((c+4) < strlen(txt))
	{
	
		charvalue = txt[c+1];
		charvalue = (charvalue * 37) + 0;
		charvalue = (charvalue * 37) + txt[c+2];
		charvalue = (charvalue * 37) + 0;
		charvalue = (charvalue * 37) + txt[c+3];
		charvalue = (charvalue * 37);
		charvalue  = (0x1A617D0D * txt[c]) + charvalue; //41a
		hash = ( (charvalue - (hash*0x2FE8ED1F)) % 0x100000000 );
		c=c+4;
	}

	while(c < strlen(txt))
	{
		hash = ((((37 * hash) + txt[c])) % 0x100000000);
		hash = ((((37 * hash) + 0)) % 0x100000000);
		c++;
	}
	
	return hash;
}

int do_hash(uint8_t type, char *exe, char *secondary_file, uint32_t knownhash)
{
	uint32_t hash, hash_two, hash_total;
	hash = 0;
	hash_two = 0;
	int c;
	
	if(exe == NULL) return -1;
	
	if(type == 0x11)
	{
		hash = do_xp_hash(exe);
	}
	else if(type == 0x17)
	{
		hash = do_vista_hash(exe);
	}
	else if(type == 0x1a)
	{
		hash = do_win8_hash(exe, 0);
	}
	if(knownhash == hash) { if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Hash Verified:\t\t0x%X\nConfirmed Path:\t\t%s\n", hash, exe); }
	else if (secondary_file != NULL)
	{
		FILE *sp = fopen(secondary_file, "rb");
		char line[2048];
		char *pch;
		char path[2048];
		char command_line[2048];
		int count;
		int FOUND = 0;
		if(!sp)
		{
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Hash verification failed. Couldn't open command line lookup file.\n");
		}
		else
		{
			while ( (fgets(line, sizeof(line), sp) != NULL) && FOUND == 0) 
			{
				line[strcspn(line, "\n")] = '\0';
				if (line[0] == '\0') continue;
				
				pch = strtok (line,"\t|*");
				if (pch != NULL)
				    snprintf (path, sizeof(path), "%s",pch);
				pch = strtok (NULL, "\t|*");
				if (pch != NULL)
				    snprintf (command_line,sizeof(path),"%s",pch);
			
							
				
				count = 0;
				while(count < 5 && FOUND == 0)
				{
					if(count == 0) snprintf(line, sizeof(line), "\"%s\" %s", path, command_line);
					else if(count == 1) snprintf(line, sizeof(line), "\"%s\"%s", path, command_line);
					else if (count == 2) snprintf(line, sizeof(line), "%s %s", path, command_line);
					else if (count == 3) snprintf(line, sizeof(line), "%s  %s", path, command_line);
					else if (count == 4) snprintf(line, sizeof(line), "%s%s", path, command_line);
					else return -1;
					if(type == 0x11)
					{
						hash_two = do_xp_hash(line);
					}
					else if(type == 0x17)
					{
						hash_two = do_vista_hash(line);
					}
					else if(type == 0x1a)
					{
						hash_two = do_win8_hash(line,1);
					}			
					hash_total = (hash + hash_two) % 0x100000000;
					
					if(hash_total == knownhash) 
					{ 
						FOUND = 1;
					}
					printf("Test %s Found %d Hash1 %#X Hash2 %#X Hash T %#X\n", line,FOUND, hash, hash_two, hash_total);
					count++;			
				}
			}	
			if(FOUND == 1)
			{
				if(GLOBAL_STD_DISPLAY) fprintf(fp_output, "Hash verified:%#X\nDevice Path:%s\nPath:%s\nCommand line:%s\n", hash_total, exe,path,command_line);
			}
			else 
			{
				if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Hash verification failed. Attempted to search lookup file but no matches were found.\n");
			}
			fclose(sp);		
		}
	}	
	else
	{
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"The hash verification failed. Possibly because there are extra command line parameters.\n");
	}
	
	return 0;
}



#ifdef OPENSSL_EN
int hashfile(char *thefile, char *hash, char *hashtype)
{
	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	size_t filecount;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;
	md = EVP_get_digestbyname(hashtype);
	if(!md) exit(1);
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	int file;
	if( (file = open(thefile, O_RDONLY)) == -1 ) {return -1;}
	char tempbuffer[1000];
	while( (filecount=read(file,tempbuffer,sizeof(tempbuffer))) == sizeof(tempbuffer) )
	{
		EVP_DigestUpdate(&mdctx, tempbuffer, sizeof(tempbuffer));
	}
	EVP_DigestUpdate(&mdctx, tempbuffer, filecount);
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);
	sprintf(hash,"");
	for(i = 0; i < md_len; i++) sprintf(hash,"%s%02x", hash,md_value[i]);
	strcat(hash,"");
	close(file);
	return 0;
}
#endif 


int poormanUnicode(uint16_t *ustr, int length, char *str_out)
{
	int c = 0;
	while(ustr[c] != 0 && c < length)
	{
		str_out[c] = (char) ustr[c];
		c++;
	}
	str_out[c] = '\0';
}

int printBytes(uint8_t *my_bytes, int length, int direction)
{	int c = 0;
	if(direction == 0) 	
		while(c < length)
		{
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%02X", my_bytes[c]);
			c++;
		}
	else 
	{
		c = length;
		while(c > 0)
		{
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%02X", my_bytes[c-1]);
			c--;
		}
	}
}

char *UTCctime(const time_t *epoch)
{
	struct tm *ptr;
	
	ptr = gmtime(epoch);
	return asctime(ptr);
}

#define TIMECHANGE_CONST 116444736000000000
time_t ft_to_unix(MY_FILETIME ft)
{
	int64_t bigtime;
	bigtime = ft.dwHigh;
	bigtime = bigtime << 32;
	bigtime = bigtime | ft.dwLow;
	return (  (((bigtime - TIMECHANGE_CONST) / 10000000)));
}

#ifdef __CYGWIN__
time_t realft_to_unix(FILETIME ft)
{
	int64_t bigtime;
	bigtime = ft.dwHighDateTime;
	bigtime = bigtime << 32;
	bigtime = bigtime | ft.dwLowDateTime;
	return (  (((bigtime - TIMECHANGE_CONST) / 10000000)));
}

int ObtainFileTime(char *filename, time_t *modify, time_t *access, time_t *create)
{
	int ret;
	if( filename == NULL )
    {
		*modify = 0;
		*access = 0;
		*create = 0;	
        return -1;
    }
	HANDLE hFile;
	
	short loc = 0;
	char *cptr;
	char drive = 0;
	char passed_file [PATH_MAX+1];
	//if( (cptr = strchr(filename, '/' )) != NULL)
	if( filename[0] == '/' )
	{
		if( (strstr(filename, "/cygdrive/")) != NULL)
		{
			drive = filename[10];
			snprintf(passed_file, PATH_MAX, "%c:%s", drive, filename+11);
		}
	}
	else 
	{
		snprintf(passed_file,PATH_MAX,"%s", filename);
	}

	while( (loc = strcspn(passed_file, "/")) <  strlen(passed_file))
		{
			passed_file[loc] = '\\';
		}
	
	
    hFile = CreateFile(passed_file, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE)
    {
		printf("Error: Invalid Handle.\n");
		*modify = 0;
		*access = 0;
		*create = 0;	
	    return -1;
    }
    FILETIME ftCreate, ftAccess, ftWrite;
	
	// Retrieve the file times for the file.
    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
        return -1;
	
	*modify = realft_to_unix(ftWrite);
	*access = realft_to_unix(ftAccess);
	*create = realft_to_unix(ftCreate);
	CloseHandle(hFile);
	
	return 1;
}
#else
int ObtainFileTime(char *file, time_t *modify, time_t *access, time_t *create)
{
	struct stat buf;
	char fullname[PATH_MAX+1];
	char currentdir[PATH_MAX+1];
	if( getcwd(currentdir,PATH_MAX) == NULL)
		{fprintf(stderr,"Failed to get Current Working directory or directory from command line.\n"); return -1;}

	if(*file != '/')
	{
		snprintf(fullname,PATH_MAX,"%s/%s",currentdir,file);
	}
	if((stat(file, &buf)) < 0) 
	{
		*modify = 0;
		*access = 0;
		*create = 0;	
	}
	else
	{
		*modify = buf.st_mtime;
		*access = buf.st_atime;
		if(ALT_CRTIME) *create = D_birthtime(buf);
		else *create = 0;
	}


	return 0;	
}
#endif

int print_at_offset(FILE *fp, off_t offset, int length)
{
	off_t current;
	uint16_t buffer[length];
	int c=0;
	if( (current = ftello( fp )) < 0 ) return -1; //Save Current Position
	if( (fseek( fp , offset, SEEK_SET )) != 0 ) return -1;
	if(!feof(fp)) { fread(&buffer, sizeof(buffer),1, fp); } else return -1;
	
	while(buffer[c] != 0 && c < length)
	{
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%c",buffer[c]);
		c++;
	}
	if( (fseeko( fp , current, SEEK_SET )) != 0 ) return -1;
	return 0;
}

int strings_at_offset(FILE *fp, off_t offset, int length, char *findexe, char *fullexe)
{
	off_t current;
	uint16_t buffer[length+1];
	char c_buffer[length+1];
	char *ptr;
	
	char cleanexe[PATH_MAX+1];
	char *ptrone = findexe;
	char *ptrtwo = cleanexe;
	while( *ptrone != 0) { *ptrtwo = *ptrone; ptrtwo++; ptrone++; }
	*ptrtwo='\0';
	
	int fe_count = strlen(cleanexe);
	int c=0;
	int cc=0;
	if( (current = ftello( fp )) < 0 ) return -1; //Save Current Position
	if( (fseek( fp , offset, SEEK_SET )) != 0 ) return -1;
	if(!feof(fp)) { fread(&buffer, sizeof(uint16_t)*length,1, fp); } else return -1;
	
	int ECHO = 0;
	short int found = 0;
	
	
	while(c <=(length/2))
	{
		if(buffer[c] == '\\' && ECHO == 0) ECHO  = 1;
		if(buffer[c] >= 32 && buffer[c] <= 126 && ECHO == 1) 
		{
			c_buffer[cc] = (char) buffer[c];
			cc++;
		}
		if(buffer[c] == 0) 
			if(ECHO) 
			{ 
				c_buffer[cc] = '\0';
					if ( (strlen(c_buffer) > 0) && ( (ptr = strstr(c_buffer, cleanexe)) != NULL) )
				{
					if(strlen(ptr) == fe_count) snprintf(fullexe, length, "%s", c_buffer);
					found = 1;
				}
				if(GLOBAL_STD_DISPLAY && GLOBAL_STRINGS) fprintf(fp_output,"%s\n", c_buffer); 
				ECHO = 0; 
				cc = 0;
			} 
		c++;
	}
	if(GLOBAL_STD_DISPLAY && GLOBAL_STRINGS) fprintf(fp_output,"\n");
	if( (fseeko( fp , current, SEEK_SET )) != 0 ) return -1;
	if(found == 0) fullexe[0] = '\0';
	return 0;
}

#define BUFFER_MAX 2048
int dir_offset(FILE *fp, off_t offset, int count)
{
	off_t current;
	uint16_t buffer[BUFFER_MAX];
	int c=0;
	int e=0;
	uint16_t length;
	if( (current = ftello( fp )) < 0 ) return -1; //Save Current Position
	if( (fseek( fp , offset, SEEK_SET )) != 0 ) return -1;
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\tDirectory Strings:\n");
	while(e < count)
	{
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\t\t");
		if(!feof(fp)) { fread(&length, sizeof(uint16_t),1, fp); } else return -1;
		length++;
		if(length > BUFFER_MAX) return -1;
		if(!feof(fp)) { fread(&buffer, sizeof(uint16_t)*length,1, fp); } else return -1;
		c=0;
		while( buffer[c] != 0 && c <=length)
		{
			if(buffer[c] >= 33 && buffer[c] <= 126) if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%c", buffer[c]);
			c++;
		}
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\n");
		e++;
	}
	if( (fseeko( fp , current, SEEK_SET )) != 0 ) return -1;	
	return 0;
}



struct _file_ref_xp {
	DWORD unknown;
	DWORD count;
};

typedef uint64_t FILERECORD; 
//Upper Two Bytes = Sequence Lower six bytes MFT Location (-1)

int readFileRecord(FILE *fp, off_t offset, int length, int header)
{
	FILERECORD file_record;
	struct _file_ref_xp file_ref_xp;
	off_t current, current_two, check;
	int c;
	if( (current = ftello( fp )) < 0 ) return -1; //Save Current Position
	if( (fseek( fp , offset, SEEK_SET )) != 0 ) return -1;
	if(header == 0x11 || header==0x17 || header==0x1a)
	{
		if(!feof(fp)) { fread(&file_ref_xp, sizeof(struct _file_ref_xp),1, fp); } else return -1;
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\tFile References: %d\n", file_ref_xp.count);
		c=0; check = 0;
		if( (current_two = ftello( fp )) < 0 ) return -1;
		while( check <= (length) && c < file_ref_xp.count)
		{
			if(!feof(fp)) { fread(&file_record, sizeof(FILERECORD),1, fp); } else return -1;
			if( (check = ftello( fp )) < 0 ) return -1; 
			check = check - current_two;
			if(file_record > 0) if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\t\t%d:MFT Location:0x%014llX\tSequence number:0x%04llX\n", c, file_record & 0x00FFFFFFFFFF, (file_record >> 48));			
			c++;
		}
	}
	if( (fseeko( fp , current, SEEK_SET )) != 0 ) return -1;
	return 0;
}

int parseReg(char *reg_file, char *lookup)
{
	struct header_struct header;
	DWORD offset_A;
	DWORD entries_A;
	DWORD offset_B;
	DWORD entries_B;
	DWORD offset_C;
	DWORD length_C;
	DWORD offset_D;
	DWORD count_D;
	DWORD length_D;

	MY_FILETIME filetime;
	MY_FILETIME older_filetimes[7];
	uint16_t unknown[4];
	DWORD exe_counter;
	off_t current;
	int c;
	char exe_string[60];
	time_t mactime_c = 0;
	time_t mactime_m = 0;
	time_t mactime_a = 0;
	uint32_t stored_hash = 0;
	char *file_ptr;
	char md5_hash_file[256];
	snprintf(md5_hash_file,256,"0");
	char fileshort[PATH_MAX+1];
	FILE *fp = fopen(reg_file, "rb");
	if(!fp) return -1;
	
	if(GLOBAL_STD_DISPLAY && GLOBAL_HTML == 0) fprintf(fp_output,"Windows Prefetch File Reader\t%s\n", VERSION );
	file_ptr = strrchr(reg_file, '/');
	if(file_ptr != NULL) snprintf(fileshort,PATH_MAX,"%s",file_ptr+1);
	else snprintf(fileshort,PATH_MAX,"%s",reg_file);
	
	if(file_ptr == NULL || GLOBAL_SHOWPATH == 1) {if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%sParsing file: %s%s\n", HTML_H1_PRE, reg_file, HTML_H1_POST);}
	else { if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%sParsing file: %s%s\n", HTML_H1_PRE, fileshort, HTML_H1_POST);}
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_PRE);

#ifdef OPENSSL_EN
	char other_hash_file[2048];
	if(GLOBAL_FILEHASH)
	{
		if( hashfile(reg_file, md5_hash_file, "md5") == -1 ) 
		   {
		      snprintf(md5_hash_file,256,"0");
			}
		else if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"MD5:\t%s\n",md5_hash_file );
		if( hashfile(reg_file, other_hash_file, "sha1") == -1 ) 
		    {
		      snprintf(other_hash_file,256,"0");
			}
		else if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"SHA1:\t%s\n\n",other_hash_file );
	}
#endif
	if(!feof(fp)) { fread(&header, sizeof(struct header_struct),1, fp); } else return -1;
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Format: 0x%2X\tOS: ", header.version);
	if(header.version == 0x11) { if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"XP\n"); }
	else if(header.version == 0x17) { if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Win7/Vista\n"); }
	else if(header.version ==  0x1a) { if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Win8+\n"); }
	else { if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Unknown\n"); return -2;}
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Signature: %c%c%c%c\tVerification: ", header.signature[0], header.signature[1], header.signature[2], header.signature[3]);
	if( (header.signature[0] == 0x53) && (header.signature[1] == 0x43) && (header.signature[2] == 0x43) && (header.signature[3] == 0x41)) if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"PASS\n");
	else if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"FAIL\n");
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"File Size: 0x%04X (%d)\n", header.file_size, header.file_size);
	poormanUnicode(header.ustr, 60, exe_string);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Executable File Name: %s\n", exe_string);
	stored_hash = ((uint32_t) (header.hash[3]  << 24) & 0xFF000000) + ((uint32_t)(header.hash[2] << 16) & 0x00FF0000)+ ((uint32_t)(header.hash[1] << 8) & 0x0000FF00) + ((uint32_t)(header.hash[0]) & 0x0000FF); 
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Stored Hash: 0x%X\n",stored_hash);


	if( (fseek ( fp , 0x0054 , SEEK_SET )) != 0 ) return -1;
	if(header.version == 0x11) 
	{
		struct sub_header_xp sub_header;
		if(!feof(fp)) { fread(&sub_header, sizeof(struct sub_header_xp),1, fp); } else return -1;	
		offset_A = sub_header.offset_A;
		entries_A = sub_header.entries_A;
		offset_B = sub_header.offset_B;
		entries_B = sub_header.entries_B;
		offset_C = sub_header.offset_C;
		length_C = sub_header.length_C;
		offset_D = sub_header.offset_D;
		count_D = sub_header.count_D;
		length_D = sub_header.length_D;
		filetime = sub_header.filetime;
		exe_counter  = sub_header.exe_counter;
	}
	else if (header.version == 0x17)
	{
		struct sub_header_win7 sub_header;
		if(!feof(fp)) { fread(&sub_header, sizeof(struct sub_header_win7),1, fp); } else return -1;	
		offset_A = sub_header.offset_A;
		entries_A = sub_header.entries_A;
		offset_B = sub_header.offset_B;
		entries_B = sub_header.entries_B;
		offset_C = sub_header.offset_C;
		length_C = sub_header.length_C;
		offset_D = sub_header.offset_D;
		count_D = sub_header.count_D;
		length_D = sub_header.length_D;
		filetime = sub_header.filetime;
		exe_counter  = sub_header.exe_counter;	
	}
	else if (header.version == 0x1a)
	{
		struct sub_header_win8 sub_header;
		if(!feof(fp)) { fread(&sub_header, sizeof(struct sub_header_win8),1, fp); } else return -1;	
		offset_A = sub_header.offset_A;
		entries_A = sub_header.entries_A;
		offset_B = sub_header.offset_B;
		entries_B = sub_header.entries_B;
		offset_C = sub_header.offset_C;
		length_C = sub_header.length_C;
		offset_D = sub_header.offset_D;
		count_D = sub_header.count_D;
		length_D = sub_header.length_D;
		filetime = sub_header.filetime;
		for(c=0;c<7;c++) older_filetimes[c] = sub_header.older_filetimes[c];
		exe_counter  = sub_header.exe_counter;	
	}
	else return -1;
		
	time_t t_time;
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Section A\tOffset:\t0x%04X\tEntries:0x%04X\n", offset_A, entries_A);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Section B\tOffset:\t0x%04X\tEntries:0x%04X\n", offset_B, entries_B);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"File Strings\tOffset:\t0x%04X\tLength:\t0x%04X\n", offset_C, length_C);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Volume Info\tOffset:\t0x%04X\tLength:\t0x%04X\tCount:\t0x%04X\n", offset_D, length_D, count_D);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Execute Count:\t\t0x%04X (%d)\n", exe_counter, exe_counter);

	t_time = ft_to_unix(filetime);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Last execute time UTC:\t%s", UTCctime(&t_time));
	char full_exe_string[length_C+1];

	if(GLOBAL_TIMESTAMP) {
		ObtainFileTime(reg_file, &mactime_m, &mactime_a, &mactime_c);
	}

	
	
	if(GLOBAL_MACTIME)
	{	
		strings_at_offset(fp, offset_C, length_C, exe_string, full_exe_string); //Get full path
		if(GLOBAL_SHOWPATH) fprintf(fp_output,"%s|[%s %s] %s (Executed Count: %d) [Last known execution.]|0|---a-----------|0|0|0|%u|%u|0|%u\n",md5_hash_file, MACTIME_PREFIX, reg_file, full_exe_string, exe_counter, (unsigned int) t_time, (unsigned int) mactime_m, (unsigned int) mactime_c);
		else fprintf(fp_output,"%s|[%s %s] %s (Executed Count: %d) [Last known execution.]|0|---a-----------|0|0|0|%u|%u|0|%u\n"  ,md5_hash_file, MACTIME_PREFIX, fileshort, full_exe_string, exe_counter, (unsigned int) t_time, (unsigned int) mactime_m, (unsigned int) mactime_c);
	}
	
	if(header.version == 0x1a)
	{
		for(c=0;c<7;c++)
		{
			t_time = ft_to_unix(older_filetimes[c]);
			if(t_time > 0 && c == 0) if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Last execute history:\t%s", UTCctime(&t_time));
			if(t_time > 0 && c !=0) if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\t\t\t%s", UTCctime(&t_time));	
			if(t_time > 0 && GLOBAL_MACTIME) 
			{
				if(GLOBAL_SHOWPATH) fprintf(fp_output,"%s|[%s %s] %s (Executed Count: %d) [Historical]|0|---a-----------|0|0|0|%u|%u|0|%u\n"  ,md5_hash_file, MACTIME_PREFIX, reg_file, full_exe_string, exe_counter, (unsigned int) t_time, (unsigned int) mactime_m, (unsigned int) mactime_c);
				else fprintf(fp_output,"%s|[%s %s] %s (Executed Count: %d) [Historical]|0|---a-----------|0|0|0|%u|%u|0|%u\n"  ,md5_hash_file, MACTIME_PREFIX, fileshort, full_exe_string, exe_counter, (unsigned int) t_time, (unsigned int) mactime_m, (unsigned int) mactime_c);
			}
		}
	}
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_POST);
	if(GLOBAL_STD_DISPLAY && GLOBAL_STRINGS && GLOBAL_HTML) fprintf(fp_output,"\n\n%sFile Strings%s\n", HTML_H2_PRE, HTML_H2_POST);
	if(GLOBAL_STD_DISPLAY && GLOBAL_STRINGS && GLOBAL_HTML == 0) fprintf(fp_output,"\n\nFile Strings\n-----------------------\n");

	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_PRE);
	if(!GLOBAL_MACTIME) strings_at_offset(fp, offset_C, length_C, exe_string, full_exe_string);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_POST);
	
	if(GLOBAL_STD_DISPLAY && GLOBAL_HTML) fprintf(fp_output,"\n\n%sExecutable%s\n", HTML_H2_PRE, HTML_H2_POST);
	if(GLOBAL_STD_DISPLAY && GLOBAL_HTML == 0) fprintf(fp_output,"\n\nExecutable\n-----------------------\n");
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_PRE);
	if(GLOBAL_STD_DISPLAY && full_exe_string != NULL) fprintf(fp_output,"Discovered Executable:\t%s\n", full_exe_string);
	do_hash(header.version, full_exe_string, lookup, stored_hash);
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_POST);
 	
	if(GLOBAL_TIMESTAMP) {
		ObtainFileTime(reg_file, &mactime_m, &mactime_a, &mactime_c);
		if(GLOBAL_STD_DISPLAY && GLOBAL_HTML) fprintf(fp_output,"\n\n%sFile System Timestamps%s\n",HTML_H2_PRE, HTML_H2_POST);
		if(GLOBAL_STD_DISPLAY && GLOBAL_HTML == 0) fprintf(fp_output,"\n\nFile System Timestamps\n-----------------------\n");
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_PRE);
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Last Modified UTC:\t%s", UTCctime(&mactime_m));
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Last Accessed UTC:\t%s", UTCctime(&mactime_a));
		if( (GLOBAL_STD_DISPLAY)  && ( TRUE_CRTIME || ALT_CRTIME)) fprintf(fp_output,"File Created UTC:\t%s", UTCctime(&mactime_c));
		if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_POST);
	}
		
	if( (fseek ( fp , offset_D , SEEK_SET )) != 0 ) return -1;
	
	if(GLOBAL_STD_DISPLAY && GLOBAL_HTML == 1) fprintf(fp_output,"\n\n%sVolume Information%s\n",HTML_H2_PRE, HTML_H2_POST);
	if(GLOBAL_STD_DISPLAY && GLOBAL_HTML == 0) fprintf(fp_output,"\n\nVolume Information\n-----------------------\n");
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_PRE);
	int v_count;
	off_t current_o;
	if(header.version == 0x11 ||  header.version == 0x17 || header.version == 0x1a)
	{
		struct vol_information_xp vol_info_xp;
		//XP
		for(v_count = 0; v_count < count_D; v_count++)
		{
			if(!feof(fp)) { fread(&vol_info_xp, sizeof(struct vol_information_xp),1, fp); } else return -1;
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Details Volume %d\t", v_count);
			if( (print_at_offset(fp, offset_D + vol_info_xp.offset_vol_path, vol_info_xp.length_vol_path)) != 0) return -1;
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\nVolume Serial: "); printBytes(vol_info_xp.vol_serial, 4, 1); if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\n");
			t_time = ft_to_unix(vol_info_xp.vol_creation_time);
			if(t_time > 0) if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"Volume Creation time UTC:\t%s", UTCctime(&t_time));
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\tOffset Volume Path:\t0x%04X\tFile Offset:\t0x%04X\tLength:0x%04X\n\tOffset File References:\t0x%04X\tFile Offset:\t0x%4X\tLength:0x%04X\n\tOffset Dir Strings:\t0x%04X\tFile Offset:\t0x%04X\tCount: 0x%04X\n", vol_info_xp.offset_vol_path,offset_D + vol_info_xp.offset_vol_path, vol_info_xp.length_vol_path, vol_info_xp.offset_E,offset_D + vol_info_xp.offset_E, vol_info_xp.length_E,vol_info_xp.offset_F,offset_D + vol_info_xp.offset_F, vol_info_xp.count_F);  		
			if(GLOBAL_FILEREF) if( (readFileRecord(fp, offset_D + vol_info_xp.offset_E, vol_info_xp.length_E, header.version))	!= 0) return -1;	
			if(GLOBAL_STRINGS) if( (dir_offset(fp, offset_D + vol_info_xp.offset_F, vol_info_xp.count_F)) != 0) return -1;		
			if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"\n");
		}	
	}	
	if(GLOBAL_STD_DISPLAY) fprintf(fp_output,"%s", HTML_PRE_POST);

	fclose(fp);
}


int parseDir(char *dirname, char *lookup)
{
	DIR	*dp; //DIR pointer
	struct dirent *dirp; //Dir struct pointer
	char fullname[PATH_MAX+1];
	if ((dp = opendir(dirname)) == NULL) {
        fprintf(stderr, "Couldn't open: %s\n", dirname);
        return -1;
    }

    do {
        if ((dirp = readdir(dp)) != NULL) 
		{		
            if ( strstr(dirp->d_name, ".pf") != NULL)
			{
				if(DWINPATH == 0) snprintf(fullname,PATH_MAX, "%s%s", dirname,dirp->d_name);
				else snprintf(fullname,PATH_MAX, "%s\\%s", dirname,dirp->d_name);
				if(checkfile(fullname) == 1)
				{
					parseReg(fullname, lookup);
				}
			}

        }
    } while (dirp != NULL);
	closedir(dp);
}


void printhelp()
{
	printf("Windows Prefetch File Reader\t%s\n", VERSION);
	printf("GNU Public License - Copyright 2014 - Richard Alcalde\n\n"); 
	printf("Usage: ./pfreader [OPTIONS] [FILE|DIR]\n");
	if(GLOBAL_FILEREF == 0)	printf("\t-f, --file-ref\t\tShow MFT file references (Experimental)\n");
	else	printf("\t-F, --no-file-ref\tDo not show MFT file references (Experimental)\n");
	if(GLOBAL_STRINGS == 0) printf("\t-s, --strings\t\tShow file and directory string data.\n");
	else printf("\t-S, --no-strings\tDo not show file and directory string data.\n");
#ifdef OPENSSL_EN
	printf("\t-H, --no-hash\t\tDo not compute MD5 and SHA1 file hashes.\n");
#endif
	printf("\t-t, --time-stamp\tObtain time stamps from file system. %s\n",STRING_TS_HELP);
	printf("\t-m, --mactime\t\tOutput basic information in TSK Body format.\n");
	printf("\t-p, --html\t\tAdd HTML code to output for cleaner reporting.\n");
	printf("\t-P, --full-path\t\tShow full path to file in output.\n");
	printf("\t-l, --lookup [FILE]\tProvide a list of path and command line arguments in a delimited [\\t|*] file. (Experimental)\n");
	printf("\t-o, --output [FILE]\tOutput to file.\n");
	printf("\t-h, --help\t\tThis help page.\n");

}//printhelp

//This is used for Get Options
struct option long_options[] =
{
  {"help", no_argument, NULL, 'h'},
  {"file-ref", no_argument, NULL, 'f'},
  {"no-file-ref", no_argument, NULL, 'F'},
  {"no-hash", no_argument, NULL, 'H'},
  {"strings", no_argument, NULL, 's'},
  {"no-strings", no_argument, NULL, 'S'},
  {"time-stamp", no_argument, NULL, 't'},
  {"html", no_argument, NULL, 'p'},
  {"full-path", no_argument, NULL, 'P'},
  {"mactime", no_argument, NULL, 'm'},  
  {"lookup", required_argument, NULL, 'l'}, 
  {"output", required_argument, NULL, 'o'},  
   { 0, 0, 0, 0 }
}; //long options



int main( int argc, char **argv)
{
  char RegFile[PATH_MAX+1];
  char dirFile[PATH_MAX+1];
  int input,option_index,count;
  char outFile[PATH_MAX+1];
  char *lookup = NULL;
  
#ifdef OPENSSL_EN
OpenSSL_add_all_digests();
#endif
  
  while((input = getopt_long(argc, argv, "hfHFstpPSml:o:", long_options, &option_index)) != EOF )
	{
		switch(input) 
		{
			case 'f':
				GLOBAL_FILEREF = 1;
			break;
			case 'F':
				GLOBAL_FILEREF = 0;
			break;
			case 'H':
				GLOBAL_FILEHASH = 0;
			break;
			case 's':
				GLOBAL_STRINGS = 1;
			break;
			case 't':
				GLOBAL_TIMESTAMP = 1;
			break;
			case 'p':
				GLOBAL_HTML = 1;
			break;

			case 'P':
				GLOBAL_SHOWPATH = 1;
			break;
			case 'S':
				GLOBAL_STRINGS = 0;
			break;
			case 'm':
				GLOBAL_MACTIME = 1;
				GLOBAL_STD_DISPLAY = 0; 
			break;
			case 'o':
				strncpy(outFile,optarg,PATH_MAX);
				if(checkfile(outFile) == 1) { fprintf(stderr,"Output file already exists.\n"); return -1;}
				fp_output = fopen(outFile, "wb");
				if(!fp_output) { fprintf(stderr,"Failed to create output file.\n"); return -1; }
			break;
			case 'l':
				lookup = malloc(sizeof(char) * PATH_MAX);
				if(lookup == NULL) {fprintf(stderr,"MALLOC FAIL\n"); return -1; }
				strncpy(lookup,optarg,PATH_MAX);
				if(checkfile(lookup) == 1) { strncpy(lookup,optarg,PATH_MAX);}
				else { fprintf(stderr,"Look up file does not exist."); return -1; }
				
			break;
			
			
			default:
			case '?':
			case 'h':
				printhelp();
			return (0);
			break;
			

		}//switch
		
	}//while
	
	
	if(fp_output == NULL) fp_output = stdout;
	
	setupHTML(GLOBAL_HTML);
	
	argc -= optind; 
	argv += optind;
	int c;
	int good = 0;
	int check;
	if(argc == 0)
	{
		printhelp(); exit(1);
	}
	else 
	{
		for(c=1; c<=argc; c++)
		{
			check = checkfile(argv[c-1]);
			if( check == 1)
			{
				if(good == 0 && GLOBAL_HTML && GLOBAL_STD_DISPLAY) fprintf(fp_output,"<HTML>\n<title>Windows Prefetch File Reader%s</title>\n<body>\n", VERSION );
				good = 1;
				strncpy(RegFile,argv[c-1],PATH_MAX);    
				parseReg(RegFile, lookup);
			}
			else if (check == 2)
			{
				if(good == 0 && GLOBAL_HTML && GLOBAL_STD_DISPLAY) fprintf(fp_output,"<HTML>\n<title>Windows Prefetch File Reader%s</title>\n<body>\n", VERSION );
				good = 1;
				strncpy(dirFile,argv[c-1],PATH_MAX);
				parseDir(dirFile, lookup);
			}
			else { fprintf(stderr,"You must include a valid file.\n"); exit(1); }
		}
		if(good && GLOBAL_HTML && GLOBAL_STD_DISPLAY) fprintf(fp_output,"\n</BODY>\n</HTML>\n\n");
    }
	
  fclose(fp_output);
  
  return 0;
}

