#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "disk.h"
#include "fs.h"

int opened_files_count;
int check;
typedef struct superblock_struct superblock_t;
typedef struct FAT_struct fat_t;
typedef struct file_struct file_t;
typedef struct rootdir_struct rootdir_t;
typedef struct filedesc_struct filedesc_t;

struct __attribute__((packed)) superblock_struct
{
	char sign[8];
	uint16_t disk_num_blocks;
	uint16_t rootdir_index;
	uint16_t data_index;
	uint16_t datablock_count;
	uint8_t fatblock_count;
	uint8_t padding[4079];
};

struct __attribute__((packed)) FAT_struct
{
	uint16_t *entries;
	int entry_count;
};

struct __attribute__((packed)) file_struct
{
	char filename[16];
	uint32_t filesize;
	uint16_t filestruct_index;
	uint8_t padding[10];
};

struct __attribute__((packed)) rootdir_struct
{
	file_t *file_list;
	int num_files;
};

struct filedesc_struct
{
	char filename[16];
	size_t offset;
};

rootdir_t rootdirectory;
superblock_t *SUPER = NULL;
filedesc_t *filedescriptor = NULL;
fat_t FAT;
bool mounting = false;

//
/*
int checker(int check){
	if check == 1{
		return -1;
	}
	return 0;
}*/

int fs_mount(const char *diskname)
{
	check = block_disk_open(diskname);
	if (check == -1)
	{
		return -1;
	}
	SUPER = (superblock_t *)malloc(sizeof(struct superblock_struct));
	check = block_read(0, SUPER);
	if (check == -1)
	{
		return -1;
	}
	check = strncmp(SUPER->sign, "ECS150FS", 8) != 0;
	if (check == -1)
	{
		return -1;
	}
	check = block_disk_count() != SUPER->disk_num_blocks;
	if (check == -1)
	{
		return -1;
	}
	FAT.entries = malloc(SUPER->fatblock_count * 4096);
	int indice = 0;
	for (int i = 1; i <= SUPER->fatblock_count; i++)
	{
		if (block_read(i, &FAT.entries[indice]) == -1)
		{
			return -1;
		}
		if (i == 1)
		{
			if (FAT.entries[0] != 65535)
			{
				return -1;
			}
		}
		indice += 2048;
	}
	FAT.entry_count = 0;
	for (int i = 0; i <= SUPER->datablock_count; i++)
	{
		if (FAT.entries[i])
		{
			FAT.entry_count++;
		}
	}
	rootdirectory.file_list = malloc(128 * sizeof(file_t));
	check = block_read(SUPER->rootdir_index, rootdirectory.file_list);
	if (check == -1)
	{
		return -1;
	}
	rootdirectory.num_files = 0;
	for (int i = 0; i < 128; i++)
	{
		if (rootdirectory.file_list[i].filename[0] != 0)
			rootdirectory.num_files++;
	}
	opened_files_count = 0;
	filedescriptor = (filedesc_t *)malloc(sizeof(filedesc_t) * 32);
	mounting = true;
	return 0;
}

int fs_umount(void)
{
	int indice = 0;
	if (!mounting)
	{
		return -1;
	}
	for (int i = 0; i < 32; i++)
		if (strlen(filedescriptor[i].filename) > 0)
		{
			return -1;
		}

	if (block_write(SUPER->rootdir_index, rootdirectory.file_list) == -1)
	{
		return -1;
	}

	for (int i = 1; i <= SUPER->fatblock_count; i++)
	{
		if (block_write(i, &FAT.entries[indice]) == -1)
		{
			return -1;
		}
		else
		{
			indice += 2048;
		}
	}
	free(filedescriptor);
	free(rootdirectory.file_list);
	free(FAT.entries);
	free(SUPER);
	rootdirectory.num_files = 0;
	FAT.entry_count = 0;

	if (block_disk_close() == -1)
	{
		return -1;
	}
	mounting = false;
	return 0;
}

int fs_info(void)
{
	if (!mounting)
	{
		return -1;
	}
	int ratioH = SUPER->datablock_count - FAT.entry_count;
	printf("FS Info:\n");
	printf("total_blk_count=%d\n", SUPER->disk_num_blocks);
	printf("fat_blk_count=%d\n", SUPER->fatblock_count);
	printf("rdir_blk=%d\n", SUPER->rootdir_index);
	printf("data_blk=%d\n", SUPER->data_index);
	printf("data_blk_count=%d\n", SUPER->datablock_count);
	printf("fat_free_ratio=%d/%d\n", ratioH, SUPER->datablock_count);
	printf("rdir_free_ratio=%d/128\n", 128 - rootdirectory.num_files);
	return 0;
}

int fs_create(const char *filename)
{
	if (!mounting)
	{
		return -1;
	}
	if (*(filename + strlen(filename)) != '\0')
	{
		return -1;
	}
	if (strlen(filename) >= 16)
	{
		return -1;
	}
	if (rootdirectory.num_files == 128)
	{
		return -1;
	}
	for (int i = 0; i < 128; i++)
	{
		if (strncmp(filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			return -1;
		}
		if (rootdirectory.file_list[i].filename[0] == 0)
		{
			memcpy(rootdirectory.file_list[i].filename, filename, 16);
			rootdirectory.file_list[i].filestruct_index = 65535;
			rootdirectory.file_list[i].filesize = 0;
			rootdirectory.num_files++;
			break;
		}
	}
	return 0;
}

int fs_delete(const char *filename)
{
	if (!mounting)
	{
		return -1;
	}
	if (*(filename + strlen(filename)) != '\0')
	{
		return -1;
	}
	if (strlen(filename) >= 16)
	{
		return -1;
	}
	if (rootdirectory.num_files == 0)
	{
		return -1;
	}

	file_t *file_to_kill = NULL;
	for (int i = 0; i < 128; i++)
	{
		if (strncmp(filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			for (int i = 0; i < 32; i++)
			{
				if (strncmp(filedescriptor[i].filename, filename, 16) == 0)
				{
					return -1;
				}
			}
			file_to_kill = &rootdirectory.file_list[i];
		}
	}
	if (!file_to_kill)
	{
		return -1;
	}
	if (FAT.entries[file_to_kill->filestruct_index] != 65535)
	{
		FAT.entry_count--;
		int current_entry = file_to_kill->filestruct_index;
		while (FAT.entries[current_entry] != 65535)
		{
			FAT.entries[current_entry] = 0;
			FAT.entry_count--;
			current_entry = FAT.entries[current_entry];
		}
		FAT.entries[current_entry] = 0;
	}
	memset(file_to_kill, 0, sizeof(file_t));
	rootdirectory.num_files--;
	return 0;
}

int fs_ls(void)
{
	if (!mounting)
	{
		return -1;
	}
	printf("FS Ls:\n");
	for (int i = 0; i < 128; i++)
	{
		if (rootdirectory.file_list[i].filename[0] != 0)
		{
			printf("file: %s, ", rootdirectory.file_list[i].filename);
			printf("size: %d, ", rootdirectory.file_list[i].filesize);
			printf("data_blk: %d\n", rootdirectory.file_list[i].filestruct_index);
		}
	}
	return 0;
}

int fs_open(const char *filename)
{
	if (!mounting)
	{
		return -1;
	}
	if (*(filename + strlen(filename)) != '\0')
	{
		return -1;
	}
	if (strlen(filename) >= 16)
	{
		return -1;
	}
	if (opened_files_count == 32)
	{
		return -1;
	}

	for (int i = 0; i < 128; i++)
	{
		if (strncmp(filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			for (int i = 0; i < 32; i++)
			{
				if (strlen(filedescriptor[i].filename) == 0)
				{
					strncpy(filedescriptor[i].filename, filename, 16);
					opened_files_count++;
					return i;
				}
			}
		}
	}
	return -1;
}

int fs_close(int fd)
{
	if (!mounting)
	{
		return -1;
	}
	if (fd < 0 || fd >= 32)
	{
		return -1;
	}
	if (strlen(filedescriptor[fd].filename) == 0)
	{
		return -1;
	}
	filedescriptor[fd].offset = 0;
	filedescriptor[fd].filename[0] = 0;
	opened_files_count--;
	return 0;
}

int fs_stat(int fd)
{
	if (!mounting)
	{
		return -1;
	}
	if (fd < 0 || fd >= 32)
	{
		return -1;
	}
	if (strlen(filedescriptor[fd].filename) == 0)
	{
		return -1;
	}
	for (int i = 0; i < 128; i++)
	{
		if (strncmp(filedescriptor[fd].filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			return rootdirectory.file_list[i].filesize;
		}
	}
	return -1;
}

//

int fs_lseek(int fd, size_t offset)
{
	if (!mounting)
	{
		return -1;
	}
	if (fd < 0 || fd >= 32)
	{
		return -1;
	}
	if (strlen(filedescriptor[fd].filename) == 0)
	{
		return -1;
	}
	for (int i = 0; i < 128; i++)
	{
		if (strncmp(filedescriptor[fd].filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			if (offset <= rootdirectory.file_list[i].filesize)
			{
				filedescriptor[fd].offset = offset;
				return 0;
			}
		}
		else
		{
			return -1;
		}
	}
	return -1;
}

int fs_write(int fd, void *buf, size_t count)
{
	if (!mounting)
	{
		return -1;
	}
	if (fd < 0 || fd >= 32)
	{
		return -1;
	}
	if (buf == NULL)
	{
		return -1;
	}

	int indice = -1;
	int i = 0;
	while (indice == -1 && i < 128)
	{
		if (strncmp(filedescriptor[fd].filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			indice = i;
		}
		i++;
	}
	if (indice == -1)
	{
		return -1;
	}

	int blocks_needed = (count + filedescriptor[fd].offset) / 4096 - (fs_stat(fd) / 4096);

	if (blocks_needed)
	{
		int oldindex = rootdirectory.file_list[indice].filestruct_index;
		uint16_t *empty[blocks_needed];
		int writeto[blocks_needed];
		if (rootdirectory.file_list[indice].filestruct_index != 65535)
		{
			rootdirectory.file_list[indice].filestruct_index = FAT.entries[rootdirectory.file_list[indice].filestruct_index];
		}

		int num = 0;
		int i = 0;
		while (num < blocks_needed && i < SUPER->datablock_count)
		{
			if (FAT.entries[i] == 0)
			{
				writeto[num] = i;
				empty[num] = &FAT.entries[i];
				num++;
			}
			i++;
		}
		*(empty[blocks_needed - 1]) = 65535;
		i = 0;
		while (i < blocks_needed - 1)
		{
			*(empty[i]) = writeto[i + 1];
			i++;
		}
		if (oldindex != 65535)
		{
			FAT.entries[oldindex] = writeto[0];
		}
		else
		{
			rootdirectory.file_list[indice].filestruct_index = writeto[0];
		}
		FAT.entry_count += blocks_needed;
	}
	if (rootdirectory.file_list[indice].filesize < count + filedescriptor[fd].offset)
	{
		rootdirectory.file_list[indice].filesize = count + filedescriptor[fd].offset;
	}

	size_t bytes = 0;
	size_t offset = filedescriptor[fd].offset;
	char *bufferblock = malloc(4096);

	uint16_t file_index = rootdirectory.file_list[indice].filestruct_index;
	while (file_index != 65535 && count != 0)
	{
		if (4096 < offset)
		{
			offset -= 4096;
		}
		else
		{
			int spacer = 4096 - offset;

			if (block_read(SUPER->data_index + file_index, bufferblock) == -1)
			{
				return -1;
			}
			bufferblock += offset;

			if ((int)count < (int)spacer)
			{
				bytes += count;
				count = 0;
				memcpy(bufferblock, (char *)buf, count);
				filedescriptor[fd].offset += count;
			}
			else
			{
				count -= spacer;
				bytes += spacer;
				memcpy(bufferblock, (char *)buf, spacer);
				filedescriptor[fd].offset += spacer;
			}
			buf += spacer;
			offset = 0;
			free(bufferblock);
			char *bufferblock = malloc(4096);
			if (block_write(SUPER->data_index + file_index, bufferblock) == -1)
			{
				return -1;
			}
		}
		file_index = FAT.entries[file_index];
	}
	free(bufferblock);
	return bytes;
}

int fs_read(int fd, void *buf, size_t count)
{
	if (!mounting)
	{
		return -1;
	}
	if (fd < 0 || fd >= 32)
	{
		return -1;
	}
	if (buf == NULL)
	{
		return -1;
	}

	int indice = -1;
	int i = 0;
	while (indice == -1 && i < 128)
	{
		if (strncmp(filedescriptor[fd].filename, rootdirectory.file_list[i].filename, 16) == 0)
		{
			indice = i;
		}
		i++;
	}
	if (indice == -1)
	{
		return -1;
	}

	if (rootdirectory.file_list[indice].filestruct_index == 65535)
	{
		return 0;
	}

	int bytes = 0;
	size_t offset = filedescriptor[fd].offset;
	uint16_t file_index = rootdirectory.file_list[indice].filestruct_index;
	while (file_index != 65535)
	{
		char *bufferblock = malloc(4096);
		if (offset > 4096)
		{
			offset -= 4096;
		}
		else
		{
			if (block_read(SUPER->data_index + file_index, bufferblock) == -1)
			{
				return -1;
			}
			bufferblock += offset;
			int spacer = 4096 - offset;
			if ((int)count < spacer)
			{
				bytes += count;
				filedescriptor[fd].offset += count;
				memcpy(buf, bufferblock, count);
				return bytes;
			}
			else
			{
				memcpy(buf, bufferblock, 4096 - offset);
				count -= spacer;
				bytes += spacer;
				buf = (char *)buf;
				buf += spacer;
				filedescriptor[fd].offset += spacer;
				offset = 0;
				free(bufferblock);
			}
		}
		file_index = FAT.entries[file_index];
		if (count == 0)
		{
			break;
		}
	}
	return bytes;
}
