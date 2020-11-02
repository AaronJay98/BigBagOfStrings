#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <zconf.h>
#include <netinet/in.h>
#include <memory.h>
#include "bigbag.h"

struct bigbag_entry_s *entry_addr(void *hdr, uint32_t offset) {
    if (offset == 0) return NULL;
    return (struct bigbag_entry_s *)((char*)hdr + offset);
}

uint32_t entry_offset(void *hdr, void *entry) {
    return (uint32_t)((uint64_t)entry - (uint64_t)hdr);
}

int main(int argc, char **argv) {
    FILE *readFile;
    char fileName[20];
    int fd;
    void *file_base;
    struct bigbag_hdr_s *hdr;
    struct bigbag_entry_s* curEntry;
    struct bigbag_entry_s* newEntry;
    struct bigbag_entry_s* getEntry;
    struct bigbag_entry_s* prevEntry;
    struct bigbag_entry_s* prevEntry2;
    struct bigbag_entry_s* memEntry;
    int memEntryOffset;
    int prevEntryOffset;
    int prevEntryOffset2;
    int beforeBestOffset;
    int getEntryOffset;
    char* inputBuffer = NULL;
    int freeSpace;
    int inputSize;
    size_t bufSize = 0;
    size_t characters;


    if(argc < 2 || argc > 3) {
        printf("USAGE: ./bigbag [-t] filename\n");
        return 1;
    }


    if(argc == 2)
        fd = open(argv[1], O_RDWR | O_CREAT , S_IRUSR | S_IWUSR);
    else
        fd = open(argv[2], O_RDWR | O_CREAT , S_IRUSR | S_IWUSR);



    struct stat stat;
    fstat(fd, &stat);
 // printf("size = %ld\n", stat.st_size);

    //If a new file create the file and make it 64KB and add header and initialize the free space entry
    if(stat.st_size == 0) {
        ftruncate(fd, BIGBAG_SIZE);
        file_base = mmap(0, BIGBAG_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        hdr = file_base;
        hdr->magic = htonl(0xC149BA9);
        hdr->first_free = 0xC; //not sure C = 12
        hdr->first_element = 0x0;
        newEntry = entry_addr(hdr, 12);
        newEntry->entry_magic = BIGBAG_FREE_ENTRY_MAGIC;
        newEntry->entry_len = BIGBAG_SIZE - sizeof(*newEntry) - 12;
        newEntry->str[0] = 'a';
        newEntry->str[1] = 'g';
        newEntry->next = 0;
    }
    else {
        file_base = mmap(0, BIGBAG_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        hdr = file_base;
    }

    characters = getline(&inputBuffer, &bufSize, stdin);

    while(inputBuffer[0] != 'x') {
        if(inputBuffer[0] == 'a' && inputBuffer[1] == ' ') {
            inputSize = characters - 2;

            //TODO add entries and adjust memory

            //check to see if memory can fit, if not go to next
            if(hdr->first_free != 0) {
                getEntryOffset = hdr->first_free;
                int bestFit = -1;
                int bestFitOffset = getEntryOffset;
                prevEntry = NULL;
                prevEntryOffset = -1;
                beforeBestOffset = 0;

                while(getEntryOffset != 0) {
                    getEntry = entry_addr(hdr, getEntryOffset);

                    if(getEntry->entry_len >= inputSize) {
                        if(bestFit < 0) {
                            bestFit = getEntry->entry_len - inputSize;
                            bestFitOffset = getEntryOffset;
                            beforeBestOffset = prevEntryOffset;
                        }
                        else if((getEntry->entry_len - inputSize) < bestFit) {
                            bestFit = getEntry->entry_len - inputSize;
                            bestFitOffset = getEntryOffset;
                            beforeBestOffset = prevEntryOffset;
                        }
                    }

                    prevEntry = getEntry;
                    prevEntryOffset = getEntryOffset;
                    getEntryOffset = getEntry->next;
                }

                freeSpace = bestFitOffset;
                if(beforeBestOffset != -1) {
                    prevEntry = entry_addr(hdr, beforeBestOffset);
                }
            }
            else {
                //error has occured
            }

            //go to current free space
            curEntry = entry_addr(hdr, freeSpace);

            //add the new free space
            if((curEntry->entry_len - inputSize) > 8) {                                           //NOT TESTED IF STATEMENT
                newEntry = entry_addr(hdr, freeSpace + sizeof(*newEntry) + inputSize);
                newEntry->entry_magic = BIGBAG_FREE_ENTRY_MAGIC;
                newEntry->next = curEntry->next;
                newEntry->str[0] = curEntry->str[0]; //not sure if necessary
                newEntry->entry_len = curEntry->entry_len - sizeof(*newEntry) - inputSize;
                curEntry->entry_len = inputSize;                                                    //Not Tested either put back after in curEntry->entry_magic if error
                if(beforeBestOffset != -1)
                    prevEntry->next = freeSpace + sizeof(*newEntry) + inputSize;
                else
                    hdr->first_free = freeSpace + sizeof(*newEntry) + inputSize;
            }
            else
                if(beforeBestOffset != -1)
                    prevEntry->next = curEntry->next;
                else
                    hdr->first_free = curEntry->next;

            //change the previous free space header to be allocated
            curEntry->entry_magic = BIGBAG_USED_ENTRY_MAGIC;

            int charPoint = 2;
            int charOffset = 0;
            char curChar = inputBuffer[charPoint];
            while(curChar != '\n') {
                curEntry->str[charOffset] = curChar;
                charPoint++;
                charOffset++;
                curChar = inputBuffer[charPoint];
            }
            curEntry->str[charOffset] = NULL;

                //puts this entry in the correct spot in sorted list
            if(hdr->first_element != 0) {
                getEntryOffset = hdr->first_element;
                prevEntry = NULL;
                while(getEntryOffset != 0) {
                    getEntry = entry_addr(hdr, getEntryOffset);
                    int cmpOut = strcmp(getEntry->str, curEntry->str);

                    if (cmpOut < 0) {
                        //keep going
                    }
                    else if (cmpOut > 0) {
                        //stop and put get after current cmpout: 1
                        curEntry->next = getEntryOffset;
                        if (prevEntry == NULL)
                            hdr->first_element = freeSpace;
                        else
                            prevEntry->next = freeSpace;

                        break;
                    }
                    else {
                        curEntry->next = getEntry->next;
                        getEntry->next = freeSpace;
                        break;
                    }
                    prevEntry = getEntry;
                    getEntryOffset = getEntry->next;
                }

                if(getEntryOffset == 0) {
                    curEntry->next = 0;
                    prevEntry->next = freeSpace;
                }
            }
            else {
                hdr->first_element = freeSpace;
                curEntry->next = 0;
            }

            //readjust big bag header
            hdr->first_free = freeSpace + sizeof(*newEntry) + inputSize; //offset of new first free

            printf("added %s\n", curEntry->str);
        }
        else if(inputBuffer[0] == 'd' && inputBuffer[1] == ' ') {
            printf("You want to delete stuff\n");
            //TODO find and delete entry and then combine free memory if possible
            int posNextSpace = 0;
            int posLastSpace = 0;
            getEntryOffset = hdr->first_element;
            prevEntry = NULL;
            int found = 1;

            while(getEntryOffset != 0) {
                getEntry = entry_addr(hdr, getEntryOffset);
                int offset = 0;

                while(getEntry->str[offset] != NULL) {
                    if(getEntry->str[offset] != inputBuffer[offset + 2]) {
                        found = 0;
                        break;
                    }
                    offset++;
                }

                if(found == 1) {
                    //TODO delete it
                    memEntryOffset = hdr->first_free;
                    memEntry = entry_addr(hdr, memEntryOffset);

                    if(prevEntry == NULL) {
                        hdr->first_element = getEntry->next;
                    }
                    else {
                        prevEntry->next = getEntry->next;
                    }

                    getEntry->entry_magic = BIGBAG_FREE_ENTRY_MAGIC;
                    posNextSpace = getEntryOffset + sizeof(*getEntry) + getEntry->entry_len;

                    int combined = 0;
                    while(memEntryOffset != 0) {
                        memEntry = entry_addr(hdr, memEntryOffset);

                        if((memEntryOffset + sizeof(*memEntry) + memEntry->entry_len) == getEntryOffset) {
                            memEntry->entry_len += sizeof(*getEntry) + getEntry->entry_len;
                            combined = 1;
                            getEntryOffset = memEntryOffset;
                            getEntry = memEntry;
                            continue;
                        }
                        if(memEntryOffset == posNextSpace) {
                            if(memEntryOffset == hdr->first_free) {
                                hdr->first_free = getEntryOffset;
                            }
                            getEntry->entry_len += sizeof(*memEntry) + memEntry->entry_len;
                            getEntry->next = memEntry->next;
                            combined = 1;
                        }



                        memEntryOffset = memEntry->next;
                    }

                    if(combined == 0) { //if none combined
                        memEntryOffset = hdr->first_free;
                        memEntry = entry_addr(hdr, memEntryOffset);
                        prevEntry2 = NULL;
                        prevEntryOffset2 = -1;

                        while(memEntryOffset != 0) {
                            memEntry = entry_addr(hdr, memEntryOffset);

                            if(memEntryOffset > getEntryOffset) {
                                if(prevEntryOffset2 < 0) {
                                    hdr->first_free = getEntryOffset;
                                    getEntry->next = memEntryOffset;
                                }
                                else {
                                    getEntry->next = prevEntry2->next;
                                    prevEntry2->next = getEntryOffset;
                                }
                                break;
                            }

                            prevEntry2 = memEntry;
                            prevEntryOffset2 = memEntryOffset;
                            memEntryOffset = memEntry->next;
                        }

                    }

                    break;
                }
                else
                    found = 1;

                prevEntry = getEntry;
                getEntryOffset = getEntry->next;
            }

            if(getEntryOffset == 0) {
                printf("Entry Not Found\n");
            }
        }
        else if(inputBuffer[0] == 'c' && inputBuffer[1] == ' ') {
            getEntryOffset = hdr->first_element;
            int found = 1;
            while(getEntryOffset != 0) {
                getEntry = entry_addr(hdr, getEntryOffset);
                int offset = 0;

                while(getEntry->str[offset] != NULL) {
                    if(getEntry->str[offset] != inputBuffer[offset + 2]) {
                        found = 0;
                        break;
                    }
                    offset++;
                }

                if(found == 1) {
                    printf("Found\n");
                    break;
                }
                else
                    found = 1;

                getEntryOffset = getEntry->next;
            }

            if(getEntryOffset == 0) {
                printf("Not Found\n");
            }
        }
        else if(inputBuffer[0] == 'l') {
            getEntryOffset = hdr->first_element;

            while(getEntryOffset != 0) {
                getEntry = entry_addr(hdr, getEntryOffset);

                printf("%s\n", getEntry->str);

                getEntryOffset = getEntry->next;
            }
        }
        else {
            printf("%c not used correctly\n", inputBuffer[0]);
            printf("possible commands:\n");
            printf("a string_to_add\n");
            printf("d string_to_delete\n");
            printf("c string_to_check\n");
            printf("l\n");
        }

        characters = getline(&inputBuffer, &bufSize, stdin);
    }

    free(inputBuffer);


    //THE REST IF FOR DEBUGGING PURPOSES

    fstat(fd, &stat);
    printf("size = %ld\n", stat.st_size);
    printf("magic = %08x\n", htonl(hdr->magic));
    printf("first_free = %d\n", hdr->first_free);
    printf("first_element = %d\n", hdr->first_element);
    struct bigbag_entry_s *entry;
    int offset = sizeof(*hdr);
    while (offset + sizeof(*entry) < stat.st_size) {
        entry = entry_addr(hdr, offset);
        if (entry == NULL) {
            printf("bad entry at offset %d\n", offset);
            break;
        }
        printf("----------------\n");
        printf("entry offset: %d\n", offset);
        printf("entry magic: %x\n", (int)entry->entry_magic);
        printf("entry len: %d\n", entry->entry_len);
        printf("entry next offset: %d\n", entry->next);
        if (entry->entry_magic == BIGBAG_USED_ENTRY_MAGIC) {
            printf("entry data: %s\n", entry->str);
        }
        offset += sizeof(*entry) + entry->entry_len;
    }
    //TEST if can read


    return 0;
}
