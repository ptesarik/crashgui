#ifndef MEMTYPES_H
#define MEMTYPES_H

typedef enum object_size
{
    BYTE_OBJECTS,
    WORD_OBJECTS,
    DWORD_OBJECTS,
    QWORD_OBJECTS
}OBJECT_SIZE;

typedef enum object_endianity
{
    LITTLE_ENDIAN_OBJECTS,
    BIG_ENDIAN_OBJECTS
}OBJECT_ENDIANITY;

typedef enum mem_type
{
    KVADDR,
    UVADDR,
    PHYSADDR,
    XENMACHADDR,
    FILEADDR
}MEM_TYPE;

#endif // MEMTYPES_H
