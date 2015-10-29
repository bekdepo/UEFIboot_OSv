/** @file
    A simple, basic, application showing how the Hello application could be
    built using the "Standard C Libraries" from StdLib.

    Copyright (c) 2010 - 2011, Intel Corporation. All rights reserved.<BR>
    This program and the accompanying materials
    are licensed and made available under the terms and conditions of the BSD License
    which accompanies this distribution. The full text of the license may be found at
    http://opensource.org/licenses/bsd-license.

    THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
    WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/
#include  <Uefi.h>
#include  <Library/UefiLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Protocol/LoadedImage.h>

#include  <stdio.h>
#include  <stdint.h>

//#include "elfparse.h"


EFI_SYSTEM_TABLE  *gST;
EFI_BOOT_SERVICES *gBS;

#define PAGE_SIZE 4096

#define ADDR_CMDLINE 0x7e00
#define ADDR_TARGET 0x200000
#define ADDR_MB_INFO 0x1000
#define ADDR_E820DATA 0x1100
#define ADDR_STACK 0x1200

#define ENTRY_ADDR 0x000000000021022e

#define E820_USABLE 1
#define E820_RESERVED 2


struct e820ent {
  uint32_t ent_size;
  uint64_t addr;
  uint64_t size;
  uint32_t type;
} __attribute__((packed));

struct multiboot_info_type {
  uint32_t flags;
  uint32_t mem_lower;
  uint32_t mem_upper;
  uint32_t boot_device;
  uint32_t cmdline;
  uint32_t mods_count;
  uint32_t mods_addr;
  uint32_t syms[4];
  uint32_t mmap_length;
  uint32_t mmap_addr;
  uint32_t drives_length;
  uint32_t drives_addr;
  uint32_t config_table;
  uint32_t boot_loader_name;
  uint32_t apm_table;
  uint32_t vbe_control_info;
  uint32_t vbe_mode_info;
  uint16_t vbe_mode;
  uint16_t vbe_interface_seg;
  uint16_t vbe_interface_off;
  uint16_t vbe_interface_len;
} __attribute__((packed));

typedef int EFIAPI entry_func_t(VOID *, VOID *, VOID *);

void Memmap_to_e820(struct e820ent *e, EFI_MEMORY_DESCRIPTOR *md)
{
  e->ent_size = 20;
  e->addr = md->PhysicalStart;
  e->size = md->NumberOfPages * PAGE_SIZE; // PAGE_SIZE = 4096(4KiB)
  switch (md->Type) {
  case EfiLoaderCode:
  case EfiLoaderData:
  case EfiBootServicesCode:
  case EfiBootServicesData:
  case EfiConventionalMemory:
    if (md->Attribute & EFI_MEMORY_WB) {
      e->type = E820_USABLE;
    }
    else {
      e->type = E820_RESERVED;
    }
    break;
  default:
    e->type = E820_RESERVED;
    break;
  }
}

int
memory_verify(uint8_t *src, uint8_t *dest, int size){
  for (int i = 0; i < size; i++) {
    if (src[i] != dest[i]) {
      return -1;
    }
  }
  return 0;
}

EFI_STATUS EFIAPI loader2(  IN VOID *Kernel,  IN VOID *E820,  IN VOID *CMDLINE  );


VOID *
EFIAPI
LoadFileToMemoryPool(
  IN CHAR16 *Path,
  IN OUT EFI_PHYSICAL_ADDRESS *Buffer,
  IN OUT UINT64 *BufferSize
  )
{
  EFI_STATUS Status;
    // load kernel and cmdline
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFile;
  EFI_FILE_PROTOCOL                *Root;
  EFI_FILE_PROTOCOL                *File;

  Status = gBS->LocateProtocol (
        &gEfiSimpleFileSystemProtocolGuid,
        NULL,
        (VOID **)&SimpleFile
        );
  if (EFI_ERROR (Status)) {
    Print(L"%r on Locate EFI Simple File System Protocol.\n", Status);
    return NULL;
  }

  Status = SimpleFile->OpenVolume(SimpleFile, &Root);
  if (EFI_ERROR (Status)) {
    Print(L"%r on Open volume.\n", Status);
    return NULL;
  }

  Status = Root->Open(Root, &File, Path, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
  if (EFI_ERROR (Status)) {
    Print(L"%r on Open file.\n", Status);
    Print(L"Path: %s\n", Path);
    return NULL;
  }

  // get file info
  EFI_FILE_INFO *FileInfo;
  UINTN FileInfoSize = sizeof(EFI_FILE_INFO) * 2;
  Status = gBS->AllocatePool(
           EfiLoaderCode,
           FileInfoSize,
           (VOID **)&FileInfo
           );
  if (EFI_ERROR (Status)) {
    Print(L"%Could not allocate memory pool %r\n", Status);
    return NULL;
  }
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
  if (EFI_ERROR (Status)) {
    Print(L"%Could not get FileInfo: %r\n", Status);
    return NULL;
  }

  // get file size
  *BufferSize = FileInfo->FileSize;
  //Print(L"FileSize = %d\n", BufferSize);
  
  // allocate FileBuffer
  Status = gBS->AllocatePages(
           AllocateAnyPages,
           EfiLoaderData,
           (*BufferSize + 8 + 4096) / 4096, // add 64bit space
           Buffer
           );
  if (EFI_ERROR (Status)) {
    Print(L"%Could not allocate memory pool %r\n", Status);
    return NULL;
  }
  Print(L"allocate address = %x\n", *Buffer);

  // set size to first 64bit space
  UINT64 *Buffer_p = (UINT64 *)*Buffer;
  *Buffer_p = *BufferSize;

  Status = File->Read(
          File,
          BufferSize,
          (VOID *)(Buffer_p + 1) // shift 64bit
          );
  if (EFI_ERROR (Status)) {
    Print(L"%Could not Read file: %r\n", Status);
    return NULL;
  }

  File->Close(File);
  Root->Close(Root);
  gBS->FreePool(FileInfo);

  return Buffer;
}


EFI_STATUS
EFIAPI
UefiMain (
	  IN     EFI_HANDLE        ImageHandle,
	  IN     EFI_SYSTEM_TABLE  *SystemTable
	  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  gST = SystemTable;
  gBS = gST->BootServices;

  EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
  Status = gBS->HandleProtocol( ImageHandle,
                                &gEfiLoadedImageProtocolGuid,
                                (void **)&loaded_image);
    if (EFI_ERROR(Status)) {
        Print(L"handleprotocol: %r\n", Status);
    }
 
    Print(L"Image base: 0x%lx\n", loaded_image->ImageBase);
 

  UINTN MemmapSize = PAGE_SIZE;
  VOID *Memmap;
  
  UINTN MapKey;
  UINTN DescriptorSize;
  UINT32 DescriptorVersion;

  
  Status = gBS->AllocatePool(
			     EfiLoaderData,
			     MemmapSize,
			     (VOID **)&Memmap
			     );
  if (EFI_ERROR (Status)) {
    Print(L"%Could not allocate memory pool %r\n", Status);
    return Status;
  }
  
  Status = gBS->GetMemoryMap(
			     &MemmapSize,
			     Memmap,
			     &MapKey,
			     &DescriptorSize,
			     &DescriptorVersion
			     );
  if (EFI_ERROR (Status)) {
    Print(L"%Could not get memory map %r\n", Status);
    return Status;
  }

  /* Print(L"Memmap = %p\n", Memmap); */
  /* Print(L"MemmapSize = %d\n", MemmapSize); */
  /* Print(L"MapKey = %d\n", MapKey); */
  /* Print(L"sizeof(EFI_MEMORY_DESCRIPTOR) = %d\n", sizeof(EFI_MEMORY_DESCRIPTOR)); */
  /* Print(L"DescriptorSize = %d\n", DescriptorSize); */
  /* Print(L"DescriptorVersion = %d\n", DescriptorVersion); */

  
  UINT64 *e820data_entry;
  UINT32 e820_size = sizeof(struct e820ent) * (MemmapSize / DescriptorSize);
  Status = gBS->AllocatePool(
			     EfiLoaderData,
			     e820_size + 8, // add 64bit
			     (VOID **)&e820data_entry
			     );
  if (EFI_ERROR (Status)) {
    Print(L"%Could not allocate memory pool %r\n", Status);
    return Status;
  }

  // set e820 size to first 64bit
  *e820data_entry = e820_size;
  // shift 64bit
  struct e820ent *e820data = (struct e820ent *)(e820data_entry + 1);

  for (int i = 0; i < (MemmapSize / DescriptorSize); i++)
  {
    EFI_MEMORY_DESCRIPTOR *md = Memmap + (i * DescriptorSize);
    /* Print(L"memmap: 0x%08x, 0x%016x, 0x%016x, %10ld, 0x%016x\n", */
    /* 	  md->Type, */
    /* 	  md->PhysicalStart, */
    /* 	  md->VirtualStart, */
    /* 	  md->NumberOfPages, */
    /* 	  md->Attribute */
    /* 	  ); */
    Memmap_to_e820(&(e820data[i]), md);
    // Print(L"E820: %d, 0x%016x-0x%016x\n",
    // 	  e820data[i].type,
    // 	  e820data[i].addr,
    // 	  e820data[i].addr + e820data[i].size
    // 	  );   
  }  

  // load cmdline
  EFI_PHYSICAL_ADDRESS Cmdline;
  UINT64 Cmdline_size = 0;
  LoadFileToMemoryPool(L"cmdline", &Cmdline, &Cmdline_size);

  // load kernel
  EFI_PHYSICAL_ADDRESS Kernel;
  UINT64 Kernel_size = 0;
  LoadFileToMemoryPool(L"loader-stripped.elf", &Kernel, &Kernel_size);

  // load loader2
  EFI_PHYSICAL_ADDRESS loader2_buf;
  UINT64 loader2_buf_size = 0;
  LoadFileToMemoryPool(L"boot2.bin", &loader2_buf, &loader2_buf_size);

  Print(L"Cmdline addr = 0x%lx\n", Cmdline);
  Print(L"Kernel addr = 0x%lx\n", Kernel);
  Print(L"boot2 addr = 0x%lx\n", loader2_buf);

  int wait = 1;
  while (wait) {
      __asm__ __volatile__("pause");
  }

  // start kernel
  entry_func_t *entry_func;
  entry_func = (entry_func_t *)((UINT64 *)loader2_buf + 1);
  entry_func ((VOID *)Kernel, (VOID *)e820data_entry, (VOID *)Cmdline);
  // EFIAPI (*loader2)(VOID *, VOID *, VOID *);
  // loader2 = (EFIAPI (*))((UINT64 *)loader2_buf + 1);
  // (*loader2)(Kernel, e820data_entry, Cmdline);

  gBS->FreePool(Memmap);
  gBS->FreePool(e820data_entry);
  gBS->FreePages(Cmdline, Cmdline_size);
  gBS->FreePages(Kernel, Kernel_size);
  gBS->FreePages(loader2_buf, loader2_buf_size);
    
  return EFI_SUCCESS;
}


