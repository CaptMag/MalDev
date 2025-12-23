#pragma once
#include "func.h"

/** The entire SMBIOS table with metadata */
typedef struct _RawSMBIOSData {
    BYTE  Used20CallingMethod;
    BYTE  SMBIOSMajorVersion;
    BYTE  SMBIOSMinorVersion;
    BYTE  DmiRevision;
    DWORD Length;
    BYTE  SMBIOSTableData[];
} RawSMBIOSData;

/** Generic structure */
typedef struct SMBIOSStruct {
    BYTE    Type;
    BYTE    Length;
    WORD    Handle;
} SMBIOS_HEADER;

typedef struct _SMBIOS_TYPE0 {
    SMBIOS_HEADER Hdr;
    uint8_t  Vendor;           // String index
    uint8_t  Version;          // String index
    uint16_t StartSegment;
    uint8_t  ReleaseDate;      // String index
    uint8_t  RomSize;
    uint64_t Characteristics;
} SMBIOS_TYPE0;

typedef struct _SMBIOS_TYPE1 {
    SMBIOS_HEADER Hdr;
    uint8_t  Manufacturer;     // String
    uint8_t  ProductName;      // String
    uint8_t  Version;          // String
    uint8_t  SerialNumber;     // String
    uint8_t  UUID[16];
    uint8_t  WakeUpType;
} SMBIOS_TYPE1;

typedef struct _SMBIOS_TYPE2 {
    SMBIOS_HEADER Hdr;
    uint8_t  Manufacturer;     // String
    uint8_t  Product;          // String
    uint8_t  Version;          // String
    uint8_t  SerialNumber;     // String
    uint8_t  AssetTag;         // String
    uint8_t  FeatureFlags;
    uint8_t  LocationInChassis;// String
    uint16_t ChassisHandle;
    uint8_t  BoardType;
} SMBIOS_TYPE2;

typedef struct _SMBIOS_TYPE3 {
    SMBIOS_HEADER Hdr;
    uint8_t  Manufacturer;     // String
    uint8_t  Type;
    uint8_t  Version;          // String
    uint8_t  SerialNumber;     // String
    uint8_t  AssetTag;         // String
    uint8_t  BootupState;
    uint8_t  PowerSupplyState;
    uint8_t  ThermalState;
    uint8_t  SecurityStatus;
} SMBIOS_TYPE3;

typedef struct _SMBIOS_TYPE4 {
    SMBIOS_HEADER Hdr;
    uint8_t  SocketDesignation; // String
    uint8_t  ProcessorType;
    uint8_t  ProcessorFamily;
    uint8_t  Manufacturer;     // String
    uint64_t ProcessorID;
    uint8_t  Version;          // String
    uint8_t  Voltage;
    uint16_t ExternalClock;
    uint16_t MaxSpeed;
    uint16_t CurrentSpeed;
    uint8_t  Status;
    uint8_t  ProcessorUpgrade;
} SMBIOS_TYPE4;

typedef struct _SMBIOS_TYPE16 {
    SMBIOS_HEADER Hdr;
    uint8_t  Location;
    uint8_t  Use;
    uint8_t  ErrorCorrection;
    uint32_t MaximumCapacity;
    uint16_t ErrorInformationHandle;
    uint16_t NumberOfMemoryDevices;
} SMBIOS_TYPE16;

typedef struct _SMBIOS_TYPE17 {
    SMBIOS_HEADER Hdr;
    uint16_t PhysicalMemoryArrayHandle;
    uint16_t MemoryErrorInformationHandle;
    uint16_t TotalWidth;
    uint16_t DataWidth;
    uint16_t Size;
    uint8_t  FormFactor;
    uint8_t  DeviceSet;
    uint8_t  DeviceLocator;    // String
    uint8_t  BankLocator;      // String
    uint8_t  MemoryType;
    uint16_t TypeDetail;
    uint16_t Speed;
    uint8_t  Manufacturer;     // String
    uint8_t  SerialNumber;     // String
    uint8_t  AssetTag;         // String
    uint8_t  PartNumber;       // String
} SMBIOS_TYPE17;

typedef struct _SMBIOS_TYPE127 {
    SMBIOS_HEADER Hdr;
} SMBIOS_TYPE127;