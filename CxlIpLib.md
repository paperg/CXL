
@[toc]
## CxlIpLib.c

### 1. CxlRcrbReadWrapper()

- memRead 读函数包装

### 2. CxlRcrbWriteWrapper()

- memWrite 写函数包装

### 3. ReadCxlVenId()

- 从 CXL 配置空间读 CXL 设备的 VID

```c

/**
  ReadCxlVenId reads Cxl device vendor Id from Cxl (pci) config space

  @param[in]  Seg     Segment number of Cxl device
  @param[in]  Bus     Bus numer of Cxl Device

  @retval     VendorId  Cxl device's Vendor Id
**/
UINT16
EFIAPI
ReadCxlVenId (
  IN  UINT8 Socket,
  IN  UINT8 Bus
  )
{
  UINT16              VendorId;
  USRA_ADDRESS        CxlDevPciAddress;
  
  // 通过 BDF 生成 Pcie mmcfg 物理地址
  GenerateBasePciePhyAddress (Socket, Bus, CXL_DEV_DEV, CXL_DEV_FUNC, \
                              UsraWidth16, &CxlDevPciAddress);
  CxlDevPciAddress.Pcie.Offset = PCI_VENDOR_ID_OFFSET;
  CXL_DEBUG_LOG ("\tSocket %d Cxl Device Func Vendor Id Address = %x \n",\
                Socket, CxlDevPciAddress.dwRawData[0]);
  // silicon 寄存器读 VID
  RegisterRead (&CxlDevPciAddress, &VendorId);

  CXL_DEBUG_LOG ("\tCxl Device under Bus: %x Dev: %x Fun: %d vendor is %x\n", Bus, CXL_DEV_DEV, \
                  CXL_DEV_FUNC, VendorId);
  return VendorId;
}

```

### 4. GetCxlDPSecBus()
![请添加图片描述](https://img-blog.csdnimg.cn/d5ddd6c9e1ef4ce58eaa1aa9b6f27350.png)


- 从 RCRB 基地址读次级总线。ref PCIe 5.0 Figure 7-14 Type 1 Configuration Space Header,从头配置空间偏移 0x19 读出次级总线号；
- CXL 1.1 Upstream and Downstream Port RCRB , 前64字节实现来自 PCIe Type1 Configuration Header.

> **CXL 2.0 8.2.1.1 CXL 1.1 Downstream Port RCRB**
The CXL 1.1 Downstream Port RCRB is a 4K memory region that contains registers based upon the PCIe specification defined registers for a Root Port. Figure 134 illustrates the layout of the CXL RCRB for a Downstream Port. With the exception of the first DWORD, the first 64 bytes of the CXL DP RCRB implement the registers from a PCIe Type 1 Configuration Header.

### 5. GetCxlDownstreamBus()

- 从CXL DP RCRB 寄存器常规获取 Secondary/Subordinate Bus。读取 Rcrb基地址，从偏移处读一个字节。

### 6. SetCxlDownstreamSecBus()

- 为 CXL Downstream port 设置 Secondary Bus 寄存器。Note: DP RCRB 基地址必须 8K 对齐；向 0x19 偏移处写总线号；

### 7. SetCxlDownstreamSubBus()

- 为 CXL Downstream port 设置 Subordinate Bus 寄存器。Note: DP RCRB 基地址必须 8K 对齐；向 0x1a 偏移处写总线号；

### 8. CxlDeviceGetExtCapOffset()

- 对一个指定 PCI 设备的特定扩展能力，获取它的偏移。产生PCI域地址-》遍历 PCI 扩展空间寄存器 -》找到扩展能力，返回偏移。

### 9. Cxl11DeviceDvsecRegAndThenOr()

- 此函数定位Root Port下的 CXL1.1 设备，写指定值到指定的寄存器，Socket, stack, register block offset and dvsec Id 必须给出。

```c

/**
  Cxl11DeviceDvsecRegAndThenOr function locates CXL11 devices under root port,
  and writes the given value to specific register pointed by caller.
  Socket, stack, register block offset and dvsec Id must be given by the caller.
  To identify register block offset, use data structure definition from cxl
  header files (cxl11.h and cxl20.h)

  @param[in] SocId                Socket number
  @param[in] CtrId                Stack number
  @param[in] DvsecIdBlockRegOffet Register offset within specific Dvsec register block
  @param[in] DvsecId              Dvsec Group Id to locate [CXL has multiple Dvsec register blocks]
  @param[in] AndData              And value to register
  @param[in] OrData               Or value to register
  @param[in] UsraDataWidth        Data size to perform operation [8, 16, 32 are value values]

  @retval    Status               EFI_SUCCESS Operation completed successfully
                                  EFI_INVALID_PARAMETER Invalid Parameter passed
                                  EFI_NOT_FOUND The register is not found in config space
**/
EFI_STATUS
EFIAPI
Cxl11DeviceDvsecRegAndThenOr (
  IN      UINT8               SocId,
  IN      UINT8               CtrId,
  IN      UINT16              DvsecIdBlockRegOff,
  IN      UINT8               DevsecId,
  IN      UINT32              AndData,
  IN      UINT32              OrData,
  IN      USRA_ACCESS_WIDTH   UsraDataWidth
)
{
  USRA_ADDRESS                PciAddr;
  UINT32                      Data32;

  Data32 = 0;
  if (SocId >= MAX_SOCKET || CtrId >= MAX_CXL_PER_SOCKET) {
    return EFI_INVALID_PARAMETER;
  }

  // 获取下一级BUS,用于组合访问设备配置空间的 PCIe 物理地址
  Data32 = (UINT8)GetCxlDownstreamBus (SocId, CtrId, (SECBUS_IIO_PCIE_G5_REG & 0xFFFF));
  GenerateBasePciePhyAddress (SocId, (UINT8) Data32, CXL_DEV_DEV, CXL_DEV_FUNC, UsraDataWidth, &PciAddr);

  // 从 4K 配置空间中定位指定的 CXL DVSEC 扩展能力 -》 DevsecId 指示哪一个 DVSEC
  PciAddr.Pcie.Offset = FindCxlDvsecCapability (&PciAddr, DevsecId);
  if (PciAddr.Pcie.Offset == 0) {
    return EFI_NOT_FOUND;
  }
  // DvsecIdBlockRegOff : 要操作的寄存器的 DVSEC 的偏移位置
  PciAddr.Pcie.Offset += DvsecIdBlockRegOff;
  // 读寄存器
  RegisterRead (&PciAddr, &Data32);
  // 与数据 
  Data32 &= AndData;
  // 或数据
  Data32 |= OrData;
  //写回
  RegisterWrite (&PciAddr, &Data32);
  return EFI_SUCCESS;
}

```


### 10.Cxl11DeviceDvsecRegAndThenOr8()/Cxl11...AndThenOr16()\Cxl11...AndThenOr32()

- 写寄存器值，数据大小不一样， 8bit/16bit/32bit；

### 11. Cxl11DeviceDvsecRegRead()

- 读 CXL DVSEC 寄存器，Socket, stack, register block offset and dvsec Id 必须给出。函数操作与写基本一致；

### 12.Cxl11DeviceDvsecRegRead8()/Cxl11DeviceDvsecRegRead16()/Cxl11DeviceDvsecRegRead32()

- 读寄存器值，数据大小不一样， 8bit/16bit/32bit；

### 13. CxlDeviceDvsecRegisterAccess()

- 此函数将访问指定设备的 DVSEC 寄存器。Note: 调用者必须申请数据缓冲区，并提供头指针。

```c


/**
  This function will access(Read or Write) the DVSEC registers of a specified CXL Device.
  Note: The caller need to allocate a data buffer and provide the pointer to the data buffer.

  @param[in]     Socket                Device's socket number.
  @param[in]     Stack                 Box Instane, 0 based.
  @param[in]     DvsecRegOff           Offset relative to the beginning of DVSEC structure.
  @param[in]     UsraDataWidth         USRA data access width, please refer to the enum USRA_ACCESS_WIDTH.
  @param[in]     OperationType         Operation type, please refer to the enum CXL_OPERATION_TYPE. 读写操作\CxlOperationMax
  @param[in out] Buffer                The pointer to the data buffer.  缓冲区指针

  @retval        EFI_SUCCESS           The access is successful. If read, the data is returned in Buffer.
  @retval        EFI_INVALID_PARAMETER One of the input parameter is invalid.
  @retval        EFI_NOT_FOUND         Can't find DVSEC structure in CXL device configuration space
  @retval        EFI_UNSUPPORTED       Unsupported Operation type.

**/
EFI_STATUS
EFIAPI
CxlDeviceDvsecRegisterAccess (
  IN       UINT8              Socket,
  IN       UINT8              Stack,
  IN       UINT16             DvsecRegOff,
  IN       USRA_ACCESS_WIDTH  UsraDataWidth,
  IN       CXL_OPERATION_TYPE OperationType,
  IN  OUT  VOID               *Buffer
  )
{
  UINT8               CxlDevBus;
  UINT8               Idx;
  UINT16              ExtCapDvsecOffset;
  USRA_ADDRESS        CxlDevPciAddress;

  if (Buffer == NULL) {
    DEBUG ((DEBUG_ERROR, "\nThe Buffer pointer must not be NULL!\n"));
    return EFI_INVALID_PARAMETER;
  }

  // MAX_CXL_PER_SOCKET == 8
  if (Stack >= MAX_CXL_PER_SOCKET) {
    DEBUG ((DEBUG_ERROR, "\nInvalid CXL Instance ID %x!\n", Stack));
    return EFI_INVALID_PARAMETER;
  }

  // 获取下一级总线号
  CxlDevBus = GetCxlDownstreamBus (Socket, Stack, (SECBUS_IIO_PCIE_G5_REG & 0xFFFF));
  if (CxlDevBus == 0) {
    return EFI_INVALID_PARAMETER;
  }

  ExtCapDvsecOffset = 0;

  // CxlVendorIdList[] = {CXL_DVSEC_VENDOR_ID=0x1e98, INTEL_CXL_DVSEC_VENDOR_ID=0x8086}
  // 寻找 DVSEC 偏移位置
  for (Idx = 0; Idx < (sizeof (CxlVendorIdList) / sizeof (UINT16)); Idx++) {
    ExtCapDvsecOffset = CxlDeviceGetExtCapOffset (
                          Socket,
                          CxlDevBus,
                          CXL_DEV_DEV,
                          CXL_DEV_FUNC,
                          PCI_EXPRESS_EXTENDED_CAPABILITY_DESIGNATED_VENDOR_SPECIFIC_ID,
                          CXL_DEVICE_DVSEC,
                          CxlVendorIdList[Idx]
                          );

    if (ExtCapDvsecOffset != 0) {
      break;
    }
  }

  if (ExtCapDvsecOffset == 0) {
    DEBUG ((DEBUG_ERROR, "Can't find DVSEC structure in CXL device configuration space!\n"));
    return EFI_NOT_FOUND;
  }

  // 生成 PCIe 物理地址，计算要访问的寄存器的偏移地址
  GenerateBasePciePhyAddress (Socket, CxlDevBus, CXL_DEV_DEV, CXL_DEV_FUNC,\
                              UsraDataWidth, &CxlDevPciAddress);
  CxlDevPciAddress.Pcie.Offset = ExtCapDvsecOffset + DvsecRegOff;

  if (OperationType == CxlOperationRead) {
    // 读寄存器
    RegisterRead (&CxlDevPciAddress, Buffer);
  } else if (OperationType == CxlOperationWrite) {
    // 写寄存器
    RegisterWrite (&CxlDevPciAddress, Buffer);
    //
    // Add below UBIOS log since USRA does not support UBIOS generation for PCIe access.
    // 
    if (UbiosGenerationEnabled ()) {
      switch (UsraDataWidth) {
        case UsraWidth64:
          DEBUG ((DEBUG_ERROR, "\n  mov QWORD PTR ds:[0%08xh], 0%016xh\n", GetRegisterAddress (&CxlDevPciAddress), *(UINT64 *)Buffer));
          break;
        case UsraWidth32:
          DEBUG ((DEBUG_ERROR, "\n  mov DWORD PTR ds:[0%08xh], 0%08xh\n", GetRegisterAddress (&CxlDevPciAddress), *(UINT32 *)Buffer));
          break;
        case UsraWidth16:
          DEBUG ((DEBUG_ERROR, "\n  mov WORD PTR ds:[0%08xh], 0%04xh\n", GetRegisterAddress (&CxlDevPciAddress), *(UINT16 *)Buffer));
          break;
        case UsraWidth8:
        default:
          DEBUG ((DEBUG_ERROR, "\n  mov BYTE PTR ds:[0%08xh], 0%02xh\n", GetRegisterAddress (&CxlDevPciAddress), *(UINT8 *)Buffer));
          break;
      }
    }
  } else {
    DEBUG ((DEBUG_ERROR, "Unsupported operation type!\n"));
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

```

### 14. CxlDeviceDvsecRegisterAndThenOr16()

- 此函数对指定设备的 DVSEC 寄存器做 bit 字段的操作，与 AndData， 或 OrData 并返回；流程与上述函数一样；

### 15. CxlPortGetCapOffset()

- 此函数对于一个指定的端口(DP or UP),指定 PCIe Capability ID，寻找其相对于 RCRB 基地址的偏移
- 首先简单介绍以下DP与UP,在一个PCIe系统中，方向的定义是以大佬RC为准的。RC高高在上，面往RC方向称之为上行（红色粗箭头），反之称之为下行（蓝色粗箭头）。由于PCIe是点对点连接的，每个连接的地方，我们称之为Port。对于Root Complex而言，它仅有一个下行端口。对于PCI-Express switch，它有一个上行端口（upstream port）和多个下行端口（downstream ports）。而PCIe设备（EP）仅有一个上行端口。

![请添加图片描述](https://img-blog.csdnimg.cn/d59aa51b2eed4e78aa555c793eaacafb.png)


```c

/**
  This function finds the RCRB offset for a specified PCIe Capability ID
  for a specified Flex Bus Port (Downstream port or Upstream port).

  @param[in] Socket        CXL's socket number.
  @param[in] Stack         Box Instane, 0 based.
  @param[in] UpstreamPort  FALSE - Downstram port; TRUE - Upstream port.  指定端口
  @param[in] CapabilityId  ID of the desired Extended Capability.

  @return The capability structure offset is returned, or zero if ID was not found.
**/
UINT8
EFIAPI
CxlPortGetCapOffset (
  IN      UINT8   Socket,
  IN      UINT8   Stack,
  IN      BOOLEAN UpstreamPort,
  IN      UINT8   CapabilityId
  )
{
  UINT32          RcrbBaseAddr;
  UINT8           CapOffset;
  UINT8           CapId = 0;

  // 获取 RCRB 基地址，底层函数
  RcrbBaseAddr = (UINT32)GetRcrbBar (Socket, Stack, TYPE_CXL_RCRB);
  if (RcrbBaseAddr == 0) {
    return 0;
  }
  
  // CXL 1.1 下游和上游端口 RCRB 是一个连续的 8K 区域, UpstreamPort 与 RcrbBaseAddr 偏移 4K 
  if (UpstreamPort) {

    RcrbBaseAddr += CXL_RCRB_BAR_SIZE_PER_PORT;
  }
  //
  // Get the start offset that points to the first capability
  // ref PCIe 5.0 Figure 7-14 Type 1 Configuration Space Header, Capabilities Pointer 0x34 
  CapOffset = (UINT8) CxlRcrbReadWrapper (Socket, RcrbBaseAddr + PCI_CAPBILITY_POINTER_OFFSET, UsraWidth8);
  //
  // Keep looking for a Capability ID that match the expected one
  // until we reach next capability offset zero.
  //
  while (CapOffset != 0 && CapId != 0xFF) {
	// 读 Capability ID
    CapId = (UINT8) CxlRcrbReadWrapper (Socket, RcrbBaseAddr + CapOffset, UsraWidth8);
    if (CapId == CapabilityId) {
	  // 找到能力，返回偏移位置
      return CapOffset;
    }
	// 读下一个偏移 Next Capability Pointer
    CapOffset = (UINT8) CxlRcrbReadWrapper (Socket, RcrbBaseAddr + CapOffset + 1, UsraWidth8);
  }
  return 0;
}

```

From PCIe 5.0 spec Table 7-17![请添加图片描述](https://img-blog.csdnimg.cn/6978f1e995674bd5b0db28a550a224f8.png)


### 16. RcrbGetExtCapOffset()

- 此函数在 RCRB 内存配置空间中寻找扩展能力偏移

![请添加图片描述](https://img-blog.csdnimg.cn/37015d9a5af84e0ea599207a5ee1c538.png)


```c 

/**
  RcrbGetExtCapOffset finds Extended cap Id offset in Rcrb memory configuration space.

  @param[in]  RcrbBaseAddr        Rcrb Mmio Base address to find Ext cap id   RCRB 基地址
  @param[in]  ExtCapId            Extended Capability to find                 要寻找的 Extended Capability
  @param[in]  VsecId              Vendor sec Id. Only applicable for Cap Id 0xB and 0x23. 
                                  Not used for other cap ids
  @param[in]  DvsecVendorId       Dvsec Vendor Id. Only applicable to Cap Id 0x23  CapID=0x23 的时候使用
                                  Not used for other cap ids

  @retval     Value               0         Extended capability Id not found
                                  non-zero  Extended capability Offset
**/
UINT16
EFIAPI
RcrbGetExtCapOffset (
  IN      UINT32  RcrbBaseAddr,
  IN      UINT16  ExtCapId,
  IN      UINT16  VsecId,
  IN      UINT16  DvsecVendorId
  )
{
  UINT8             Socket;       // Socket number is used only in KtiSim
  UINT16            ExtCapOffset;
  UINT32            ExtCapHeader;
  UINT16            Data16;
  UINT16            VsecRegOffset;

  Socket = 0;
  //
  // Get the start offset that points to the extended capability structure list
  // > Extended Capabilities in a Root Complex Register Block always begin at offset 000h with a PCI Express Extended Capability header. ref PCIe 5.0 spec 7.6.2

  ExtCapHeader = CxlRcrbReadWrapper (Socket, RcrbBaseAddr, UsraWidth32);
  ExtCapOffset = (UINT16)(ExtCapHeader >> 20);  // Bit[31:20] = next ptr

  while (ExtCapOffset != 0 && ExtCapOffset != 0xFFF) {
    //
    // PCI Express Base 4.0 Revision 1.0 Specification
    // Chapter 7.6.3 PCI Express Extended Capability Header
    // "For Extended Capabilities implemented in Configuration Space,
    // this offset is relative to the beginning of PCI compatible Configuration Space
    // and thus must always be either 000h (for terminating list of Capabilities)
    // or greater than 0FFh.
    // The bottom 2 bits of this offset are Reserved and must be implemented as 00b
    // although software must mask them to allow for future uses of these bits."
    //
	// 根据规范，ExtCapOffset必须始终为0或者大于 0FFh, 0 为终止。
	// 低 2 位 保留必须为 00b
	//  对上述两个内容进行检查
	
    if ((ExtCapOffset & DWORD_MASK) || (ExtCapOffset < CXL_PORT_RCRB_EXTENDED_CAPABILITY_BASE_OFFSET)) {
      // dword alignment; lower limit
      ExtCapOffset = 0;  // if bad format or normal end of list, set not found
      break;            //  terminate search
    }

    // offset is good, get capabilities ID and next offset
    // capabilities ID check
    ExtCapHeader = CxlRcrbReadWrapper (Socket, RcrbBaseAddr + ExtCapOffset, UsraWidth32);

    if (((ExtCapHeader & EXCAP_MASK) == 0xFFFF) && ((ExtCapHeader >> 20) == 0)) {
      //
      // PCI Express Base 4.0 Revision 1.0 Specification
      // Chapter 7.6.2 Extended Capabilities in the Root Complex Register Block
      // Absence of any Extended Capabilities is required to be indicated by an Extended Capability header
      // with a Capability ID of FFFFh and a Next Capability Offset of 000h.
      // 任何扩展能力不存在的话，cap ID == ffffh && next cap off == 0h
      ExtCapOffset = 0;
      break;
    }

    // 比较是否匹配
    if ((ExtCapHeader & EXCAP_MASK) == ExtCapId) {
      switch (ExtCapId) {
        case PCI_EXPRESS_EXTENDED_CAPABILITY_VENDOR_SPECIFIC_ID:
          VsecRegOffset = 4;
          Data16 = (UINT16) CxlRcrbReadWrapper (Socket, RcrbBaseAddr + ExtCapOffset + VsecRegOffset, UsraWidth16);
          if (Data16 == VsecId) {
            //
            // Find the desired VSEC instance
            //
            return ExtCapOffset;
          }
          break;

        case PCI_EXPRESS_EXTENDED_CAPABILITY_DESIGNATED_VENDOR_SPECIFIC_ID:  // 0x23
          VsecRegOffset = OFFSET_OF (CXL_1_1_DVSEC_FLEX_BUS_PORT, DesignatedVendorSpecificHeader2);
          Data16 = (UINT16) CxlRcrbReadWrapper (Socket, RcrbBaseAddr + ExtCapOffset + VsecRegOffset, UsraWidth16);
          if (Data16 == VsecId) {  // DVSEC Extended Capability Header 15:0 -> VID
            //
            // Find the desired DVSEC instance, further check the DVSEC Vendor ID
            // DesignatedVendorSpecificHeader1  DVSEC ID
            VsecRegOffset = OFFSET_OF (CXL_1_1_DVSEC_FLEX_BUS_PORT, DesignatedVendorSpecificHeader1);
            Data16 = (UINT16) CxlRcrbReadWrapper (Socket, RcrbBaseAddr + ExtCapOffset + VsecRegOffset, UsraWidth16);
            if (Data16 == DvsecVendorId) { // 匹配返回 DVSEC 偏移地址
              return ExtCapOffset;
            }
          }
          break;

        default:
          return ExtCapOffset;
      }
    }
    ExtCapOffset = (UINT16)(ExtCapHeader >> 20);  // Bit[31:20] = next ptr
  }

  return 0;
}


```

### 17. CxlPortGetExtCapOffset()

- 此函数对于指定 Flex Bus Port 的特定扩展能力获取 RCRB 偏移；会调用上一个函数。

### 18. CxlPortDvsecRegisterAccess16()

- 此函数访问特定 CXL DP or UP Port 的 DVSEC 寄存器。
![请添加图片描述](https://img-blog.csdnimg.cn/1dc3e1de672d4c0da6c9b4d7f0c0e775.png)

```c

/**
  This function will access(Read or Write) the DVSEC registers of a specifid CXL DP or UP port.
  Note:
  1) The caller need to allocate a data buffer and provide the pointer to the data buffer.
  2) This function only support 16 bit register read/write.

  @param[in]     Socket                CXL's socket number.
  @param[in]     Stack                 Box Instane, 0 based.
  @param[in]     UpstreamPort          FALSE - Downstram port; TRUE - Upstream port.  端口选择
  @param[in]     DvsecRegOff           Offset relative to the beginning of DVSEC structure. 寄存器偏移
  @param[in]     OperationType         Operation type, please refer to the enum CXL_OPERATION_TYPE.   读写操作
  @param[in out] Buffer                The pointer to the data buffer.   缓冲区指针

  @retval        EFI_SUCCESS           The access is successful. If read, the data is returned in Buffer.
  @retval        EFI_INVALID_PARAMETER One of the input parameter is invalid or out of range.
  @retval        EFI_NOT_FOUND         Can't find DVSEC structure in Flex Bus port RCRB.
  @retval        EFI_UNSUPPORTED       Unsupported operation type.

**/
EFI_STATUS
EFIAPI
CxlPortDvsecRegisterAccess16 (
  IN       UINT8              Socket,
  IN       UINT8              Stack,
  IN       BOOLEAN            UpstreamPort,
  IN       UINT16             DvsecRegOff,
  IN       CXL_OPERATION_TYPE OperationType,
  IN  OUT  UINT16             *Buffer
  )
{
  UINT16            ExtCapDvsecOffset;
  UINT32            RcrbBaseAddr;
  UINT8             Idx;
  EFI_STATUS        Status;
  UINT8             CxlDevBus;

  Status = EFI_SUCCESS;

  if (Buffer == NULL) {
    DEBUG ((DEBUG_ERROR, "\nThe Buffer pointer must not be NULL!\n"));
    return EFI_INVALID_PARAMETER;
  }
  // MAX_CXL_PER_SOCKET = 8
  if (Stack >= MAX_CXL_PER_SOCKET) {
    DEBUG ((DEBUG_ERROR, "\nInvalid CXL Instance ID %x!\n", Stack));
    return EFI_INVALID_PARAMETER;
  }


  // ref CXL 2.0 spec 8.1.8 PCIe DVSEC for Flex Bus Port
  // In CXL 1.1 hosts and devices, this DVSEC is accessed via CXL 1.1 RCRB.
  // The DVSEC associated with a CXL 2.0 device shall be accessible via Device 0, Function 0 of the device.
  if ((IsCxl20DevOpInCxl11Mode (Socket, Stack) == TRUE) && (UpstreamPort == TRUE)) {
    // 如果设备是2.0设备，工作在1.1模式下，即将操作 UpstreamPort
	// 获取总线号
    CxlDevBus = GetCxlDownstreamBus (Socket, Stack, (SECBUS_IIO_PCIE_G5_REG & 0xFFFF));

    // 通过 bdf 读写端口寄存器
	// 从 4K PCI 配置空间寻找 DVSEC
    if (OperationType == CxlOperationRead) {
      Status = CxlDvsecRegRead (Socket, CxlDevBus, CXL_DEV_DEV, CXL_DEV_FUNC, CXL_FLEX_BUS_PORT_DVSEC, (UINT8) DvsecRegOff,\
                                Buffer, UsraWidth16);
    } else if (OperationType == CxlOperationWrite) {
      Status = CxlDvsecRegWrite (Socket, CxlDevBus, CXL_DEV_DEV, CXL_DEV_FUNC, CXL_FLEX_BUS_PORT_DVSEC, (UINT8) DvsecRegOff,\
                                 Buffer, UsraWidth16);
    }
    return Status;
  } else {
    // 如果是  Downstram Port 或者 不是2.0工作在 1.1 模式下
    ExtCapDvsecOffset = 0;
    // 从 RCRB 内存配置空间寻找 DVSEC
    for (Idx = 0; Idx < (sizeof (CxlVendorIdList) / sizeof (UINT16)); Idx++) {
      ExtCapDvsecOffset = CxlPortGetExtCapOffset (
                          Socket,
                          Stack,
                          UpstreamPort,
                          PCI_EXPRESS_EXTENDED_CAPABILITY_DESIGNATED_VENDOR_SPECIFIC_ID,
                          CXL_FLEX_BUS_PORT_DVSEC,
                          CxlVendorIdList[Idx]
                          );
      if (ExtCapDvsecOffset != 0) {
        break;
      }
    }

    if (ExtCapDvsecOffset == 0) {
      DEBUG ((DEBUG_ERROR, "Can't find DVSEC structure in Flex Bus port RCRB!\n"));
      return EFI_NOT_FOUND;
    }

    RcrbBaseAddr = (UINT32) GetRcrbBar (Socket, Stack, TYPE_CXL_RCRB);
    if (RcrbBaseAddr == 0) {
      return EFI_INVALID_PARAMETER;
    }

    if (UpstreamPort) {
      RcrbBaseAddr += CXL_RCRB_BAR_SIZE_PER_PORT;
    }

     // 找到 Flex Bus Port DVSEC，进行操作，地址需要通过 RCRB 基地址 + 偏移计算
      if (OperationType == CxlOperationRead) {
        *Buffer = MmioRead16 (RcrbBaseAddr + ExtCapDvsecOffset + DvsecRegOff);
      } else if (OperationType == CxlOperationWrite) {
        LogMmioWrite16 (RcrbBaseAddr + ExtCapDvsecOffset + DvsecRegOff, *Buffer);
      } else {
        DEBUG ((DEBUG_ERROR, "\nUnsupported operation type!\n"));
        return EFI_UNSUPPORTED;
      }
    return EFI_SUCCESS;
  }
}

```

### 19. CxlPortDvsecRegisterAndThenOr16()

- 对 CXL DP or UP 端口指定 DVSEC 寄存器进行位操作，流程与前一个函数一样。

### 20. GetCxlAccessInfoCxl11()

- CXL1.1 获取 CXL 端口与设备的访问地址,PCIe 配置空间基地址以及组件寄存器基地址。保存在  CxlAccessInfo 中。

```c 

/**
  Get the CXL Ports and Device's access addresses for Cxl 1.1.

  @param SocId                   - CPU Socket Node number (Socket ID)
  @param Stack                   - Box Instance, 0 based
  @param CxlProtocolList         - The CXL protocol list which is going to check, [0:0] - 1: indicate to check the cxl.$ protocol, 0: don't care cxl.$
                                                                                  [1:1] - 1: indicate to check the cxl.mem protocol, 0: don't care cxl.mem
                                   If the field is 0, means there is no need to check the protocol supported. Then it will return the CxlAccessInfo if the
                                   stack works as CXL.
  @param CxlAccessInfo           - CXL Access output structure (CXL DP RCRB Base & CXL device PCI address)

  @retval EFI_SUCCESS            - The CXL Access info is successfully returned in the output data structure.
  @retval EFI_UNSUPPORTED        - The CXL doesn't not support the input protocols.
  @retval EFI_INVALID_PARAMETER  - One of the input parameter is invalid.
  @retval EFI_NOT_FOUND          - Failed to read the CXL device's Capability register.

**/
EFI_STATUS
EFIAPI
GetCxlAccessInfoCxl11 (
  IN UINT8              Socket,
  IN UINT8              Stack,
  IN CXL_PROTOCOL_LIST  CxlProtocolList,
  OUT CXL_ACCESS_INFO   *CxlAccessInfo
  )
{
  USRA_ADDRESS                          CxlDevUsraAddress;
  UINT32                                RcrbBarBase;
  UINT8                                 CxlDevBus;
  EFI_STATUS                            Status;
  CXL_DVSEC_FLEX_BUS_DEVICE_CAPABILITY  CxlDevCap;

  if (CxlAccessInfo == NULL) {
    DEBUG((DEBUG_ERROR, "CxlAccessInfo is NULL\n"));
    ASSERT(FALSE);
    return EFI_INVALID_PARAMETER;
  }

  if (GetCxlStatus(Socket, Stack) != AlreadyInCxlMode) {
    DEBUG ((DEBUG_INFO, "\nThe Stack %d is not in CXL mode!", Stack));
    return EFI_UNSUPPORTED;
  }

  // 读 CXL 1.1 设备的 DeviceCapability 寄存器 2 字节
  Status = CxlDeviceDvsecRegisterAccess (Socket,
                                         Stack,
                                         OFFSET_OF (CXL_1_1_DVSEC_FLEX_BUS_DEVICE, DeviceCapability),
                                         UsraWidth16,
                                         CxlOperationRead,
                                         &CxlDevCap.Uint16
                                         );

  if(Status != EFI_SUCCESS){
    DEBUG ((DEBUG_ERROR, "\n Failed to read the CXL device's Capability register!\n"));
    return EFI_NOT_FOUND;
  }

  //
  // Check if it needs to check the CXL cache capability
  // 检查是否支持  .cache
  if ((CxlProtocolList & CXL_PROTOCOL_CACHE_TYPE) != 0) {
    if (CxlDevCap.Bits.CacheCapable == 0) {
      DEBUG ((DEBUG_ERROR, "\nThe CXL device in CXL port %d doesn't support CXL.$!", Stack));
      return EFI_UNSUPPORTED;
    }
  }

  //
  // Check if it needs to check the CXL memory capability
  // 检查是否支持 .mem
  if ((CxlProtocolList & CXL_PROTOCOL_MEM_TYPE) != 0) {
    if (CxlDevCap.Bits.MemCapable == 0) {
      DEBUG ((DEBUG_ERROR, "\nThe CXL device in CXL port %d doesn't support CXL.M!", Stack));
      return EFI_UNSUPPORTED;
    }
  }

  // 获取 RCRB 基地址
  RcrbBarBase = (UINT32) GetRcrbBar (Socket, Stack, TYPE_CXL_RCRB);
  if (RcrbBarBase == 0) {
    CxlAccessInfo->CxlPortRcrbBar = 0;
    CxlAccessInfo->CxlDevPcieAddress = 0;
    CxlAccessInfo->CxlDevCompRegAddress = 0;
    return EFI_UNSUPPORTED;
  }
  // 赋值 CxlPortRcrbBar
  CxlAccessInfo->CxlPortRcrbBar = RcrbBarBase;

  CxlDevBus = GetCxlDownstreamBus (Socket, Stack, (SECBUS_IIO_PCIE_G5_REG & 0xFFFF));
  if (CxlDevBus == 0) {
    CxlAccessInfo->CxlDevPcieAddress = 0;
    CxlAccessInfo->CxlDevCompRegAddress = 0;
    return EFI_UNSUPPORTED;
  }

  //
  // Point to the CXL device's pci configuration space offset 0 (VID field)
  // VID 在 PCI 配置空间起始位置
  GenerateBasePciePhyAddress (Socket, CxlDevBus, CXL_DEV_DEV, CXL_DEV_FUNC, \
                              UsraWidth32, &CxlDevUsraAddress);
  CxlDevUsraAddress.Pcie.Offset = PCI_VENDOR_ID_OFFSET;
  CxlAccessInfo->CxlDevPcieAddress = GetRegisterAddress (&CxlDevUsraAddress);

  //
  // Read the CXL device component register access in the upstream RCRB
  // ref CXL 2.0 Table 137. CXL Memory Mapped Registers Regions CXL1.1 component register
  // CXL1.1 组件寄存器位置在RCRB MEMBAR0的 0x10 和 0x14 偏移处
  CxlAccessInfo->CxlDevCompRegAddress = CxlRcrbReadWrapper (
                                          Socket,
                                          RcrbBarBase + SIZE_4KB + PCI_BASE_ADDRESSREG_OFFSET,
                                          UsraWidth32
                                          );
  CxlAccessInfo->CxlDevCompRegAddress &= (UINTN) ~0xF;
  return EFI_SUCCESS;
}

```

### 21. GetCxlAccessInfoCxl20DevCmpat()

-  CXL2.0设备工作在1.1模式下，获取端口和设备的访问地址。

```c

/**
  Get the CXL Ports and Device's access addresses for  Cxl 2.0 device operating in 1.1 mode.

  @param SocId                   - CPU Socket Node number (Socket ID)
  @param Stack                   - Box Instance, 0 based
  @param CxlProtocolList         - The CXL protocol list which is going to check, [0:0] - 1: indicate to check the cxl.$ protocol, 0: don't care cxl.$
                                                                                  [1:1] - 1: indicate to check the cxl.mem protocol, 0: don't care cxl.mem
                                   If the field is 0, means there is no need to check the protocol supported. Then it will return the CxlAccessInfo if the
                                   stack works as CXL.
  @param CxlAccessInfo           - CXL Access output structure (CXL DP RCRB Base & CXL device PCI address)

  @retval EFI_SUCCESS            - The CXL Access info is successfully returned in the output data structure.
  @retval EFI_UNSUPPORTED        - The CXL doesn't not support the input protocols.
  @retval EFI_INVALID_PARAMETER  - One of the input parameter is invalid.
  @retval EFI_NOT_FOUND          - Failed to read the CXL device's Capability register.

**/
EFI_STATUS
EFIAPI
GetCxlAccessInfoCxl20DevCmpat (
  IN UINT8              Socket,
  IN UINT8              Stack,
  IN CXL_PROTOCOL_LIST  CxlProtocolList,
  OUT CXL_ACCESS_INFO   *CxlAccessInfo
  )
{
  USRA_ADDRESS                              CxlDevUsraAddress;
  UINT32                                    RcrbBarBase;
  UINT8                                     CxlDevBus;
  EFI_STATUS                                Status;
  CXL_2_0_DVSEC_FLEX_BUS_DEVICE_CAPABILITY  CxlDevCap20;

  if (CxlAccessInfo == NULL) {
    DEBUG((DEBUG_ERROR, "CxlAccessInfo is NULL\n"));
    ASSERT(FALSE);
    return EFI_INVALID_PARAMETER;
  }

  if (GetCxlStatus(Socket, Stack) != AlreadyInCxlMode) {
    DEBUG ((DEBUG_INFO, "\nThe Stack %d is not in CXL mode!", Stack));
    return EFI_UNSUPPORTED;
  }
  
  // 获取设备 DeviceCapability
  Status = CxlDeviceDvsecRegisterAccess (Socket,
                                         Stack,
                                         OFFSET_OF (CXL_2_0_DVSEC_FLEX_BUS_DEVICE, DeviceCapability),
                                         UsraWidth16,
                                         CxlOperationRead,
                                         &CxlDevCap20.Data16
                                         );

  if(Status != EFI_SUCCESS){
    DEBUG ((DEBUG_ERROR, "\n Failed to read the CXL device's Capability register!\n"));
    return EFI_NOT_FOUND;
  }

  //
  // Check if it needs to check the CXL cache capability
  // 检查是否支持 .cache 能力
  if ((CxlProtocolList & CXL_PROTOCOL_CACHE_TYPE) != 0) {
    if (CxlDevCap20.Bits.CacheCapable == 0) {
      DEBUG ((DEBUG_ERROR, "\nThe CXL device in CXL port %d doesn't support CXL.$!", Stack));
      return EFI_UNSUPPORTED;
    }
  }

  //
  // Check if it needs to check the CXL memory capability
  // 检查是否支持 .mem 能力
  if ((CxlProtocolList & CXL_PROTOCOL_MEM_TYPE) != 0) {
    if (CxlDevCap20.Bits.MemCapable == 0) {
      DEBUG ((DEBUG_ERROR, "\nThe CXL device in CXL port %d doesn't support CXL.M!", Stack));
      return EFI_UNSUPPORTED;
    }
  }

  RcrbBarBase = (UINT32) GetRcrbBar (Socket, Stack, TYPE_CXL_RCRB);
  if (RcrbBarBase == 0) {
    CxlAccessInfo->CxlPortRcrbBar = 0;
    CxlAccessInfo->CxlDevPcieAddress = 0;
    CxlAccessInfo->CxlDevCompRegAddress = 0;
    return EFI_UNSUPPORTED;
  }
  // 获取 RCRB 基地址
  CxlAccessInfo->CxlPortRcrbBar = RcrbBarBase;

  CxlDevBus = GetCxlDownstreamBus (Socket, Stack, (SECBUS_IIO_PCIE_G5_REG & 0xFFFF));
  if (CxlDevBus == 0) {
    CxlAccessInfo->CxlDevPcieAddress = 0;
    CxlAccessInfo->CxlDevCompRegAddress = 0;
    return EFI_UNSUPPORTED;
  }

  //
  // Point to the CXL device's pci configuration space offset 0 (VID field)
  // 获取 PEIe 基地址
  GenerateBasePciePhyAddress (Socket, CxlDevBus, CXL_DEV_DEV, CXL_DEV_FUNC, \
                              UsraWidth32, &CxlDevUsraAddress);
  CxlDevUsraAddress.Pcie.Offset = PCI_VENDOR_ID_OFFSET;
  CxlAccessInfo->CxlDevPcieAddress = GetRegisterAddress (&CxlDevUsraAddress);

  //
  // Get the CXL device component register BAR
  // 对于 CXL2.0 社设备获取 component register 基地址
  CxlAccessInfo->CxlDevCompRegAddress = (UINTN)GetCxlRegisterBlockBaseAddress (Socket, CxlDevBus, CXL_DEV_DEV, CXL_DEV_FUNC, RL_REG_BLK_ID_COMP_REGS);

  return EFI_SUCCESS;
}

```

### 22. ProgramPciCommandRegister()

- 在CXL DP/UP RCRB 中设置 PCI CMD 寄存器，使能/失能 MMIO 空间。

### 23.  CxlDvsecRegRead()

- 该函数从 DVSEC 寄存器块中读寄存器。设备由 SBDF 定位识别，可能由多个DVSEC 能力寄存器块。每一个块由 DVSEC ID 区分，每一个寄存器块包含一组寄存器，规范中定义了。

```c

/**
  CxlDvsecRegRead reads register from CXL-device's dvsec register blocks. The CXL device is
  identified by Socket, Bus, Device and Function numbers. CXL devices may have multiple DVSEC
  capability register blocks. Each block is identified with Dvsec ID. Each register block
  contains bunch of registers that are located using offset as defined in CXL spec.
  It is callers responsibilty to provide accurate device and register information to read
  the register. Data is returned to the caller in the given data buffer pointer.
  The last parameter conveys number width of data read request.

  Note: Device(s) - In this context, devices refers to both end point and bridge devices
                    since both type of devices has DVSEC, this service can be used
                    regardless of end point or bridge
					
					设备被视为 EP 和 桥设备，他们都有 DVSEC。不管是 EP 还是桥都可以使用此服务。
  Usage Guidance:
        - For UsraWidth32 read operation, ensure the address to be read is Dword aligned  4字节对齐
        - For UsraWidth16 read operation, ensure the address to be read is Word aligned   2字节对齐
        - For UsraWidth8 read operation, no address alignment required                    不用对齐

  @param[in]    SocketId          Socket number under which the device is located
  @param[in]    Bus               PCI bus number
  @param[in]    Device            PCI device number
  @param[in]    Function          PCI function number to be configured
  @param[in]    DvsecId           Dvsec ID [Eg: 3, 7, 0 and so on]
  @param[in]    CapRegBlockOffset Offset of register with in DvsecBlock Eg: 0x10 is the offset
                                  to Alternate Memory Base in Dvsec ID 3. Pass 0x10 to this field
  @param[in out]Data *            On Input, pointer to buffer to store register value
                                  On Output, value of the register
  @param[in]    AccessWidth       Usra defined access width

  @retval       EFI_STATUS        Status returned from Register read API
                                  EFI_INVALID_PARAMETER callers input is not correct
                                    Socket, Device or Function input is invalid
                                  EFI_NOT_FOUND Dvsec Id is not available
**/
EFI_STATUS
CxlDvsecRegRead (
  IN  UINT8   Socket,
  IN  UINT8   Bus,
  IN  UINT8   Device,
  IN  UINT8   Function,
  IN  UINT8   DvsecId,
  IN  UINT8   CapRegBlockOffset,
  OUT VOID    *Data,
  IN  USRA_ACCESS_WIDTH   AccessWidth
  )
{
  USRA_ADDRESS        PciAddress;
  EFI_STATUS          Status;

  if (Socket >= MAX_SOCKET || Device > 31 || Function > 7) {
    DEBUG ((DEBUG_ERROR, "Invalid device information Check Socket:%d-Dev:%d-Func:%d\n", Socket, Device, Function));
    return EFI_INVALID_PARAMETER;
  }

  // 通过 SBDF 得到 PCIe 物理地址 
  GenerateBasePciePhyAddress (Socket, Bus, Device, Function, UsraWidth32, &PciAddress);
  CXL_DEBUG_LOG ("\t\t\tAddress To search for Dvsec = %X in Seg %x\n", PciAddress.dwRawData[0], Socket);

  // 找到　DvsecId　指定的 DVSEC　偏移
  PciAddress.Pcie.Offset = FindCxlDvsecCapability (
    &PciAddress,
    DvsecId
    );

  if (PciAddress.Pcie.Offset == 00) {
    CXL_DEBUG_LOG ("\t\t\tDvsec %d is not present in Bus:%X-Dev:%X-Fun:%X 4K PCI config space\n",\
                    DvsecId, Bus, Device, Function);
    return EFI_NOT_FOUND;
  }

  CXL_DEBUG_LOG ("\t\t\tDvsec %x located in offset %X\n", DvsecId, PciAddress.Pcie.Offset);
  PciAddress.Attribute.AccessWidth = AccessWidth;
  PciAddress.Pcie.Offset += CapRegBlockOffset;
  
  // 寄存器讀操作
  Status = RegisterRead (&PciAddress, Data);

  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "\t%r error while reading %X add\n", Status, PciAddress.dwRawData[0]));
  }  else {
    // 成功，日志打印
    switch (AccessWidth) {
      case UsraWidth8:
        CXL_DEBUG_LOG ("\t\t\tValue %X Read from Add %X\n", *(UINT8 *)Data, PciAddress.dwRawData[0]);
        break;
      case UsraWidth16:
        CXL_DEBUG_LOG ("\t\t\tValue %X Read from Add %X\n", *(UINT16 *)Data, PciAddress.dwRawData[0]);
        break;
      case UsraWidth32:
        CXL_DEBUG_LOG ("\t\t\tValue %X Read from Add %X\n", *(UINT32 *)Data, PciAddress.dwRawData[0]);
        break;
      default:
        CXL_DEBUG_LOG ("\t\t\tInvalid Access Width\n");
    }
  }
  return Status;
}

```

### 24. CxlDvsecRegWrite()

- DVSEC 寄存器块中的寄存器写操作，与前一个读基本一致；

### 25. CxlDvsecRegAndThenOr()

- 调用 CxlDvsecRegRead() -> 与or或数据 -> CxlDvsecRegWrite(),执行 DVSEC 寄存器位操作；

### 26. GetCxlPortType()
![请添加图片描述](https://img-blog.csdnimg.cn/87ca8c79f2014a4db152a825cdd234b9.png)
- 确定给定的设备是 CXL2.0 还是 CXL1.1 设备，不是CXL设备返回 NON-CXL.

```c 

/**
  GetCxlPortType finds whether given pci device is a cxl2p0 or cxl11 device. For non-CXL
  devices, it returns NON-CXL

  @param[in]    SocketId          Socket number under which the device is located
  @param[in]    Bus               PCI bus number
  @param[in]    Device            PCI device number
  @param[in]    Function          PCI function number

  @retval PortType Value: Meaning
                      02: CXL20
                      01: CXL11
                      FF: Non-CXL Port
**/
UINT8
GetCxlPortType (
  IN  UINT8 SocketId,
  IN  UINT8 Bus,
  IN  UINT8 Device,
  IN  UINT8 Function
  )
{
  UINT8                                           PortType;
  UINT8                                           CapRegBlockOffset;
  EFI_STATUS                                      Status;
  PCI_EXPRESS_DESIGNATED_VENDOR_SPECIFIC_HEADER_1 DvsecHeader1;

  PortType = UNKNOWN_PORT;
  CapRegBlockOffset = 00;
  CXL_DEBUG_LOG ("\t%a for Soc %d, Bus %x, Dev %x, Fun %d\n", __FUNCTION__, SocketId, Bus,\
                  Device, Function);
  CapRegBlockOffset = OFFSET_OF(CXL_2_0_DVSEC_FLEX_BUS_PORT, DesignatedVendorSpecificHeader1);
  // 读 CXL_FLEX_BUS_PORT_DVSEC 寄存器 DesignatedVendorSpecificHeader1
  Status = CxlDvsecRegRead (SocketId, Bus, Device, Function, CXL_FLEX_BUS_PORT_DVSEC,\
                            CapRegBlockOffset, &DvsecHeader1.Uint32, UsraWidth32);
  CXL_DEBUG_LOG ("\t\tValue of Dvsec 7 Header1 (Offset: %x) = %X\n", CapRegBlockOffset,\
                  DvsecHeader1.Uint32);

  if (EFI_ERROR(Status)) {
    CXL_DEBUG_LOG ("\t\t%r returned by CxlDvsecRegRead\n", Status);
    PortType = UNKNOWN_PORT;
    return PortType;
  }

  CXL_DEBUG_LOG ("\t\tDvsec ID 7 VenId = %x\n\t\tRevision = %x\n",\
                  DvsecHeader1.Bits.DvsecVendorId, DvsecHeader1.Bits.DvsecRevision);
  CXL_DEBUG_LOG ("\t\tThis is %s port\n", (DvsecHeader1.Bits.DvsecRevision == 1? L"CXL20": L"CXL11"));

  // ref CXL 2.0 Table 140. PCI Express DVSEC Header Registers Settings for Flex Bus Port
  if (DvsecHeader1.Bits.DvsecRevision == 1) {
    PortType = CXL20_PORT;
  }  else {
    PortType = CXL11_PORT;
  }
  return PortType;
}

```

### 27. GetCxl20PortOperatingMode()
![请添加图片描述](https://img-blog.csdnimg.cn/198a8e75d34b49a68fd5d2a6aad43ab5.png)

- 确定 CXL2.0 端口的工作模式。如果给定设备不是 CXL2.0 端口，则返回未知模式。这个用在调用者需要知道2.0端口是工作在2.0模式还是1.1模式。 

```c 

/**
  GetCxl20PortOperatingMode finds CXL 20 port's operating mode. if the given device is
  not CXL20 port, Unknown mode is returned. This can be used in a situation where the caller
  needs to be know if the CXL20 port is operating in 20 or 11 mode

  Prerequisite: This function assumes the given port is CXL20 port.

  @param[in]    SocketId          Socket number under which the device is located
  @param[in]    Bus               PCI bus number
  @param[in]    Device            PCI device number
  @param[in]    Function          PCI function number

  @retval PortType Value: Meaning
                      02: CXL20 Mode
                      01: CXL11 Mode
                      FF: Non-Cxl2p0 Port
**/
UINT8
GetCxl20PortOperatingMode (
  IN  UINT8   SocketId,
  IN  UINT8   Bus,
  IN  UINT8   Device,
  IN  UINT8   Function
  )
{
  UINT8                               Data8;
  UINT8                               CapRegBlockOffset;
  EFI_STATUS                          Status;
  CXL_2_0_DVSEC_FLEX_BUS_PORT_STATUS  PortStatusReg;

  CXL_DEBUG_LOG ("\t%a for Soc %d, Bus %x Dev %x Fun %d\n",\
                  __FUNCTION__, SocketId, Bus, Device, Function);
  CapRegBlockOffset = OFFSET_OF(CXL_2_0_DVSEC_FLEX_BUS_PORT, PortStatus);
  
  // 读 CXL_2_0_DVSEC_FLEX_BUS_PORT 寄存器 PortStatus 值
  Status = CxlDvsecRegRead (SocketId, Bus, Device, Function, CXL_FLEX_BUS_PORT_DVSEC, CapRegBlockOffset,\
                            &PortStatusReg.Data16, UsraWidth16);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "\tNon Cxl 20 port. Do not check operating mode\n"));
    return 0xFF;
  }

  // CXL2p0_Enabled 如果为1表明 CXL2.0 协议已经使能
  // ref CXL 2.0 8.2.1.3.3 DVSEC Flex Bus Port Status (Offset 0Eh)
  if (PortStatusReg.Bits.Cxl2p0Enable == 0) {
    Data8 = CXL11_MODE;
  } else {
    Data8 = CXL20_MODE;
  }
  CXL_DEBUG_LOG ("\tCxl20 port is operating in %s\n", (PortStatusReg.Bits.Cxl2p0Enable)?L"CXL2p0":L"CXL11");

  return Data8;
}

```

### 28. RcrbDvsecRegBlockRead()

- 读 DVSEC 块寄存器的值。找到寄存器偏移 -> RCRB 读寄存器；

### 29. RcrbDvsecRegBlockWrite()

- 写　DVSEC　块寄存器。

### 30. RcrbDvsecRegBlockAndThenOr()

- DVSEC　块寄存器的位操作： AndData32\OrData32

### 31. GetCxlRegisterBlockBaseAddress()
![请添加图片描述](https://img-blog.csdnimg.cn/3d801138f4e144b193da8eb17215ea38.png)

- 返回 CXL 寄存器块的基地址。CXL 设备由不同种类的寄存器块，比如组件寄存器、BAR 虚拟ACL 寄存器等。Refer: CXL 2.0 spec rev 1.0 section 8.1.9 

```c

/**
  GetCxlRegisterBlockBaseAddress returns CXL register block base address. CXL devices has
  different kinds of register blocks. Say Components Registers, BAR Virtualization ACL Registers
  and so on. Refer: CXL 2.0 spec rev 1.0 section 8.1.9

  @param[in]  Socket            Socket number under which the device is located
  @param[in]  Bus               PCI bus number
  @param[in]  Device            PCI device number
  @param[in]  Function          PCI function number
  @param[in]  RegBlockId        Register Block ID
                                  00 - Invalid Id/Empty Register Block
                                  01 - Component Registers
                                  02 - BAR Virtualization ACL Registers
                                  03 - CXL Memory Devices
                                  04 - 255 - Invalid

  @retval     Register Block's Base Address
**/
UINT64
GetCxlRegisterBlockBaseAddress (
  IN  UINT8   Socket,
  IN  UINT8   Bus,
  IN  UINT8   Device,
  IN  UINT8   Function,
  IN  UINT8   RegBlockId
  )
{
  UINT8       i;
  UINT8       NumberOfRegBlocks;
  UINT8       BarOffset;
  UINT32      HighBarOffset;
  EFI_STATUS  Status;
  UINT32      Data32;
  UINT64      RegBlockBaseAddress;
  USRA_ADDRESS        PciAddress;
  PCI_EXPRESS_DESIGNATED_VENDOR_SPECIFIC_HEADER_1  Header;
  CXL20_REGISTER_LOCATOR_DVSEC_REGISTER_BASE_LOW RegBlockOffsetLow;

  RegBlockBaseAddress = 0;
  CXL_DEBUG_LOG ("\t\t\tRead Register Block Id %d for Device Seg: %x, Bus: %x, Dev%x, Fun:%x\n",\
                    RegBlockId, Socket, Bus, Device, Function);
  // 要返回的 Register Block ID 参数范围检查，只能位 1，2，3
  if (RegBlockId == 00 || RegBlockId > 3) {
    CXL_DEBUG_LOG ("\t\r\rIncorrect Block Id = %d - Exit without reading Bar\n", RegBlockId);
    return RegBlockBaseAddress;
  }
  
  //
  //Read DVSEC length
  // 读 CXL_REGISTER_LOCATOR_DVSEC 寄存器
  // 其中参数：CXL_REGISTER_LOCATOR_DVSEC 指定DVSEC; 0x4 : 寄存器偏移，读Header1；存入 Header.Uint32
  
  Status = CxlDvsecRegRead (Socket, Bus, Device, Function, CXL_REGISTER_LOCATOR_DVSEC,
                            0x04, &Header.Uint32, UsraWidth32);
  if (EFI_ERROR(Status)) {
    CXL_DEBUG_LOG ("\t\t\t%r error while reading Register Locator Dvsec register block\n");
    return RegBlockBaseAddress;
  }

  GenerateBasePciePhyAddress (Socket, Bus, Device, Function, UsraWidth32, &PciAddress);
  
  // The DVSEC Length field must be set to h (0Ch+ n * 8) bytes to accommodate the registers included in the DVSEC, where n is the number of Register Blocks described by this Capability. The DVSEC ID must be set to 08h to advertise that this is a CXL 2.0 Register Locator DVSEC capability structure.
  // ref CXL 2.0 spec Figure 131. Register Locator DVSEC with 3 Register Block Entries
  // 减掉前面的长度 0xC，每个寄存器 Offset 占用8字节
  NumberOfRegBlocks = (UINT8)(Header.Bits.DvsecLength - 0xC) / 8;
  CXL_DEBUG_LOG ("\t\t\tNumberOfRegBlocks = %d\n", NumberOfRegBlocks);

  for (i = 0; i < NumberOfRegBlocks; i++) {
  
    // 遍历寄存器地址信息 Register Block Low Offset
    BarOffset = OFFSET_OF(CXL_2_0_REGISTER_LOCATOR_DVSEC, RegisterBaseLowRegisterBlock1) + i * 8;
	
	// 读 Register Offset Low 内容
    Status = CxlDvsecRegRead (Socket, Bus, Device, Function, CXL_REGISTER_LOCATOR_DVSEC,
                              BarOffset, &RegBlockOffsetLow.Data32, UsraWidth32);
    if (EFI_ERROR (Status)) {
      CXL_DEBUG_LOG("\t\t\t%r error while reading Register Locator Dvsec register block\n");
      return RegBlockBaseAddress;
    }

    // BlockIdentifier要匹配， RegisterBIR 要合法： 0 - 5 6个BAR
	
    if (RegBlockOffsetLow.Bits.RegisterBlockIdentifier == RegBlockId && RegBlockOffsetLow.Bits.RegisterBIR < 6) {
      
	  // ref CXL 2.0 spec 8.1.9.1 Register Offset Low (Offset Varies)
	  // Register BIR - Indicates which one of a Function's Base Address Registers, located beginning at 10h in Configuration Space
	  // Register Block Identifier - Identifies the type of CXL registers.
	  // 计算偏移，从 0x10 开始，bar0 位于 0x10
	  
	  PciAddress.Pcie.Offset = 0x10 + (RegBlockOffsetLow.Bits.RegisterBIR * 4);
	  // 读出块寄存器基地址, BAR 寄存器只存储一个地址
      Status = RegisterRead(&PciAddress, &Data32);
      if (EFI_ERROR (Status)) {
        CXL_DEBUG_LOG ("\t\t\t%r error while reading Register Pci Bar (low 32 bits)\n", Status);
        return RegBlockBaseAddress;
      }
	  // regBlock 基地址
      RegBlockBaseAddress = (UINT64)(Data32 & ~0xF);  // Clear out BAR register attributes field

      if ((Data32 & 0x7) == 0x4) {
	    // BAR 空间数据低位解析： 2:1 -> 00 : 32bit decoding 10 : 64bit decoding;  0 -> 0 : Memory request 1 : IO request
        // 
        // 64-bit MMIO BAR
        // 把地址高位读出来
        PciAddress.Pcie.Offset += 4;
        Status = RegisterRead(&PciAddress, &Data32);
        if (EFI_ERROR (Status)) {
          CXL_DEBUG_LOG ("\t\t\t%r error while reading Register Pci Bar (high 32 bits)\n", Status);
          return RegBlockBaseAddress;
        }
		// 组合成64位地址
        RegBlockBaseAddress |= LShiftU64 ((UINT64) Data32, 32);
      }

      // 计算出基地址之后，寄存器块可能在这一块空间的某一处开始，有一个偏移，需要将这个偏移加上；偏移记录在 DVSEC 中
      // Read High Offset
      Status = CxlDvsecRegRead (Socket, Bus, Device, Function, CXL_REGISTER_LOCATOR_DVSEC,
                              BarOffset + 4, &HighBarOffset, UsraWidth32);
      if (EFI_ERROR (Status)) {
        CXL_DEBUG_LOG("\t\t\t%r error while reading Register Locator Dvsec register block\n");
        return RegBlockBaseAddress;
      }
	  // 基地址加上高低64位偏移，得出最后的寄存器块起始地址
      RegBlockBaseAddress += LShiftU64(HighBarOffset, 32);
      RegBlockBaseAddress += RegBlockOffsetLow.Data32 & 0xFFFF0000;
      break;
    }
  }
  return RegBlockBaseAddress;
}

```
![请添加图片描述](https://img-blog.csdnimg.cn/f60a2b46105c4ce882eff887c1cc2ca6.png)
![请添加图片描述](https://img-blog.csdnimg.cn/2fb626b9ac6647aea880a308fbcb8794.png)

### 32. GetCxlCacheMemCapIdBase()
![请添加图片描述](https://img-blog.csdnimg.cn/840cdda9ebcc4856ab422286ffb9c95b.png)

- 在 cache and mem sub system component register block 中得到 capability 的基地址

```c 

/*
  GetCxlCacheMemCapIdBase function gets base address of capability in cache and mem
  sub system component register block.
  It takes Cache Mem component register base as input to look for CapId.

  @param[in]    CacheMemBase  BaseAddress where cache and mem comp registers are located
  @param[in]    CacheMemBase  Capability Id to locate

  @retval       BaseAddress   Mmio Base address of CapId
                              00 CapId not found or invalid input
*/
UINT64
GetCxlCacheMemCapIdBase (
  IN  UINTN   CompRegCacheMemBase,
  IN  UINT16  CapId
  )
{
  CXL_2_0_CXL_CAP_HEADER_REG      CxlCapHeader;
  CXL_2_0_CXL_CAP_GENERIC_HEADER  CxlCapGenHeader;
  UINT8 Index;

  // 首先检查两个参数是否合法， CompRegCacheMemBase 基地址合法
  if ((CompRegCacheMemBase == 00 || CompRegCacheMemBase == 0xFFFFFFFF)) {
    DEBUG ((DEBUG_ERROR, "Invalid Input Base Address = %x\n", CompRegCacheMemBase));
    return 0x00;
  }
  
  // CapId 不能大于 8 
  if (CapId >= CxlCompMaxCap) {
    DEBUG ((DEBUG_ERROR, "Invalid Input CapId=%x\n", CapId));
    return 0x00;
  }

  //
  // Read CXL Cap Register Header. This is the first Cap register and it's Id must be 1
  // 读 CXL Capability Header Register, 第一个寄存器， Capability_ID 等必须为 1
  // ref CXL 2.0 8.2.5.1 CXL Capability Header Register (Offset 0x0)
  CxlCapHeader.Data32 = MmioRead32 (CompRegCacheMemBase);
  if ((CxlCapHeader.Bits.CxlCapId != 0x01) || \
      (CxlCapHeader.Bits.CxlCapVer != 0x01) || \
      (CxlCapHeader.Bits.CxlCacheMemVer != 0x01)) {
    DEBUG ((DEBUG_ERROR, "\t\t\t%X Invalid Cxl Comp Register block\n", CompRegCacheMemBase));
    return 00;
  } else {
    // 返回第一个寄存器的地址, 就是首地址
    if (CapId == CxlCapHeader.Bits.CxlCapId) {
      return CompRegCacheMemBase;
    }
  }

  Index = 1;
  // 从 1 开始 遍历，跳过 CXL_Capability_Header 计算地址
  // Each element is 1 DWORD in size and is located contiguous with previous elements
  // 元素连续，ArraySize 表示元素数量，不包含 CXL_Capability_Header，每个元素 4 个字节
  while(Index <= CxlCapHeader.Bits.ArraySize) {
    CxlCapGenHeader.Data32 = MmioRead32 (CompRegCacheMemBase + Index * 4);
    if (CapId == CxlCapGenHeader.Bits.CxlCapId) {
	  // 匹配成功，CxlCapPtr 表示相对于起始地址的偏移，加上返回即可
      CompRegCacheMemBase += CxlCapGenHeader.Bits.CxlCapPtr;
      return CompRegCacheMemBase;
    }
    Index ++;
  }
  return 0x00;
}

```

![请添加图片描述](https://img-blog.csdnimg.cn/a24a249f97554f949ae3718fed059b7e.png)
![请添加图片描述](https://img-blog.csdnimg.cn/d3f09e72baec4c33ab9a865b44d1bc32.png)

### 33. GetCxlCacheMemCompSubSysCapBasegBdf()

- 该函数使用 BDF 从 cache and mem subsystem component register block 中得到 capability 基地址；
- 调用 GetCxlRegisterBlockBaseAddress() 得到组件寄存器块基地址 -> 得到基地址加4K -> 使用地址与 GetCxlCacheMemCapIdBase() 得到 capabilities 基地址。

### 34. GetCxlSubSysCacheMemCompRegRcrb()
![请添加图片描述](https://img-blog.csdnimg.cn/0e8b4b5560c6461d95a4b2a79ce5c7eb.png)

- CXL 1.1 组件寄存器位置由 64位 MEMBAR0 寄存器指定，在 RCRB 0x10和 0x14处；与前一个函数相比，就是组件寄存器首地址获取方式不一样；
- 从 CacheMem comp register block 得到特定 capabilities 寄存器块基地址；

### 35. ConfigureSecComp()
![请添加图片描述](https://img-blog.csdnimg.cn/bef51bdd44894499adf2b729dc1291ce.png)

- 配置CXL 设备的可信级别，由 BIOS 设置自定义

### 36. ConfigureCxlCompRegsRcrb()

- 配置组件寄存器，目前只有设备可信级别
- 获取寄存器基地址方式从 RCRB 获取，适用于 CXL1.1 设备

```c

/*
  ConfigureCxlCompRegsRcrb configures CXL1.1 USP and DSP component registers using
  Rcrb Base address. CXL component registers (Refer: CXL 2.0 spec Revsion 0 Section: 8.2.3)
  are sub divided into multiple subsystem component registers. This function targetted to
  configure all subsystem registers. Currently .cache and .mem registers' security level
  is configured. When the scope is extended, header should be updated to reflect new scope.
  GetCxlSubSysCacheMemCompRegRcrb function used to get particular capability from cahe and mem
  sub component registers. Each capabailty is identified using Capability ID. This function takes
  cap Id as input to get capabilities base address. Refer CXL_COM_REG_CAP_ID enum for cap Id
  definitions.

  @param [in]   *KtiInternalGlobal
  @param [in]   RcrbBase            RcrbBase address of CXL 1.1 USP or DSP

  @retval       None
*/
VOID
ConfigureCxlCompRegsRcrb (
  IN  KTI_HOST_INTERNAL_GLOBAL  *KtiInternalGlobal,
  IN  UINT32  RcrbBase
  )
{
  UINT8   CxlSecLvl;
  UINT32  BaseAddress;

  CxlSecLvl = CXL_SECURITY_FULLY_TRUSTED;
  // CXL_SECURITY_AUTO=3
  if (KTISETUP->DfxParm.DfxCxlSecLvl < CXL_SECURITY_AUTO) {
    // 获取安全级别
    CxlSecLvl = KTISETUP->DfxParm.DfxCxlSecLvl;
  }
  // 得到 CxlCompSecCap=3 的基地址
  BaseAddress = (UINT32)GetCxlSubSysCacheMemCompRegRcrb (RcrbBase, CxlCompSecCap);
  CXL_DEBUG_LOG ("\t\t\tSec cap Base Address = %X\n", BaseAddress);
  if(BaseAddress == 0) {
    CXL_DEBUG_LOG ("\t\t\tNo Cxl Sec Comp Regs\n");
    return;
  }
  // 调用上一个函数进行安全配置
  ConfigureSecComp (BaseAddress, CxlSecLvl);
}

```


### 37. ConfigureCxlCompRegsBDF()

- 与上一个函数功能相同，只有获取寄存器基地址方式不同，使用 BDF 访问设备，遍历DVSEC，寻找组件寄存器；适用于 CXL 2.0 设备；

### 38. IsCxl20DevOpInCxl11Mode()

- 常规确认是否是 2.0设备工作在 1.1 模式下；

```c

/**
  Routine to determin if it is a CXL 2.0 device operating in 1.1 Mode.

  @param[in]  Socket              Socket Index
  @param[in]  Stack               Stack number

  @retval TRUE    - It is a CXL 2.0 device operating in 1.1 Mode.
  @retval FALSE   - It is NOT a CXL 2.0 device operating in 1.1 Mode.
**/
BOOLEAN
EFIAPI
IsCxl20DevOpInCxl11Mode (
  IN  UINT8                     Socket,
  IN  UINT8                     Stack
  )
{
  UINT32          RcrbBaseAddr;

  // 得到 DP RCRB 基地址
  RcrbBaseAddr = (UINT32) GetRcrbBar (Socket, Stack, TYPE_CXL_RCRB);
  ASSERT (RcrbBaseAddr != 0);
  // UP RCRB 基地址
  RcrbBaseAddr += CXL_RCRB_BAR_SIZE_PER_PORT;

  //
  // Workaround for Reynolds Rock A0, do 2 accesses to RCRBBAR space in all cases and treat the 2nd access as reliable.
  //
  MmioRead32 (RcrbBaseAddr);

  //If the return data is all 1, assume this is a CXL 2.0 device operating in 1.1 mode
  if (MmioRead32 (RcrbBaseAddr) == 0xFFFFFFFF) {
    return TRUE;
  } else {
    return FALSE;
  }
}

```

## 参考
- Compute Express Link Specification Revision 2.0
- PCI_Express_Base_5.0r1.0
