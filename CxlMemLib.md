@[toc]

## 1. CDAT 介绍
Coherent Device Attribute Table (CDAT)
### 1.1. 背景
>Compute Express Link (CXL) and other industry standard coherent interconnects enable coherent switches, coherent memory devices or coherent accelerator devices to be attached to one or more processors. The systems containing such devices are heterogenous in nature and system software needs to understand the topology and affinity information in order to optimize resource assignment. In modern systems, the System Firmware communicates this information to the Operating System via static ACPI Tables such as SRAT and HMAT. SRAT ACPI table describes various NUMA domains in a system including host processors, accelerators, and memory. HMAT ACPI table describes bandwidth and latency from any initiator (a processor or an accelerator) to any memory target. SRAT and HMAT are constructed by system firmware or pre-boot environment. 

包含 CXL 设备的系统本质上是异构的，并且系统软件需要了解拓扑和亲和信息以优化资源分配。 在现代系统，系统固件通过静态例如 SRAT 和 HMAT 等 ACPI 将此信息传递给操作系统。 SRAT ACPI 表描述了系统中的各种 NUMA 域，包括主机处理器、加速器和内存。 HMAT ACPI 表描述了来自任何启动器（处理器或加速器）的带宽和延时。SRAT和HMAT由系统固件或预引导环境构建。


>Prior to emergence of these coherent interconnects, the processors were the sole coherent components in the system. System firmware could be expected to have apriori knowledge of performance attributes of the processors and by extension could construct SRAT and HMAT. That assumption is no longer a valid for systems with these coherent interconnects. Often, these systems are constructed using coherent devices and switches from multiple vendors. Having the system firmware keep track of performance properties of multiple components from various vendors can be impractical.would be needed to deal with a new type of device. Furthermore, some coherent interconnects allow dynamic addition or removal of devices and switches, thus making it even more challenging for system software to gather the performance information. 

在这些一致性互连出现之前，处理器是系统中唯一的一致性组件。系统固件可以期望具有性能属性的先验知识处理器和扩展可以构建 SRAT 和 HMAT。 对于具有这些一致性互连的系统来说，这个假设不再有效。 通常，这些系统是用来自多个供应商的一致性设备和 switches 构造的。 让系统固件跟踪来自不同供应商的多个组件的性能属性是不切实际的。需要一个新的系统固件升级去解决这一类设备。此外，一些一致性互联设备云允许动态添加和移除设备和 switches， 因此，系统软件手机这些性能信息很有挑战性。

> Coherent Device Attribute Table (CDAT) is introduced to address this challenge. CDAT is a data structure that is exposed by a coherent component and describes the performance characteristics of these components. The types of components include coherent memory devices, coherent accelerators, and coherent switches. For example, CXL accelerators may expose its performance characteristics via CDAT. CDAT describes the properties of the coherent component and is not a function of the system configuration. 

因此，引入了一致性设备属性表 (CDAT) 来应对这一挑战。CDAT是一种数据结构，它由一个一致性组件暴漏出来，并描述了这些组件的性能特征。组件的类型包括一致性存储设备、一致性加速器以及一致性 switches。 例如，CXL 加速器可能会通过 CDAT 暴露其性能特征。CDAT 描述了一致性组件的属性，而不是系统配置的功能。

### 1.2. CDAT Discovery
> CDAT structures can be discovered and extracted from devices or switches either during boot (by the system firmware), or after boot (by the OS).


### 1.3. 定义
- Device physical address (DPA)， 设备中相关的内存地址。系统软件负责配置映射 DPA 到系统物理地址 (SPA)。 DPA=0 表示应谁的内存位置位于最低 SPA, DPA=(Device Capacity - 1) 表示设备内存地址映射到高 SPA 空间。
  
- Device Scoped Memory Affinity Domain (DSMAD) ， 是一个由统一的内存属性的连续的 DPA 区域，软件应将其视为不同的内存邻近域  proximity domain。

- A coherent memory device is modelled as one having， One or more DSMADs.
- A coherent accelerator is modelled as one having, One or more Generic Initiators; Zero or more DSMADs.
- A coherent switch

![请添加图片描述](https://img-blog.csdnimg.cn/a88a70ccae984174a57064c16e4e4639.png)

### 1.4. Structure Type
#### 1.4.1 Device Scoped Memory Affinity Structure (DSMAS)

> Device Scoped Memory Affinity Structure (DSMAS)
DSMAS structure is used to return DPA range associated with each DSMAS and its attributes. The number of instances of DSMAS shall equal the number of DSMAD.

- DSMAS 用来返回与每个 DSMAS 相关的 DPA 范围和属性。 DSMAS 实例的数量应该和 DSMAD 的数量相等。

![DSMAS](https://img-blog.csdnimg.cn/5f78156311fd4832a3af438bf7532404.png)

#### 1.4.2 Device Scoped EFI Memory Type Structure (DSEMTS)

> Device Scoped EFI Memory Type Structure (DSEMTS)
DSEMTS structure is used to communicate the expected memory usage and any associated hints associated with different subranges of device memory. The number of DSEMTS ranges can exceed the number of DSMAS entries since DSMAS entries often represent hardware constructs and DSEMTS represent software usage. If a DPA range described by a DSMAS is not covered by any DSEMTS, the memory type is assumed to be EFI normal memory. DPA ranges covered by DSEMTS entries must not overlap and must fit within the DPA range associated with the associated DSMAS Handle.

- DSEMTS 这个结构体结构用于传达预期的内存使用情况以及与设备内存不同子范围任何相关的提示。DSEMTS 范围的数量可能超过 DSMAS 表项的数量，因为 DSMAS 表项通常代表硬件结构而 DSEMTS 代表软件使用情况。如果一个 DSMAS 描述的 DPA（Device physical address） 范围不能被任何 DSEMTS 覆盖，内存类型被假设为是一个 EFI normal memory。被 DSEMTS 表项覆盖的 DPA 范围一定不能重叠，并且必须适配与相关 DSMAS 句柄关联的 DPA 范围。
- 部分字段：
![请添加图片描述](https://img-blog.csdnimg.cn/417fa7b6c10c4a4aac69fb106a0c0a01.png)

#### 1.4.3 Device Scoped Initiator Structure (DSIS)

> DSIS structure is used to return the ACPI Initiators that are part of the device. The number of instances of DSIS shall equal the number of Initiators. The Initiator may be part of the same proximity domain as memory (Flags[0]=1) or it may be an initiator with no memory attached(Flags[0]=0).

- DSIS 结构体用来返回 ACPI Initiators, 设备的一部分。DSIS 实例的数量应该与 Initiators 数量相等。 Initiator 可能是和内存一样的域的一部分，或者它是一个没有内存的 initiator；
- SRAT gnenric initiators : 异构处理器和加速器、GPU 和 I/O 设备集成计算 或 DMA 引擎;

#### 1.4.4 Device scoped Latency and Bandwidth Information Structure (DSLBIS)

- 描述内存带宽和延时信息

![请添加图片描述](https://img-blog.csdnimg.cn/0f02bbd11e594906a88ad3ff199bf4ab.png)![请添加图片描述](https://img-blog.csdnimg.cn/e35ea025cf7a4b808f515c9016336320.png)
#### 1.4.5 Device Scoped Memory Side Cache Information Structure (DSMSCIS)

> This structure describes memory side caches that are internal to the coherent device. HMAT memory cache structure also includes the SMBIOS Type 17 handles that represents the memory side cache physical devices. When the system firmware constructs HMAT based on CDAT, it shall set the “Number of SMBIOS handles” field in these HMAT structure to be 0. This is because the memory side cache on a coherent device is not a FRU, and thus will not have a corresponding SMBIOS Type 17 records.

- 此结构描述了一致性设备内部的内存端缓存。 HMAT 内存缓存结构也包括代表内存端缓存物理设备的 SMBIOS 类型 17 handles。 系统固件在基于 CDAT 构建 HMAT 时，需要在这些 HMAT 结构中设置“Number of SMBIOS handles” 字段为 0。这是因为内存端缓存在一个一致性设备中不是一个 FRU，因此不会有相应的 SMBIOS 类型 17 记录。

![请添加图片描述](https://img-blog.csdnimg.cn/a13a34b83a044df2b4bd49ff2fe74c6e.png)

## 2. 函数解析
### 2.1. CxlMemCdat.c

#### 2.1.1 GetCdatStructHandle()
- 获取 CDAT 结构的 handle。**注意，没有 SSLBIS 的 handle!**

```c
/**
  This function gets the handle of CDAT structure. Note that there is no handle in the Switch
  Scoped Latency and Bandwidth Information Structure (SSLBIS).

  @param[in] StructPtr         Pointer to the CDAT structure.

  @return The handle of CDAT structure.
**/
UINT8
GetCdatStructHandle (
  IN VOID            *StructPtr
  )
{
  switch (((CDAT_STRUCT_HEADER *) StructPtr)->Type) {
  ...
  
  // SSLIBIS 返回无效 HANDLE
  case CDAT_TYPE_SWITCH_SCOPED_LATENCY_AND_BANDWIDTH_INFO_STRUCT:
  default:
    return INVALID_CDAT_HANDLE;
  }
}
```

#### 2.1.2. GetNextCdatStruct()

- 此函数从 CDAT 数据缓冲区获取下一个 CDAT 结构体。可以选择是否指定返回的下一个结构体的 type 和 handle。如果没有指定，会直接返回下一个结构体；如果没有指定前面的结构体 StructPtr，那么将放回第一个匹配的结构体；注意如果指定了 CdatHandle 参数, 那么不能发现 SSLBIS,因为 GetCdatStructHandle() 处理 SSLIBS 返回无效。

```c
/**
  This function gets the next CDAT structure from CDAT data buffer.

  It is optional to specify the type and/or handle of next CDAT structure to return. If there is no
  type or handle specified, then the next CDAT structure of any type or handle will be returned. If
  there is no previous structure specified, then the first matched CDAT structure of CDAT data buffer
  will be returned. Note that no CDAT SSLBIS can be found if there is a handle specified.

  @param[in]      HeaderPtr         Pointer to the header of CDAT data buffer.           缓冲区头部
  @param[in, out] StructPtr         In: Pointer to the previous structure or NULL.       作为参数输入，指定前面的结构体或者NULL
                                    Out: Pointer to the next structure to return or NULL.    作为输出，指定下一个结构体或者NULL;  
  @param[in]      CdatType          Pointer to the type of next CDAT structure to return (Optional).  可选，下一个结构体的类型
  @param[in]      CdatHandle        Pointer to the handle of next CDAT structure to return (Optional).  可选，洗一个结构体的 handle

  @retval EFI_SUCCESS               This function is executed successfully.
  @retval EFI_NOT_FOUND             No CDAT structure matches the requirement.
  @retval EFI_INVALID_PARAMETER     Some of input parameters are invalid.
**/
EFI_STATUS
GetNextCdatStruct (
  IN     VOID      *HeaderPtr,
  IN OUT VOID      **StructPtr,
  IN     UINT8     *CdatType,       OPTIONAL
  IN     UINT8     *CdatHandle      OPTIONAL
  )
{
  UINTN            NextStructPtr;
  UINT32           CdatLength;

  if ((HeaderPtr == NULL) || (StructPtr == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Locate the first or next CDAT structure. 定位第一个或者下一个结构体， 
  // 根据参数  StructPtr 是否指定了 previous structure
  CdatLength = ((COHERENT_DEVICE_ATTRIBUTE_TABLE_HEADER *) HeaderPtr)->Length;
  if ((*StructPtr != NULL) && (*StructPtr != HeaderPtr)) {
    NextStructPtr = (UINTN) *StructPtr + ((CDAT_STRUCT_HEADER *) *StructPtr)->Length;
  } else {
    NextStructPtr = (UINTN) HeaderPtr + sizeof (COHERENT_DEVICE_ATTRIBUTE_TABLE_HEADER);
  }

  //
  // Search for the CDAT structure of specified type and/or handle. 寻找下一个结构体 handle
  // 如果指定了 CdatType， 则进行比较；
  // 如果指定了 CdatHandle， 也进行比较，调用 GetCdatStructHandle() 获取下一个结构体 Handle, 处理 SSLIBS 返回无效
  while ((NextStructPtr > (UINTN) HeaderPtr) && (NextStructPtr < (UINTN) HeaderPtr + CdatLength)) {
    if (((CdatType == NULL) || (*CdatType == ((CDAT_STRUCT_HEADER *) NextStructPtr)->Type)) &&
        ((CdatHandle == NULL) || (*CdatHandle == GetCdatStructHandle ((VOID *) NextStructPtr)))) {
      *StructPtr = (VOID *) NextStructPtr;
      return EFI_SUCCESS;
    }

    NextStructPtr += ((CDAT_STRUCT_HEADER *) NextStructPtr)->Length;  // Move to the next structure.
  }
  //  没有发现
  return EFI_NOT_FOUND;
}
```

#### 2.1.3 CheckCxlCdatData()

- 此函数检查 CDAT 数据是否有效。原始数据会打印出来。

```c

/**
  This function checks whether the CXL CDAT data is valid. The raw data of CXL CDAT
  will be dumped for debug purpose regardless of whether the CXL CDAT data is valid.

  @param[in] SocketId              Socket index.
  @param[in] StackFwInst           Stack FW instance.
  @param[in] InstanceId            Logical instance index.
  @param[in] CxlEndDevInfo         Pointer to CXL end device data.

  @retval TRUE                     CXL CDAT data is valid.
  @retval FALSE                    CXL CDAT data is not valid.
**/
BOOLEAN
CheckCxlCdatData (
  IN UINT8                 SocketId,
  IN UINT8                 StackFwInst,
  IN UINT8                 InstanceId,
  IN CXL_END_DEVICE_INFO   *CxlEndDevInfo
  )
{
  VOID                     *CxlCdatPtr;
  CDAT_STRUCT_HEADER       *StructPtr;
  UINT32                   CdatLength;
  UINT8                    MemAffinityNum;
  UINT8                    InitiatorNum;
  UINT8                    EfiMemTypeNum;
  BOOLEAN                  IsStructNumValid;

  StructPtr = NULL;
  MemAffinityNum = 0;
  InitiatorNum = 0;
  EfiMemTypeNum = 0;
  IsStructNumValid = TRUE;
  // 获取 CDAT 指针
  CxlCdatPtr = GetCxlEndDevCdat (SocketId, StackFwInst, InstanceId);
  if (CxlCdatPtr == NULL) {
    RcDebugPrint (SDBG_MAX, "CXL: Socket %d Stack %d Instance %d, CDAT is not present\n", SocketId, StackFwInst, InstanceId);
    return TRUE;     // Nothing to check if there is no CDAT present.
  }

  //
  // Check the legnth of entire table.
  // 检查 CDAT 长度 在 0 - 0x400 之间
  CdatLength = ((COHERENT_DEVICE_ATTRIBUTE_TABLE_HEADER *) CxlCdatPtr)->Length;
  if ((CdatLength == 0) || (CdatLength > MAX_CDAT_LENGTH)) {
    RcDebugPrint (SDBG_MINMAX, "CDAT is invalid - the length of entire table is %d\n", CdatLength);
    return FALSE;
  }

  //
  // Dump the raw data of CXL CDAT buffer.
  //
  DisplayCxlCdatRawData (CxlCdatPtr);

  //
  // Entire table must sum to zero.
  // SUM 必须为 0
  if (CalculateCheckSum8 (CxlCdatPtr, CdatLength) != 0) {
    RcDebugPrint (SDBG_MINMAX, "CDAT is invalid - entire table doesn't sum to zero\n");
    return FALSE;
  }

  //
  // Traverse all structures of CXL CDAT.
  // 遍历所有结构体
  while (!EFI_ERROR (GetNextCdatStruct (CxlCdatPtr, (VOID **) &StructPtr, NULL, NULL))) {
    if (StructPtr->Length == 0) {
      RcDebugPrint (SDBG_MINMAX, "CDAT is invalid - the length of structure is 0\n");
      return FALSE;
    }

    if (StructPtr->Type == CDAT_TYPE_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT) {
      MemAffinityNum++;
    } else if (StructPtr->Type == CDAT_TYPE_DEVICE_SCOPED_INITIATOR_STRUCT) {
      // 如果 CDAT 中有 DSIS，DSIS 实例的数量应该与 Initiators 数量相等
      InitiatorNum++;
    } else if (StructPtr->Type == CDAT_TYPE_DEVICE_SCOPED_EFI_MEMORY_TYPE_STRUCT) {
      EfiMemTypeNum++;
    }
  }

  //
  // Check the number of structures for CXL type 1/2/3 device.
  //
  if ((MemAffinityNum > MAX_MEMORY_AFFINITY_STRUCTS) || (MemAffinityNum < CxlEndDevInfo->HdmCount)) {
    IsStructNumValid = FALSE;
  } else if ((InitiatorNum > MAX_INITIATOR_STRUCTS) || (EfiMemTypeNum > MemAffinityNum)) {
    IsStructNumValid = FALSE;
  } else if ((CxlEndDevInfo->HdmCount == 0) ^ (MemAffinityNum == 0)) {
    IsStructNumValid = FALSE;
  } else if ((CxlEndDevInfo->MemExpander) ^ (InitiatorNum == 0)) {
    // 如果设备是一个 MemExpander, 但是 Initiators 数量不为 0， 则结构体非法
    IsStructNumValid = FALSE;
  }

  if (!IsStructNumValid) {
    // CDAT 结构体非法, 返回错误
    RcDebugPrint (SDBG_MINMAX, "CDAT is invalid - the structure number is invalid: DSMAS %d, DSIS %d, DSEMTS %d\n",
      MemAffinityNum, InitiatorNum, EfiMemTypeNum);
    return FALSE;
  }

  //
  // Check if all CDAT structures have been traversed.
  // 根据长度，检查是不是所有结构体都遍历过了
  if ((UINTN) StructPtr + StructPtr->Length != (UINTN) CxlCdatPtr + CdatLength) {
    RcDebugPrint (SDBG_MINMAX, "CDAT is invalid - not all structures can be traversed\n");
    return FALSE;
  }

  return TRUE;
}

```

#### 2.1.4 GetCxlMemInfoFromCdat()

- 此函数在指定的设备中得到 CDAT, 然后获取指定 HDM Range 的内存信息。记录内存易失性和非易失性的大小；

```c

/**
  This function gets the information of CXL memory within the specified HDM range from the CDAT
  of the specified CXL end device.

  @param[in]      SocketId           Socket index.
  @param[in]      StackFwInst        Stack FW instance.
  @param[in]      InstanceId         Logical instance index.
  @param[in]      HdmRange           DPA range of HDM in 64MB granularity.    64MB 粒度 HDM 的 DPA 范围
  @param[in, out] CxlMemInfo         Pointer to the CXL memory information data.   内存信息缓冲区指针

  @retval EFI_SUCCESS                This function gets the information successfully.
  @retval EFI_NOT_FOUND              There is no CDAT present on the CXL end device.
  @retval EFI_UNSUPPORTED            This function is failed to get the information.
**/
EFI_STATUS
GetCxlMemInfoFromCdat (
  IN     UINT8         SocketId,
  IN     UINT8         StackFwInst,
  IN     UINT8         InstanceId,
  IN     ADDR_RANGE    HdmRange,
  IN OUT CXL_MEM_INFO  *CxlMemInfo
  )
{
  UINT8                                      CdatType;
  UINT32                                     MemLength;
  ADDR_RANGE                                 DpaRange;
  VOID                                       *CxlCdatPtr;
  CDAT_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT  *MemAffinityPtr;
 
  // 检查基地址 base 和 Limit 是否有效， Limit 上限
  if (HdmRange.Base >= HdmRange.Limit) {
    return EFI_SUCCESS;                // Return if the HDM range is invalid.
  }

  MemLength = 0;
  MemAffinityPtr = NULL;
  CdatType = CDAT_TYPE_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT;

  // 获取 CDAT 指针
  CxlCdatPtr = GetCxlEndDevCdat (SocketId, StackFwInst, InstanceId);
  if (CxlCdatPtr == NULL) {
    return EFI_NOT_FOUND;
  }
  
  // 遍历所有的 DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT 结构体
  while (!EFI_ERROR (GetNextCdatStruct (CxlCdatPtr, (VOID **) &MemAffinityPtr, &CdatType, NULL))) {
    // 计算出重叠部分
    DpaRange.Base = MAX (HdmRange.Base, (UINT32) RShiftU64 (MemAffinityPtr->DpaBase, CONVERT_B_TO_64MB));
    DpaRange.Limit = MIN (HdmRange.Limit, (UINT32) RShiftU64 (MemAffinityPtr->DpaBase + MemAffinityPtr->DpaLength, CONVERT_B_TO_64MB));
    
    if (DpaRange.Base >= DpaRange.Limit) {
      // 结构体的 DPA range 和 HDM range 没有重叠部分
      continue;  // Continue if there is no overlap between the DPA range of this structure and HDM range.
    }

    MemLength += DpaRange.Limit - DpaRange.Base;
    if (MemAffinityPtr->Flags.NonVolatile != 0) {
      // 内存是非易失性，记录大小，64MB 粒度
      CxlMemInfo->PerCap += DpaRange.Limit - DpaRange.Base;
    } else {
      // 内存是易失性
      CxlMemInfo->VolCap += DpaRange.Limit - DpaRange.Base;
    }
  }

  // 如果指定的 HDM 在 CDAT 中只占部分，则返回错误
  if (MemLength != HdmRange.Limit - HdmRange.Base) {
    RcDebugPrint (SDBG_MINMAX, "Only partial memory 0x%x(64MB) can be located in CDAT for HDM range 0x%x ~ 0x%x(64MB)\n",
      MemLength, HdmRange.Base, HdmRange.Limit);
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}
```

#### 2.1.5 GetCxlEndDevPerfData()

- 此函数从设备 CDAT 中获取性能数据
- DSLBIS Flags 与 DataType 字段，如果Handle 代表的 Initiator 没有内存则忽略；否则，与 HMAT 响应的字段匹配
HMAT 相关字段，From ACPI_6_3_May16.pdf Table 5-146：

![请添加图片描述](https://img-blog.csdnimg.cn/a0acc6289aea488fb6176be23996a535.png)


```c

/**
  This function gets the performance data from CDAT for the specified CXL end device.

  @param[in]      SocketId           Socket index.
  @param[in]      StackFwInst        Stack FW instance.
  @param[in]      InstanceId         Logical instance index.
  @param[in, out] CxlEndDevInfo      Pointer to CXL end device data.

  @retval EFI_SUCCESS                This function is executed successfully.
  @retval EFI_NOT_FOUND              There is no DSLBIS present in CDAT.
  @retval EFI_UNSUPPORTED            The DSLBIS is not supported.
**/
EFI_STATUS
GetCxlEndDevPerfData (
  IN     UINT8                 SocketId,
  IN     UINT8                 StackFwInst,
  IN     UINT8                 InstanceId,
  IN OUT CXL_END_DEVICE_INFO   *CxlEndDevInfo
  )
{
  UINT8                                                 MemAffinityType;
  UINT8                                                 LatBwInfoType;
  EFI_STATUS                                            Status;
  VOID                                                  *CxlCdatPtr;
  CDAT_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT             *MemAffinityPtr;
  CDAT_DEVICE_SCOPED_LATENCY_AND_BANDWIDTH_INFO_STRUCT  *LatBwInfoPtr;

  LatBwInfoPtr = NULL;
  MemAffinityType = CDAT_TYPE_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT;
  LatBwInfoType = CDAT_TYPE_DEVICE_SCOPED_LATENCY_AND_BANDWIDTH_INFO_STRUCT;

  // 获取 CDAT 指针
  CxlCdatPtr = GetCxlEndDevCdat (SocketId, StackFwInst, InstanceId);
  if (CxlCdatPtr == NULL) {
    // 没有 CDAT 
    // Override the flag to TRUE if it is running on Simics. So that CXL end devices
    // can still be interleaved together in absence of memory performance data on Simics.
    //
    // Simics 是一个全系统模拟器或虚拟平台，用于运行目标硬件的未更改的生产二进制文件。
    // 如果运行在 Simics 之上，那么修改 flag 为 TRUE，即使缺失内存性能数据也可以正常运行；
  
    if ((GetEmulation () & SIMICS_FLAG) != 0) {
      CxlEndDevInfo->VolMemPerf.Valid = TRUE;
      CxlEndDevInfo->PerMemPerf.Valid = TRUE;
    }
    return EFI_SUCCESS;
  }
  // 遍历所有的 DEVICE_SCOPED_LATENCY_AND_BANDWIDTH_INFO_STRUCT 结构体
  while (!EFI_ERROR (GetNextCdatStruct (CxlCdatPtr, (VOID **) &LatBwInfoPtr, &LatBwInfoType, NULL))) {
    // 0 - Memory, 如果不存在 memory side cache, 这个结构体表示内存性能；如果存在，则表示没有命中发生时的内存性能
    // 1 - 1st level memory side cache
    // 2 - 2nd level m s c
    // 3 - 3rd level m s c

    if (LatBwInfoPtr->Flags.MemoryHierarchy != 0) {
      continue;    // CXL memory is not supported to be mapped as near memory.
    }

    // Data Type :
    //             if Memory Hierarchy = 0
    //             0 - Access Latency    
    //             1 - Read Latency
    //             2 - Write Latency
    //             3 - Access Bandwidth
    //             4 - Read Bandwidth
    //             5 - Write Bandwidth
    //          
    //             if Memory Hierarchy = 1,2,3,4
    //             0 - Access Hit Latency 
    //             1 - Read Hit Latency
    //             2 - Write Hit Latency
    //             3 - Access Hit Bandwidth
    //             4 - Read Hit Bandwidth
    //             5 - Write Hit Bandwidth
    //             此处  Memory Hierarchy = 0
    
    MemAffinityPtr = NULL;
    if (CxlEndDevInfo->HdmCount == 0) {
      //
      // Parse initiator performance data for CXL type 1 device.
      // 没有设备内存 Hdm，设备为 Type 1 设备
      // 解析获取延时和带宽
      ParseCdatPerfData (LatBwInfoPtr->Entry[0], LatBwInfoPtr->EntryBaseUnit, LatBwInfoPtr->DataType, &CxlEndDevInfo->InitiatorPerf);
    } else {
      //
      // Parse memory performance data for CXL type 2/3 device.
      // 解析 Type 2 / 3 设备的内存性能
      // MemAffinityType 获取 DSMAS 以及指定 LatBwInfoPtr->Handle， 是一个 DSMAS handle
      Status = GetNextCdatStruct (CxlCdatPtr, (VOID **) &MemAffinityPtr, &MemAffinityType, &LatBwInfoPtr->Handle);
      if (EFI_ERROR (Status)) {
        // 没有找到
        RcDebugPrint (SDBG_MINMAX, "There is no DSMAS referenced by the DSLBIS in CXL CDAT\n");
        return EFI_UNSUPPORTED;
      }

      if (MemAffinityPtr->Flags.NonVolatile != 0) {
        // 解析非易失性内存性能
        ParseCdatPerfData (LatBwInfoPtr->Entry[0], LatBwInfoPtr->EntryBaseUnit, LatBwInfoPtr->DataType, &CxlEndDevInfo->PerMemPerf);
      } else {
        // 解析易失性内存性能
        ParseCdatPerfData (LatBwInfoPtr->Entry[0], LatBwInfoPtr->EntryBaseUnit, LatBwInfoPtr->DataType, &CxlEndDevInfo->VolMemPerf);
      }

      //
      // Parse initiator performance data for CXL type 2 device.
      //
      if (!CxlEndDevInfo->MemExpander) {
        // 如果不是 MemExpander， Type 2 设备
        // Entry[1] represents the pathway between the device egress and the initiator inside the device.
        // Entry[2] represents the pathway between the initiator inside the device and the device memory.
        // 解析性能数据
        ParseCdatPerfData (LatBwInfoPtr->Entry[1], LatBwInfoPtr->EntryBaseUnit, LatBwInfoPtr->DataType, &CxlEndDevInfo->InitiatorPerf);
        ParseCdatPerfData (LatBwInfoPtr->Entry[2], LatBwInfoPtr->EntryBaseUnit, LatBwInfoPtr->DataType, &CxlEndDevInfo->Initiator2MemPerf);
      }
    }
  }

  if (LatBwInfoPtr == NULL) {
    // 没找到 DSLBIS ，也算成功
    RcDebugPrint (SDBG_MAX, "There is no DSLBIS present in CDAT\n");
    return EFI_SUCCESS;
  }

  //
  // Dump CXL performance data.
  //
  DisplayCxlEndDevPerfData (CxlEndDevInfo);

  return EFI_SUCCESS;
}

```

#### 2.1.6 GetCxlEndDevEfiMemType()

- 此函数是，对于指定的 CXL 设备， 从 CDAT 获取 EFI 内存类型以及属性。当 CDAT 存在并且不存在 DSEMTS 时， CXL 内存将将被标记为 EfiConventionalMemory。 当 DSENTS 存在，CXL 内存将被标记为DSEMTS提供的 EFI 内存类型。

```
/**
  This function gets the EFI memory type and attribute from CDAT for the specified CXL end device.
  When CDAT is present and DSEMTS is absent, CXL memory will be tagged with EfiConventionalMemory.
  When DSEMTS is present, CXL memory will be tagged with the EFI memory type provided by DSEMTS.

  @param[in]      SocketId           Socket index.
  @param[in]      StackFwInst        Stack FW instance.
  @param[in]      InstanceId         Logical instance index.
  @param[in, out] CxlEndDevInfo      Pointer to CXL end device data.

  @retval EFI_SUCCESS                This function is executed successfully.
  @retval EFI_UNSUPPORTED            The DSEMTS is not supported.
**/

EFI_STATUS
GetCxlEndDevEfiMemType (
  IN     UINT8                 SocketId,
  IN     UINT8                 StackFwInst,
  IN     UINT8                 InstanceId,
  IN OUT CXL_END_DEVICE_INFO   *CxlEndDevInfo
  )
{
  UINT8                                      MemAffinityType;
  UINT8                                      EfiMemAttrType;
  EFI_STATUS                                 Status;
  VOID                                       *CxlCdatPtr;
  CDAT_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT  *MemAffinityPtr;
  CDAT_DEVICE_SCOPED_EFI_MEMORY_TYPE_STRUCT  *EfiMemAttrPtr;

  // 如果没有设备内存，则返回成功
  if (CxlEndDevInfo->HdmCount == 0) {
    return EFI_SUCCESS;   // Return if there is no memory present.
  }

  EfiMemAttrPtr = NULL;
  MemAffinityType = CDAT_TYPE_DEVICE_SCOPED_MEMORY_AFFINITY_STRUCT;
  EfiMemAttrType = CDAT_TYPE_DEVICE_SCOPED_EFI_MEMORY_TYPE_STRUCT;

  CxlEndDevInfo->VolEfiMemType = CxlEfiConventionalMemory;
  CxlEndDevInfo->PerEfiMemType = CxlEfiConventionalMemory;

  CxlCdatPtr = GetCxlEndDevCdat (SocketId, StackFwInst, InstanceId);
  if (CxlCdatPtr == NULL) {
    // 如果不存在 CDAT , 则 EFI 内存类型设置成无效
    CxlEndDevInfo->VolEfiMemType = MaxCxlEfiMemType;
    CxlEndDevInfo->PerEfiMemType = MaxCxlEfiMemType;  // Set CXL EFI memory type to invalid if CDAT is not present.
    return EFI_SUCCESS;
  }

  // 循环遍历 CDAT 结构体
  while (!EFI_ERROR (GetNextCdatStruct (CxlCdatPtr, (VOID **) &EfiMemAttrPtr, &EfiMemAttrType, NULL))) {
    MemAffinityPtr = NULL;
    // 从 CADT 数据缓冲区得到下一个 CDAT 结构体 , 成功返回 0， 指定了 DsmasHandle
    Status = GetNextCdatStruct (CxlCdatPtr, (VOID **) &MemAffinityPtr, &MemAffinityType, &EfiMemAttrPtr->DsmasHandle);
    if (EFI_ERROR (Status)) {
      // CDAT 中没有找到 DSMAS 
      RcDebugPrint (SDBG_MINMAX, "The DSEMTS references an invalid DSMAS in CXL CDAT\n");
      return EFI_UNSUPPORTED;
    }

    // EfiMemAttrPtr  : DSEMTS 结构体指针，
    // MemAffinityPtr : DSMAS 结构体指针，
    // DPA ranges covered by DSEMTS entries must not overlap and 
    // must fit within the DPA range associated with the associated DSMAS Handle.
    if (!((EfiMemAttrPtr->DpaOffset + EfiMemAttrPtr->DpaLength) <= MemAffinityPtr->DpaLength)) {
      RcDebugPrint (SDBG_MINMAX, "The memory range covered by DSEMTS doesn't fit within the associated DSMAS\n");
      return EFI_UNSUPPORTED;
    }

    //
    // Overriding priority: EfiReservedMemoryType (0x2) > EFI_MEMORY_SP (0x1) > EfiConventionalMemory (0x0).
    // CxlEndDevInfo->PerEfiMemType 与 VolEfiMemType 都初始化为 0， 则根据 EfiMemAttrPtr 中的类型赋值
    if (MemAffinityPtr->Flags.NonVolatile) {
      //  非易失内存类型
      CxlEndDevInfo->PerEfiMemType = MAX (EfiMemAttrPtr->EfiMemoryTypeAndAttribute, CxlEndDevInfo->PerEfiMemType);
    } else {
      //  易失内存类型
      CxlEndDevInfo->VolEfiMemType = MAX (EfiMemAttrPtr->EfiMemoryTypeAndAttribute, CxlEndDevInfo->VolEfiMemType);
    }
  }

  if (EfiMemAttrPtr == NULL) {
    RcDebugPrint (SDBG_MAX, "There is no DSEMTS present in CDAT\n");
  }

  return EFI_SUCCESS;
}
```



