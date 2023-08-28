import binascii
from base_data_type_model import BaseDataTypeModel
from cdxa_constants import *
# creating data types
# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/StructureDataType.html#constructor.summary

def byte_array_com_to_str(ba_comp):
    sb = binascii.hexlify(bytearray(ba_comp.getBytes()))
    if sb == "":
        return "None"
    return sb.strip()

def get_component_default_rep_or_none(comp):
    dvr = comp.getDefaultValueRepresentation()
    if dvr == "0":
        return "None"
    return dvr

def append_str(st, ad):
    r = st
    if r != "":
        r += "_" + ad
    else:
        r = ad
    return r
    

class CDXASubHeader(BaseDataTypeModel):
    __name__ = "CDXASubHeader"
    def __init__(self, existingData = None):
        super(CDXASubHeader, self).__init__()
        self.loaded = False
        self.is_interleaved = None
        self.channel_number = None
        self.sub_mode = None
        self.coding_info = None
        self.subheader_first_four_bytes = None
        if existingData is not None:
            self.is_interleaved = existingData.getComponent(0)
            self.channel_number = existingData.getComponent(1)
            self.sub_mode = existingData.getComponent(2)
            self.coding_info = existingData.getComponent(3)
            self.subheader_first_four_bytes = existingData.getComponent(4)
            self.data = existingData
            self.loaded = True

    def getIsInterleaved(self):
        self.is_initalized()
        return self.is_interleaved.getValue().getValue()
    
    def getChannelNumber(self):
        self.is_initalized()
        return self.channel_number.getValue().getValue()

    def getCodingInfoString(self):
        self.is_initalized()
        return get_component_default_rep_or_none(self.coding_info)

    def getSubmodeString(self):
        self.is_initalized()
        return get_component_default_rep_or_none(self.sub_mode)
    
    def __str__(self):
        self.is_initalized()
        st =  "| Interleaved: %s"% self.is_interleaved.getValue()
        st += "\n Channel Number: %s" % self.channel_number.getValue()
        st += "\tSubmode: %s\tCoding Info: %s\n" % (self.coding_info.getValue(), self.sub_mode.getValue())
        st += "Subheader Bytes: %s" % byte_array_com_to_str(self.subheader_first_four_bytes)
        return st

class CDXABlockAddress(BaseDataTypeModel):
    __name__ = "CDXABlockAddress"
    def __init__(self, existingData = None):
        super(CDXABlockAddress, self).__init__()
        self.loaded = False
        self.minute = None
        self.second = None
        self.block_or_frame_or_sector = None
        if existingData is not None:
            self.minute = existingData.getComponent(0)
            self.second = existingData.getComponent(1)
            self.block_or_frame_or_sector = existingData.getComponent(2)
            self.data = existingData
            self.loaded = True

    def getMinute(self):
        st = self.minute.getValue().toString()
        return int(st.split('x')[1])

    def getSecond(self):
        st = self.second.getValue().toString()
        return int(st.split('x')[1])

    def getBlockOrFrameOrSector(self):
        return self.block_or_frame_or_sector.getValue().getValue()

    def __str__(self):
        self.is_initalized()
        return " Minute: %d | Second: %d | Block/Frame/Sector: %d" % (self.getMinute(), self.getSecond(), self.getBlockOrFrameOrSector())

class CDXAMainHeader(BaseDataTypeModel):
    __name__ = "CDXAMainHeader"
    def __init__(self, existingData = None):
        super(CDXAMainHeader, self).__init__()
        # CDXABlockAddress
        self.block_address = None
        # byte
        self.mode = None
        if existingData is not None:
            self.block_address = CDXABlockAddress(existingData.getComponent(0))
            self.mode = existingData.getComponent(1)
            self.data = existingData
            self.loaded = True

    def getMode(self):
        return self.mode.getValue().getValue()

    def getMinute(self):
        return self.block_address.getMinute()

    def getSecond(self):
        return self.block_address.getSecond()
    
    def getBlockOrFrameOrSector(self):
        return self.block_address.getBlockOrFrameOrSector()

    def __str__(self):
        self.is_initalized()
        st =  "%s\n" % self.block_address
        st += " Mode: %s" % self.mode.getValue()
        return st

class CDXASectorHeader(BaseDataTypeModel):
    __name__ = "CDXASectorHeader"
    def __init__(self, existingData = None, sector_number = None):
        super(CDXASectorHeader, self).__init__()
        # byte[12]
        self.sync_header = None 
        # CDXAMainHeader
        self.header = None
        # CDXASubHeader
        self.sub_header = None
        self.sector_number = sector_number

        print "Existing data %s" % existingData
        if existingData is not None:
            self.sync_header = existingData.getComponent(0)
            self.header = CDXAMainHeader(existingData.getComponent(1))
            self.sub_header = CDXASubHeader(existingData.getComponent(2))
            self.data = existingData
            self.loaded = True

    def getSubmodeLabelString(self):
        self.is_initalized()
        rep = self.sub_header.getSubmodeString()
        sm = ""
        if CDXA_SUB_MODE_END_AUDIO in rep:
            sm = append_str(sm, "END_AUDIO")
        if CDXA_SUB_MODE_VIDEO in rep:
            sm = append_str(sm, "VIDEO")
        if CDXA_SUB_MODE_AUDIO in rep:
            sm = append_str(sm, "AUDIO")
        if CDXA_SUB_MODE_DATA in rep:
            sm = append_str(sm, "DATA")
        if CDXA_SUB_MODE_TRIGGER in rep:
            sm = append_str(sm, "TRIGGER")
        if CDXA_SUB_MODE_REAL_TIME in rep:
            return "REAL_TIME"
        if CDXA_SUB_MODE_EOF in rep:
            return "EOF"
        if CDXA_SUB_MODE_FORM in rep:
            sm = append_str(sm, "FORM2")
        else:
            sm = append_str(sm, "FORM1")
        return sm

    def getSectorForm(self):
        self.is_initalized()
        rep = self.sub_header.getSubmodeString()
        if rep is None:
            return None
        sm = None          
        if CDXA_SUB_MODE_FORM in rep:
            sm = 2
        else:
            sm = 1
        return sm

    def getInterleavedString(self):
        self.is_initalized()
        if self.sub_header.getIsInterleaved() == 0: 
            return 'No' 
        else: 
            return 'Yes'

    def getSectorDataStartAddress(self):
        self.is_initalized()
        return self.data.getMaxAddress().add(1)
    
    def getSectorEndRegionAddress(self):
        self.is_initalized()
        end_offset = None
        rep = self.sub_header.getSubmodeString()
        if CDXA_SUB_MODE_FORM in rep:
            end_offset = self.data.getMaxAddress().add(2324)
        else:
            end_offset = self.data.getMaxAddress().add(2048)
        return end_offset

    def getSectorStartLabel(self):
        self.is_initalized()
        # OLD LABEL: label = "SECTOR_0x%04X_%X" % (current_sector, addr.getOffset())
        st = (
            "SEC-START-%03d:%02d:%003d-%s"
        ) % (
            self.header.getMinute(),
            self.header.getSecond(),
            self.header.getBlockOrFrameOrSector(),
            self.getSubmodeLabelString(),
        )
        if self.sector_number is not None:
            st = st + "-0x%04X" % self.sector_number
        return st

    def getSectorEndLabel(self):
        self.is_initalized()
        # OLD LABEL: label = "SECTOR_0x%04X_ECD_%X" % (current_sector, addr.getOffset())
        st = (
            "SEC-END-%03d:%02d:%003d-%s"
        ) % (
            self.header.getMinute(),
            self.header.getSecond(),
            self.header.getBlockOrFrameOrSector(),
            self.getSubmodeLabelString(),
        )
        if self.sector_number is not None:
            st = st + "-0x%04X" % self.sector_number
        return st

    def toLabel(self):
        self.is_initalized()
        st = (
            "SECTOR-%03d:%02d:%003d-%s"
        ) % (
            self.header.getMinute(),
            self.header.getSecond(),
            self.header.getBlockOrFrameOrSector(),
            self.getSubmodeLabelString(),
        )
        if self.sector_number is not None:
            st = st + "-0x%04X" % self.sector_number
        return st
    
    def toPlateComment(self):
        self.is_initalized()
        st = (
            "Sector Header:\n"
            "  Minute: %3d  Second:      %3s  Block/Frame/Sector: %3d\n"
            "  Form:   %3d  Interleaved: %3s  Channel Number:     %3s\n"
            "  Submode: %s\n"
            "  Coding Info: %s"
        ) % (
            self.header.getMinute(),
            self.header.getSecond(),
            self.header.getBlockOrFrameOrSector(),
            self.getSectorForm(),
            self.getInterleavedString(),
            self.sub_header.getChannelNumber(),
            self.sub_header.getSubmodeString(),
            self.sub_header.getCodingInfoString()
        )
        return st
        
    def __str__(self):
        self.is_initalized()
        st = (
            "Sector Header:\n"
            "  Minute: %3d  Second:      %3d  Block/Frame/Sector: %3d\n"
            "  Form:   %3d  Interleaved: %3s  Channel Number:     %3s\n"
            "  Submode: %s\n"
            "  Coding Info: %s"
        ) % (
            self.header.getMinute(),
            self.header.getSecond(),
            self.header.getBlockOrFrameOrSector(),
            self.getSectorForm(),
            self.getInterleavedString(),
            self.sub_header.getChannelNumber(),
            self.sub_header.getSubmodeString(),
            self.sub_header.getCodingInfoString()
        )
        return st

if __name__ == "__main__":
    a = toAddr(0x30000000)
    print a
    dat = getDataAt(a)
    ba_data = CDXASectorHeader(dat)
    print ba_data.toLabel()
    print ba_data.toPlateComment()
    # print ba_data
    a = a.add(0x930)
    
    print a
    dat = getDataAt(a)
    ba_data = CDXASectorHeader(dat)
    print ba_data.toLabel()
    print ba_data.toPlateComment()
    # print ba_data
