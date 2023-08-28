from ghidra.program.model.symbol import SourceType
from ghidra.util.data.DataTypeParser import AllowedDataTypes
from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.exception import *
from cdxa_sector_header import CDXASectorHeader
from psx_data_types import PSXDataTypeManager
# from ghidra.program.flatapi import FlatProgamAPI

SYM_TABLE = currentProgram.getSymbolTable()
PSX_SECTOR_SIZE = 0x930
CDXA_MAGIC = "00 ff ff ff ff ff ff ff ff ff ff 00"
# https://c3rb3ru5d3d53c.github.io/2023/02/ghidra-python-cheatsheet.en.md/#searching-patterns
# def search_memory(string, max_results=128):
# 	fpi = FlatProgramAPI(getCurrentProgram())
# 	return fpi.findBytes(currentProgram.getMinAddress(), ''.join(['.' if '?' in x else f'\\x{x}' for x in string.split()]), max_results)

# addresses = search_memory('55 8b ec 83 ec 20 8b 4? ?? 33')
# for address in addresses: print(address)


def search_memory_for_next(startAddress, target):
    print 'searching %X' % startAddress.getOffset()
    formattedd = ''.join(['.' if '?' in x else '\\x%s'%x for x in target.split()])
    print formattedd
    res = findBytes(startAddress, formattedd, 1)
    if res is None or len(res) == 0:
        return None
    return res

def prompt_for_file(desc_txt, open_button_txt):
    try:
        f = askFile(desc_txt, open_button_txt)
    except CancelledException:
        return None    
    return f

def prompt_for_data_type():
    """ get the target data type for sector labeling"""
    tool = state.getTool()
    dtm = currentProgram.getDataTypeManager()
    selection_dialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
    tool.showDialog(selection_dialog)
    data_type = selection_dialog.getUserChosenDataType()
    return data_type

def prompt_for_int(title, message):
    try:
        user_int = askInt(title, message)
    except CancelledException:
        return None
    return user_int 

def create_label(addr, label, source_type = SourceType.ANALYSIS, remove_old = True):
    sym_tbl = currentProgram.getSymbolTable()
    old_labels = sym_tbl.getSymbols(addr)
    if remove_old:
        for lbl in old_labels:
            lbl.delete()
    new_label = sym_tbl.createLabel(addr, label, source_type)
    return new_label

def create_data(addr, data_type, remove_old = True):
    """ remove old data and recreate it with the specified type """
    if data_type is None:
        print "No data type can't create"
        return
    dat = getDataAt(addr)
    if remove_old and dat is not None:
        print 'removing data at %s' % addr
        removeDataAt(addr)
        dat = None
    if dat is None:
        print "Creating %s at %s" % (data_type.getName(), addr)
        dat = createData(addr, data_type)
    return dat


def find_next_header(startAddress):
    res = search_memory_for_next(startAddress, CDXA_MAGIC)
    return res[0]

def prompt_for_jpsx_index_file():
    """ get a jpsxdec index file from the user """
    return prompt_for_file("Select a jpsxdec index file to open", "Open")

def prompt_for_type_archive_file():
    return prompt_for_file((
        "Unable to locate types from PSXBinaryDataTypes archive.\n"
        "Select it here to open it or cancel and use the Ghidra GUI to add it to continue.\n"
    ), "Open archive")
   
def check_header_bytes(addr):
    bs = getBytes(addr, 12)
    for i in range(len(bs)):
        if (i == 0 or i == 11) and bs[i] != 0x00:
            return False
        elif bs[i] != 0xFF:
            return False
    return True

def process_sector(type_manager, current_sector_num, addr):
    # create data at the header address
    sector_data = create_data(addr, type_manager.getCDXAHeaderType())
    sector_data_obj = CDXASectorHeader(sector_data, current_sector_num)

    # set label/comment using the data from the header
    create_label(addr, sector_data_obj.toLabel())
    setPlateComment(addr, sector_data_obj.toPlateComment())

    sector_submodes = sector_data_obj.getSubmodeLabelString()
    sector_form = sector_data_obj.getSectorForm()

    # identify beginning of data region
    sector_start_address = sector_data_obj.getSectorDataStartAddress()
    # create label and data
    create_label(sector_start_address, sector_data_obj.getSectorStartLabel())
    data_region_type = type_manager.getCDXADataRegionType(sector_submodes, sector_form)
    if data_region_type is not None:
        create_data(sector_start_address, data_region_type)
    
    # identify end of data region
    sector_end_address = sector_data_obj.getSectorEndRegionAddress()
    # create label and data
    create_label(sector_end_address, sector_data_obj.getSectorEndLabel())
    footer_type = type_manager.getCDXAFooterType(sector_form)
    if footer_type is not None:
        create_data(sector_end_address, footer_type)
    return sector_data_obj

def create_type_manager():
    types_loaded = False
    dtm = currentProgram.getDataTypeManager()
    type_manager = None
    try:
        type_manager = PSXDataTypeManager(dtm)
        types_loaded = True
    except Exception as e:
        print e
        pass
    if not types_loaded:
        arch_file = prompt_for_type_archive_file()
        if arch_file is None:
            print "! Unable to locate PSXBinaryDataTypes archive, cannot continue."
            raise Exception("Unable to locate PSXBinaryDataTypes archive, cannot continue.") 
        dtm = openDataArchive(arch_file, True)
        type_manager = PSXDataTypeManager(dtm)
    return type_manager

def main():
    type_manager = create_type_manager()
    base_sector = prompt_for_int("Enter Base Sector", "Enter the base disc sector for the program.")
    if base_sector is None:
        print "! No base sector entered, using 0."
        base_sector = 0
    print "> Using base sector 0x%04X (%d)" % (base_sector, base_sector)

    current_sector = base_sector
    current_address = currentProgram.getMinAddress()
    max_address = currentProgram.getMaxAddress()
    while current_address < max_address:
        loc = find_next_header(current_address)
        print loc
        if loc is None:
            break
        process_sector(type_manager, current_sector, loc)
        current_sector += 1
        current_address = loc.add(1)
    print "> Done"
main()