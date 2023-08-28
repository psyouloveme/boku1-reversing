import string
from ghidra.program.model.symbol import SourceType
from ghidra.app.util.datatype import DataTypeSelectionDialog
from ghidra.util.data.DataTypeParser import AllowedDataTypes

SYM_TABLE = currentProgram.getSymbolTable()
PSX_SECTOR_SIZE = 0x930

def create_file_label(addr, embedded_file_info):
    """ check for an existing sector label, create or update """
    old_symbols = SYM_TABLE.getSymbols(addr)
    formatted_typename = embedded_file_info.type.upper()
    label = "%s_%s_%08X" % (embedded_file_info.file_id, formatted_typename, addr.getOffset())
    found_old_label = False
    for old_label in old_symbols:
        old_name = old_label.getName(False)
        if old_name == label:
            found_old_label = True            
            break
    if not found_old_label:
        createLabel(addr, label, False)
        # print "Created label '%s' at %s" % (label, str(addr))


def find_sector_symbol(sector_num):
    """ search the symbol table for the sector start label """
    for sym in SYM_TABLE.getAllSymbols(True):
        search_sector = "SECTOR_0x%04X" % sector_num
        if search_sector in sym.getName() and "ECD" not in sym.getName():
            return sym
    return None


def prompt_for_jpsxdec_index_file():
    """ get a jpsxdec index file from the user """
    try:
        f = askFile("Select a jpsxdec index file (.idx) to import", "Open")
    except CancelledException:
        return None    
    return f

def parse_int(int_str):
    """ parse int from string or return None """
    if int_str is None or int_str == "":
        return None
    v = None
    try:
        v = int(int_str)
    except Exception as e:
        print e
        return None
    return v

def process_split_int_col(line, idx, split, rep = None):
    if line is None or line == "" or idx is None or split is None:
        return None
    sb = line[idx]
    if sb is None or sb == "":
        return None
    sb = sb.strip()
    if rep is not None:
        sb = sb.replace(rep, "")
    vals = sb.split(split)
    if len(vals) != 2:
        return None
    a = parse_int(vals[0])
    b = parse_int(vals[1])
    if a is None or b is None:
        return None
    return (a, b)

def process_int_col(line, idx, rep = None):
    if line is None or line == "" or idx is None:
        return None
    b = line[idx]
    if b is None or b == "":
        return None
    b = b.strip()
    if rep is not None:
        b = b.replace(rep, "")
    v = parse_int(b)
    return v

class DiscFile():
    """
        0: index
        1: id/name
        2: sectors (s-e)
        3: type
        4: start offset
        5: dimensions
        6: palettes
        7: bpp
    """
    def __init__(self, line):
        split_line = line.split("|")

        self.disc_index = process_int_col(split_line, 0, "#:")
        self.file_id = split_line[1].replace("ID:", "")

        sectors = process_split_int_col(split_line, 2, "-", "Sectors:")
        if sectors is not None:
            self.start_sector = sectors[0]
            self.end_sector = sectors[1]
        else:
            self.start_sector = None
            self.end_sector = None

        self.type = split_line[3].replace("Type:", "")
        self.start_offset = process_int_col(split_line, 4, "Start Offset:")

        dimensions = process_split_int_col(split_line, 5, "x", "Dimensions:")
        if dimensions is not None:
            self.width = dimensions[0]
            self.height = dimensions[1]
        else:
            self.width = None
            self.height = None
        
        self.palettes = process_int_col(split_line, 6, "Palettes:")
        self.bytes_per_pixel = process_int_col(split_line, 7, "Bpp:")

    def __str__(self):
        s = "#: %s " % self.disc_index
        s += "| ID: %s " % self.file_id
        s += "| Sectors: %d-%d " % (self.start_sector, self.end_sector)
        s += "| Type: %s " % self.type
        s += "| Start Offset: %d " % self.start_offset
        s += "| Dimensions: %dx%d " % (self.width, self.height)
        s += "| Palettes: %d " % self.palettes
        s += "| BPP: %d" % self.bytes_per_pixel 
        return s

def main():
    index_file = prompt_for_jpsxdec_index_file()
    if index_file is None:
        print "No index file provided, exiting."
        return
    label_count = 0
    with open(index_file.absolutePath, "r") as f:
        for line in f:
            if not line.startswith("#:"):
                # skip comments or non file index lines
                continue
            if "Path:" in line:
                # skip root files
                continue
            if "Type:Tim" not in line:
                # only handle Tim files for now
                continue
            embedded_file_info = None
            try:
                embedded_file_info = DiscFile(line)
            except Exception as e:
                print e
                continue
            # print embedded_file_info
            start_sector_symbol = find_sector_symbol(embedded_file_info.start_sector)
            if start_sector_symbol is None:
                print "! No symbol found for sector 0x%04X" % embedded_file_info.start_sector
                continue
            sector_start_address = start_sector_symbol.getAddress()
            # print sector_start_address
            start_sector_data = getDataAt(sector_start_address)
            if start_sector_data is not None:
                start_sector_data_type = start_sector_data.getDataType()
                mapped_address = sector_start_address.add(embedded_file_info.start_offset + start_sector_data_type.getLength())
                # print "Mapped sector %d+%d to offset 0x%04X" % (embedded_file_info.start_sector, embedded_file_info.start_offset, mapped_address.getOffset())
                create_file_label(mapped_address, embedded_file_info)
                label_count += 1
    print "Created %s data file labels."


            


            # process the info...
            
main()
        

# def prompt_for_data_type():
#     """ get the target data type for sector labeling"""
#     tool = state.getTool()
#     dtm = currentProgram.getDataTypeManager()
#     selection_dialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
#     tool.showDialog(selection_dialog)
#     data_type = selection_dialog.getUserChosenDataType()
#     return data_type

# def prompt_for_int(title, message):
#     try:
#         user_int = askInt(title, message)
#     except CancelledException:
#         return None
#     return user_int 

# def create_sector_label(addr, current_sector):
#     """ check for an existing sector label, create or update """
#     old_symbols = SYM_TABLE.getSymbols(addr)
#     label = "SECTOR_0x%04X_%X" % (current_sector, addr.getOffset())
#     found_old_label = False
#     for old_label in old_symbols:
#         old_name = old_label.getName(False)
#         if old_name == label or u"SECTOR" in old_name:
#             found_old_label = True            
#             break
#     if not found_old_label:
#         createLabel(addr, label, False)
#         # print "Created label '%s' at %s" % (label, str(addr))

# def create_sector_data(addr, data_type):
#     """ create a sector header data struct at the address if there isn't already one """
#     if data_type is None:
#         return
#     old_data = getDataAt(addr)
#     if old_data is None:
#         createData(addr, data_type)
#         # print "Created '%s' data at %s" % (data_type.getName(), str(addr))

# def main():
#     mem_blocks = getMemoryBlocks()
#     blocks_to_process = []

#     expected_total_sectors = 0
#     # determine which blocks are aligned to be PSX disc data
#     for block in mem_blocks:
#         block_name = block.getName()
#         if block.getSize() % PSX_SECTOR_SIZE == 0:
#             block_expected_sectors = block.getSize() / PSX_SECTOR_SIZE
#             print "> Block %s is PSX aligned. 0x%08X - 0x%08X, 0x%08x bytes. Expect %s sectors." % (block_name, block.getStart().getOffset(), block.getEnd().getOffset(), block.getSize(), block_expected_sectors)
#             expected_total_sectors += block_expected_sectors
#             blocks_to_process.append(block)
#         # else:
#             # print "Block '%s' is not PSX aligned, skipping." % block_name
#     print "> Expect %04X (%d) total sectors." % (expected_total_sectors, expected_total_sectors)

#     if len(blocks_to_process) == 0:
#         print "! No PSX disc algined blocks located (must be multiple of 0x%04X), exiting." % PSX_SECTOR_SIZE
#         return

#     # prompt for data type, exit early if none provided
#     data_type = prompt_for_data_type()
#     if data_type is None:
#         print "! No datatype selected, cancelling."
#     else:
#         print "> Selected data type: %s" % data_type.getName()

#     base_sector = prompt_for_int("Enter Base Sector", "Enter the base disc sector for the program.")
#     if base_sector is None:
#         print "! No base sector entered, cancelling."
#     print "> Using base sector 0x%04X (%d)" % (base_sector, base_sector)
    


#     current_sector = base_sector

#     last_sector_offset = None
#     last_block_end_offset = None
#     block_start_offset = None
#     block_end_offset = None
#     total_sectors_created = 0
#     for curr_block in blocks_to_process:
#         block_name = curr_block.getName()
#         block_start_offset = curr_block.getStart().getOffset()
#         block_end_offset = curr_block.getEnd().getOffset()
#         block_size = curr_block.getSize()

#         if last_block_end_offset is not None and block_start_offset is not None and (last_block_end_offset + 1) != block_start_offset:
#             sector_gap = (block_start_offset - last_block_end_offset)
#             print "sector gap = %04X %d | block offset start = %04X %d | last sector offset = %04X %d" % (sector_gap, sector_gap, block_start_offset, block_start_offset, last_sector_offset, last_sector_offset)

#             if last_sector_offset is not None and sector_gap % PSX_SECTOR_SIZE == 0:
#                 # preserve sector numbers if regions are non-contiguous but spaced with sector alignment
#                 skipped_sectors = sector_gap / PSX_SECTOR_SIZE
#                 print "skipped sectors = %04X %d | sector gap = %04X %d | PSX_SECTOR_SIZE = %04X %d" % (skipped_sectors, skipped_sectors, sector_gap, sector_gap, PSX_SECTOR_SIZE, PSX_SECTOR_SIZE)
#                 current_sector += skipped_sectors
#                 print "> Non-continguous block '%s' skipped %d sectors, restarting numbering at sector %04X" % (block_name, skipped_sectors, current_sector)
#             else:
#                 # restart sector numbering at 0 if alignment is not correct
#                 print "! Non-contiguous block '%s' found, restarting sector numbering at 0x0000." % block_name
#                 current_sector = 0

#         last_block_end_offset = block_end_offset
#         print "> Begin processing block '%s'." % (block_name)
#         curr_block_sectors = 0
#         for addr_int in range(block_start_offset, block_start_offset + block_size, PSX_SECTOR_SIZE):
#             addr = toAddr(addr_int)
#             if curr_block.contains(addr):
#                 create_sector_data(addr, data_type)
#                 create_sector_label(addr, current_sector)
#                 last_sector_offset = addr_int
#                 curr_block_sectors += 1
#                 current_sector += 1
#             else:
#                 print "! Address 0x%08X is not in region '%s', ignoring." % (addr_int, block_name)
#         total_sectors_created += curr_block_sectors
#         print "> Finished processing block '%s': created 0x%04X (%d) sectors." % (block_name, curr_block_sectors, curr_block_sectors)
#     print "> Finished processing program. Created 0x%04X (%d) sectors." % (total_sectors_created, total_sectors_created)
#     if expected_total_sectors != total_sectors_created:
#         print "!!!! Error: Created 0x%04X (%d) sectors but expected to create 0x%04X (%d) sectors!" % (total_sectors_created, total_sectors_created, expected_total_sectors, expected_total_sectors)