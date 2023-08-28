from ghidra.program.model.data import DataTypePath
from psx_dt_constants import *

# check for category, prompt if not exists

class PSXSymbolManager():
    __name__ = "PSXSymbolManager"
    def check_datatype_region(self, addr, dataType):
        found_data = False
        
    def apply_data_type(self, addr, dataType):
        dat = None
        try:
            dat = self.__listing.createData(addr, dataType)
        except:
            dat = None
        return dat

    def __init__(self, dtm, listing):
        self.type_check_success = False
        # can't do anything without the symbol manager either
        if listing is None:
            raise Exception("! PSXSymbolManager: Listing was not provided.")
        self.__listing = listing

        # can't do anything without the data manager
        if dtm is None:
            raise Exception("! PSXSymbolManager: DataType manager was not provided.")
        self.__dtm = dtm

class PSXDataTypeManager():
    __name__ = "PSXDataTypeManager"

    def check_for_type(self, categoryPath, dataTypeName):
        dtp = DataTypePath(categoryPath, dataTypeName)
        dt = self.dtm.getDataType(dtp)
        if dt is None:
            raise Exception("! Failed checking type %s" % dtp)
        return dt
    
    # def list_all(self):
    #     for t in self.dtm.getAllDataTypes():
    #         print t
    
    def check_init(self):
        if not self.type_check_success:
            raise Exception("! PSXDataTypeManager: Types are not initalized.")

    def getCDXAHeaderType(self):
        self.check_init()
        return self.cdxa_header_type
    
    def getCDXAFooterType(self, form_num):
        self.check_init()
        if form_num == 1:
            return self.cdxa_ecd_type
        elif form_num == 2:
            return self.cdxa_padding_type
        return None

    def getCDXADataRegionType(self, submode_str, form_num = 1):
        self.check_init()
        if 'DATA' in submode_str:
            return None
        if form_num == 1:
            if "VIDEO" in submode_str:
                return self.cdxa_form_one_video
            if "AUDIO" in submode_str:
                return self.cdxa_form_one_audio
        elif form_num == 2:
            if "VIDEO" in submode_str:
                return self.cdxa_form_two_video
            if "AUDIO" in submode_str:
                return self.cdxa_form_two_audio
        return None

    

    def __init__(self, dtm):
        self.type_check_success = False

        # can't do anything without the data manager
        if dtm is None:
            raise Exception("! PSXDataTypeManager: DataType manager was not provided.")
        self.dtm = dtm

        # self.list_all()

        # if symm is None:
        #     raise Exception("! PSXDataTypeManager: Symbol manager was not provided.")
        # self.__symm = symm

        # set default None for all types
        self.cdxa_header_type = None
        self.cdxa_ecd_type = None
        self.cdxa_padding_type = None

        self.cdxa_form_one_audio = None
        self.cdxa_form_one_video = None
        self.cdxa_form_two_audio = None
        self.cdxa_form_two_video = None

        self.tim_header_type = None
        self.clut_header_type = None
        self.pixel_header_type = None

        self.clut_fourbit_type = None
        self.clut_eightbit_type = None

        self.frame_buffer_fourbit_type = None
        self.frame_buffer_eightbit_type = None


        # find all the types we need
        try:
            self.cdxa_header_type = self.check_for_type(JPSX_TYPE_CATEGORY, CDXA_HEADER_TYPE)
            self.cdxa_ecd_type = self.check_for_type(JPSX_TYPE_CATEGORY, CDXA_ECD_TYPE)
            self.cdxa_padding_type = self.check_for_type(JPSX_TYPE_CATEGORY, CDXA_PADDING_TYPE)

            self.tim_header_type = self.check_for_type(XENTAX_TYPE_CATEGORY, TIM_HEADER_TYPE)
            self.clut_header_type = self.check_for_type(XENTAX_TYPE_CATEGORY, TIM_CLUT_HEADER_TYPE)
            self.pixel_header_type = self.check_for_type(PSYQ_TIM_CATEGORY, TIM_PIXEL_HEADER_TYPE)

            self.cdxa_form_one_audio = self.check_for_type(JPSX_SECTOR_DATA_CATEGORY, CDXA_FORM1_AUDIO_DATA)
            self.cdxa_form_one_video = self.check_for_type(JPSX_SECTOR_DATA_CATEGORY, CDXA_FORM1_VIDEO_DATA)
            self.cdxa_form_two_audio = self.check_for_type(JPSX_SECTOR_DATA_CATEGORY, CDXA_FORM2_AUDIO_DATA)
            self.cdxa_form_two_video = self.check_for_type(JPSX_SECTOR_DATA_CATEGORY, CDXA_FORM2_VIDEO_DATA)

            self.clut_fourbit_type = self.check_for_type(PSYQ_TIM_CLUT_CATEGORY, CLUT_4BIT_TYPE)
            self.clut_eightbit_type = self.check_for_type(PSYQ_TIM_CLUT_CATEGORY, CLUT_8BIT_TYPE)

            self.frame_buffer_fourbit_type = self.check_for_type(PSYQ_TIM_PIXEL_CATEGORY, FRAME_BUFFER_4BIT_TYPE)
            self.frame_buffer_eightbit_type = self.check_for_type(PSYQ_TIM_PIXEL_CATEGORY, FRAME_BUFFER_8BIT_TYPE)
            
            self.type_check_success = True
        except Exception as e:
            print e
            print "! PSXDataTypeManager: An error occurred validating program types. %s" % str(e)
            pass
        print "> PSXDataTypeManager: Located required types."


if __name__ == "__main__":
    manager = PSXDataTypeManager(currentProgram.getDataTypeManager())