class BaseDataTypeModel(object):
    __name__ = "BaseDataTypeModel"
    def is_initalized(self):
        if not self.loaded or self.data is None:
            raise Exception("Model is not loaded.")
    
    def __init__(self):
        self.loaded = False
        self.data = None

