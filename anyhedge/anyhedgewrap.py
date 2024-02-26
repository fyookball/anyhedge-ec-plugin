"""Wrapper class to import anyhedge code"""

 
from . import anyhedge_lib 

class anyhedgewrap():
    def __init__(self, ui_window=None):
        self.Terminal = anyhedge_lib  
        self.ui_window = ui_window
 
