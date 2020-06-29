from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from docking.widgets import OptionDialog 
from docking.widgets.filechooser import GhidraFileChooser, GhidraFileChooserMode
import json

result={}

bbm = BasicBlockModel(currentProgram)
bbm_iter=bbm.getCodeBlocks(TaskMonitor.DUMMY)

user_base = int(OptionDialog.showInputSingleLineDialog(None, "Base address","Base address","0x13370000"),16)
ghidra_base = currentProgram.getImageBase().getOffset()

while bbm_iter.hasNext():
	cb=bbm_iter.next()
	addr=cb.getFirstStartAddress().getOffset()
	# if addr-ghidra_base < 0x00100000: continue # TODO stupid workaround for some unexpeceted fuzz-case crashes
	srcs=[]
	src_iter=cb.getSources(TaskMonitor.DUMMY)
	while src_iter.hasNext():
		cbref=src_iter.next()
		ref_addr=cbref.getReferent().getOffset()
		dst_addr=cbref.getReference().getOffset()
		if dst_addr == addr:
			srcs.append(ref_addr-ghidra_base+user_base)
	result["0x%lx" % (addr-ghidra_base+user_base)] = srcs


gfc = GhidraFileChooser(None);
gfc.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
file_name=gfc.getSelectedFile().getAbsolutePath()
file = open(file_name,"w")
file.write(json.dumps(result))
file.close()

print("Written info about %d CodeBlocks to %s" % (len(result), file_name))
