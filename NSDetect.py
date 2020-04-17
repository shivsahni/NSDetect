import pandas
import socket
import dns.resolver
import traceback
import sys

class bcolors:
    TITLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    INFO = '\033[93m'
    OKRED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    UNDERLINE = '\033[4m'
    FGWHITE = '\033[37m'
    FAIL = '\033[95m'

verbose=False
def myPrint(text, type):
	if(type=="INFO"):
		if(verboseMode):
			print bcolors.INFO+text+bcolors.ENDC
			return
		
	if(type=="INFO_WS"):
		print bcolors.INFO+text+bcolors.ENDC
		return
	if(type=="ERROR"):
		print bcolors.BGRED+bcolors.FGWHITE+bcolors.BOLD+text+bcolors.ENDC
		return
	if(type=="MESSAGE"):
		print bcolors.TITLE+bcolors.BOLD+text+bcolors.ENDC+"\n"
		return
	if(type=="INSECURE_WS"):
		print bcolors.OKRED+bcolors.BOLD+text+bcolors.ENDC
		return
	if(type=="OUTPUT"):
		print bcolors.OKBLUE+bcolors.BOLD+text+bcolors.ENDC+"\n"
		return
	if(type=="OUTPUT_WS"):
		print bcolors.OKBLUE+bcolors.BOLD+text+bcolors.ENDC
		return
	if(type=="SECURE"):
		print bcolors.OKGREEN+bcolors.BOLD+text+bcolors.ENDC

def isVulnerable(domainName):

	global nsRecords, aRecords, isException
	isException=False
	nsRecords=0
	try:
		aRecords= dns.resolver.query(domainName)
	except dns.resolver.NoNameservers:
		try:
			nsRecords = dns.resolver.query(domainName, 'NS')
		except:
			myPrint("Exception While Fetching NS Records of "+domainName, "INFO")
			isException=True
			return False

		if len(nsRecords)==0:
			return False
		return True
	except:
		pass
		#myPrint("Exception while fetching A records of "+domainName, "INFO")
	return False

vulnerableDomains=[]
isException=False
x=0
nsRecords=0
aRecords=0
verboseMode=False

if (len(sys.argv)<3):
	myPrint("Please provide the CSV to initiate the scanning.", "ERROR")
	print ""
	myPrint("Usage: python NSDetect.py -i input.csv [-v]","ERROR")
	myPrint("Please try again!!", "ERROR") 
	print ""
	exit(1);

if (sys.argv[1]=="-i" or sys.argv[1]=="--input"):
	pathToCsv=sys.argv[2]

if (len(sys.argv)>3 and (sys.argv[3]=="-v" or sys.argv[3]=="-verbose")):
	verboseMode=True

colNames=["domain"]
data = pandas.read_csv(pathToCsv, names=colNames)
domains=set(data.domain.tolist())
i=1
for domain in domains:
	try:
		print str(i)+". ", 
		i=i+1
		result=isVulnerable(domain)
		if (result==False) and (verboseMode==True) and (isException==True):
			continue
		if result:
			vulnerableDomains.append(domain)
			myPrint(domain,"ERROR")
		else:
			myPrint(domain,"SECURE")
	except KeyboardInterrupt:
		break
print "Total Vulnerable Domains Found: "+str(len(vulnerableDomains))
print vulnerableDomains
