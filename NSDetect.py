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


vulnerableDomains=[]
suspectedDomains=[]
isException=False
x=0
nsRecords=0
aRecords=0
verboseMode=False


def myPrint(text, type):
	if(type=="INFO"):
		if(verboseMode):
			print(bcolors.INFO+text+bcolors.ENDC)
		return
	if(type=="PLAIN_OUTPUT_WS"):
		print(bcolors.INFO+text+bcolors.ENDC)
		return
	if(type=="INFOB"):
		print(bcolors.INFO+bcolors.BOLD+text+bcolors.ENDC)
		return
	if(type=="ERROR"):
		print(bcolors.BGRED+bcolors.FGWHITE+bcolors.BOLD+text+bcolors.ENDC)
		return
	if(type=="MESSAGE"):
		print(bcolors.TITLE+bcolors.BOLD+text+bcolors.ENDC+"\n")
		return
	if(type=="INSECURE_WS"):
		print(bcolors.OKRED+bcolors.BOLD+text+bcolors.ENDC)
		return
	if(type=="INSECURE"):
		print(bcolors.OKRED+bcolors.BOLD+text+bcolors.ENDC+"\n")
		return
	if(type=="OUTPUT"):
		print(bcolors.OKBLUE+bcolors.BOLD+text+bcolors.ENDC+"\n")
		return
	if(type=="OUTPUT_WS"):
		print(bcolors.OKBLUE+bcolors.BOLD+text+bcolors.ENDC)
		return
	if(type=="SECURE"):
		print(bcolors.OKGREEN+bcolors.BOLD+text+bcolors.ENDC)

def printList(lst):
	counter=0
	for item in lst:
		counter=counter+1
		entry=str(counter)+". "+item
		myPrint("\t"+entry, "INSECURE_WS")

def isVulnerable(domainName):

	global nsRecords, aRecords, isException
	isException=False
	nsRecords=0
	try:
		aRecords= dns.resolver.query(domainName)
	except dns.resolver.NXDOMAIN:
			return False, "\tI: "+domainName+"  Not Registered-> Getting NXDOMAIN Exception"
	except dns.resolver.NoNameservers:
		try:
			nsRecords = dns.resolver.query(domainName, 'NS')
		except:
			isException=True
			return False, "\tI: Exception While Fetching NS Records of "+domainName
		if len(nsRecords)==0:
			return False
		return True, ""
	except:
		pass
	return False, ""


#########################################################################################


#########################################################################################
print(bcolors.OKRED+"""				
   	    ) (   (                            
   	 ( /( )\ ))\ )          )           )  
   	 )\()(()/(()/(    (  ( /(  (     ( /(  
   	((_)\ /(_)/(_))  ))\ )\())))\ (  )\()) 
   	 _((_(_))(_))_  /((_(_))//((_))\(_))/  
   	| \| / __||   \(_)) | |_(_)) ((_| |_   
   	| .` \__ \| |) / -_)|  _/ -_/ _||  _|  
   	|_|\_|___/|___/\___| \__\___\__| \__| 

	"""+bcolors.OKRED+bcolors.BOLD+"""         				
     # Developed By Shiv Sahni - @shiv__sahni
"""+bcolors.ENDC)

if ((len(sys.argv)==2) and (sys.argv[1]=="-h" or sys.argv[1]=="--help")):
	myPrint("Usage: python NSDetect.py -i/--input <pathToCsv> [ -v/-verbose]","ERROR")
	myPrint("\t-i/--input: Pathname of the CSV file", "ERROR") 
	myPrint("\t-v/--verbose: For more verbose output", "ERROR")
	print("")
	exit(0);


if (len(sys.argv)<3):
	myPrint("Please provide the CSV to initiate the scanning.", "ERROR")
	print("")
	myPrint("Usage: python NSDetect.py -i input.csv [-v/--verbose]","ERROR")
	myPrint("Please try again!!", "ERROR") 
	print("")
	exit(1);

if (sys.argv[1]=="-i" or sys.argv[1]=="--input"):
	pathToCsv=sys.argv[2]

if (len(sys.argv)>3 and (sys.argv[3]=="-v" or sys.argv[3]=="--verbose")):
	verboseMode=True

colNames=["domain"]
data = pandas.read_csv(pathToCsv, names=colNames)
domains=set(data.domain.tolist())
i=0
for domain in domains:
	try:
		i=i+1
		result, exceptionMessage=isVulnerable(domain)
		if result:
			vulnerableDomains.append(domain)
			myPrint(str(i)+". "+domain,"ERROR")
		elif((result==False) and (isException==True)):
			suspectedDomains.append(domain)
			myPrint(str(i)+". "+domain,"INFOB")
			myPrint(exceptionMessage, "INFO")
		else:
			myPrint(str(i)+". "+domain,"SECURE")
			myPrint(exceptionMessage, "INFO")
	except KeyboardInterrupt:
		break

countV=len(vulnerableDomains)
myPrint("\nTotal Vulnerable Domains Found: "+str(countV), "INFOB")
countS=len(suspectedDomains)
myPrint("Total Suspected Domains Found: "+str(countS)+"\n", "INFOB")
if(countV>0):
	myPrint("List of Vulnerable Domains:", "INFOB")
	printList(vulnerableDomains)
if(countS>0):
	myPrint("List of Suspected Domains:", "INFOB")
	printList(suspectedDomains)

