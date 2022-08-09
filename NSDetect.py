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

