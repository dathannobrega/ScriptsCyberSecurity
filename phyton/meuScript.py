import sys,os

if len(sys.argv)<= 2:
    print("USAGE: 192.168.0.1 80")
else:
    print("Varrrendo o Host:", sys.argv[1]," Na porta; ",sys.argv[2])
#TRABALHANDO COM ARGUMENTOS#


##############
os.system("netstat -nltp")


#####

print("MEU SCRIPT\n")
ip = input("DIgite o ip: ") #
port = 80

print(type(ip))
################### FOR em Python####
for ip in range(1,10):
    print(ip)
#########################################