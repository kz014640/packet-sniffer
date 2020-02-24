import socket
import struct
import time
import psutil
import pyspeedtest
import threading
from collections import deque
from tkinter import *
from tkinter import filedialog
import matplotlib.animation as animation
from matplotlib import style
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from functools import reduce
import datetime
import os
from statistics import mean
import sys

speedtest = pyspeedtest.SpeedTest()
style.use('ggplot')
f = Figure(figsize=(5,5), dpi=100)
a = f.add_subplot(111)

global ping
global downloadMax
global uploadMax
global xList
global yList2
global yList
global severityDownload
global severityUpload
global severityLevel
global FileHead
global fileWrite

yList = []
xList = []
yList2 = []
severityDownload = []
severityUpload = []
SeverityLevel = []

fileWrite = 0
FileHead = 0

xList.append(0)
yList2.append(0)
yList.append(0)

#user selectable varibles
#write a manual of user selected varibles for appendix
NumTrial = 10 #can be changed to allow users to change the amount of time it calculates the downnload and upload
DownloadUnits = 1000 #can be changed to change the download units of the program normnaly 1000 to convert into killa bits
UploadUnits = 1000 #can be changed to change the upload units of the program normnaly 1000 to convert into killa bits
Graphlimit = 20 #this can be changed to change the amount of varibles stored to print the graph
maxSeverity = 5 #can be changes to change the amount of severity levels
SeverityLimit = 5#can be changed to a different amount for how many minutes the severity wants to calclulate by

def main():
    # the below calculates the ping
    ping = speedtest.ping()
    # thje below calculates the max download speed
    downloadMax = speedtest.download()
    # the below calculates the max upload speed
    uploadMax = speedtest.upload()

    #gets the highest download speed over 10 checks to make sure that the maxdownload speed wasnt a mistake
    for i in range(NumTrial):

        if uploadMax < speedtest.upload():
            uploadMax = speedtest.upload()

        if downloadMax < speedtest.download():
            downloadMax = speedtest.download()

    #converts the speed from bytes to kilabytes
    downloadMax = (downloadMax / DownloadUnits)
    uploadMax = (uploadMax / UploadUnits)
    #prints the speed to check
    print(downloadMax)
    print(uploadMax)

    #calculates the severity level in acending order so serverity[0] is the lowest severity
    for i in range(maxSeverity):
        print(i)
        severityDownload.append((downloadMax/maxSeverity)*(maxSeverity-i))
        severityUpload.append((uploadMax/maxSeverity)*(maxSeverity-i))

    severityDownload.append(0)
    severityUpload.append(0)
    #prints the lists to check the levels
    print(severityDownload)
    print(severityUpload)

    #runs the GUI and the other threads
    Create_GUI()

def Network_sniffer(transfer_rate):

    # the public network interface
    HOST = socket.gethostbyname(socket.gethostname())
    # create a raw socket and bind it to the public interface
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    connection.bind((HOST, 0))
    # Include IP headers
    connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # receive all packages
    connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    while True:
        now = datetime.datetime.now()
        raw_data, addr = connection.recvfrom(65565)
        #print(raw_data)
        src, dest, proto, data, version, header, LOP, TTL = network_frame(raw_data)

        NetworkLabel.insert(END,'Ethernet Frame:\n')
        #inserts the current date and time
        NetworkLabel.insert(END, now.strftime("%Y-%m-%d %H:%M") + '\n')
        # shows the ip version
        NetworkLabel.insert(END, 'internet version:{}\n'.format(version))
        # shows the header length
        NetworkLabel.insert(END, 'header length:{} bytes\n'.format(header * 4))
        # shows the total length of the package
        NetworkLabel.insert(END, 'length of package:{}\n'.format(LOP))
        # time to leave
        NetworkLabel.insert(END, 'time to leave:{}\n'.format(TTL))
        # shows the destination, source and protocol
        NetworkLabel.insert(END, 'Destination: {}, source: {}, Protocol: {}\n\n'.format(dest, src, proto))

        # the following will print the transfer rate to a label
        status.configure(text=print_rate(transfer_rate))
        #print_rate(transfer_rate)

        if(fileWrite==1):

            #writes ethernet frame
            FileHead.write("Ethernet Frame:\n")
            #writes the current time
            FileHead.write(now.strftime("%Y-%m-%d %H:%M") + "\n")
            #writes the internet version
            FileHead.write("internet version:{}\n".format(version))
            #writes the header length
            FileHead.write("header length:{} bytes\n".format(header * 4))
            #writes the package length
            FileHead.write("length of package:{}\n".format(LOP))
            #writes the time to leave
            FileHead.write("time to leave:{}\n".format(TTL))
            #writes the destination, source, protocol
            FileHead.write("Destination: {}, source: {}, Protocol: {}\n".format(dest, src, proto))
            #writes the download and upload speed
            FileHead.write(print_rate(transfer_rate))
            #writes a new line
            FileHead.write("\n")
            #writes the severity level
            FileHead.write("Severity Level: " + str(severityAverage(SeverityLevel)))
            # writes a new line
            FileHead.write("\n\n")


def network_frame(data):

    #unpacks the IP header into a struct for each part of information
    Data = struct.unpack('!BBHHHBBH4s4s', data[:20])

    #the first part gets the version of the ipheader
    version = Data[0]

    #adds 16 in hecadecimal ontop it so it become just 4 bits dedicated to the header
    header = version & 0xF

    #moves the version along 4 bits
    version = version >> 4

    #gets the length of the package from the second part
    length_of_package = Data[2]

    #takes the time to leave from the 5th slot of teh struct
    timetoleave = Data[5]

    #gets the source ip address
    src = socket.inet_ntoa(Data[8])

    #gets the desination ip address
    dest = socket.inet_ntoa(Data[9])

    #gets the protocol
    protocol = Data[6]

    #returns all information about the ip header
    return src, dest, protocol, data[20:], version, header, length_of_package, timetoleave


def CalculateSpeed(rate, downtime=3, interface='WiFi'):
    #gets the time
    time1 = time.time()

    # gets network information for WIFI
    network_counter = psutil.net_io_counters(pernic=True)[interface]

    # calculates the totla bytes sent and recieved
    total = (network_counter.bytes_sent, network_counter.bytes_recv)
    #used to create a time that will run everyminute

    min = 0
    timer = time.time()

    while True:

        timer2 = time.time()

        if timer2 > timer + 60:

            timer = time.time()
            min = min + 1
            print(min)

            currentSeverityD = speedtest.download()/1000
            currentSeverityU = speedtest.upload()/1000

            Severity = []

            for i in range(maxSeverity):
                #Compares the current download speed and upload speed
                #agains the severity list to determine the severity levels
                if currentSeverityD > severityDownload[i+1]:
                    #print("Severity download "+ str((5-i)))
                    #print(currentSeverityD)
                    #print(severityDownload[i+1])
                    Severity.append(maxSeverity-i)
                    currentSeverityD=0

                if currentSeverityU > severityUpload[i+1]:
                    #print("Severity upload " + str((5-i)))
                    #print(currentSeverityU)
                    #print(severityUpload[i + 1])
                    Severity.append(maxSeverity-i)
                    currentSeverityU=0

            #creates an average severity of download and upload
            SeverityLevel.append((Severity[0] + Severity[1]) /2)

            print((Severity[0] + Severity[1]) /2)

            #makes sure the severity only looks at the last 5 minutes
            if(len(SeverityLevel)>SeverityLimit):
                SeverityLevel.pop(0)

            level=severityAverage(SeverityLevel)
            #changes the colour of the severity label depending on the color
            severityLabel.configure(text="Severity level is " + str(level))
            #10/10 * 4(10/5) - shows the calculation process as the maxSeverity level changes
            if(level > 1*(4*(maxSeverity/5))):
                severityLabel.config(bg="green")

            elif(level > 1*(3*(maxSeverity/5))):
                severityLabel.config(bg="green")

            elif (level > 1*(2*(maxSeverity/5))):
                severityLabel.config(bg="yellow")

            elif (level > 1*(1*(maxSeverity/5))):
                severityLabel.config(bg="orange")

            else:
                severityLabel.config(bg="red")

        #sets the total = to last total to compare the two
        total2 = total
        #time sleeps for 3 seconds
        time.sleep(downtime)
        #gets network information again from psutil
        network_counter = psutil.net_io_counters(pernic=True)[interface]
        #gets a second time to find the total amount of bytes sent and recieved between those times
        time2 = time.time()
        #calculates a second total
        total = (network_counter.bytes_sent, network_counter.bytes_recv)
        #calculates the download and upload speed from the difference
        #multiples by 8 to get the speed in bits and divides by 10000 to get the value into kila bits
        upload, download = [(now - last) / (time2 - time1) *8 / 1000.0
                  for now, last in zip(total, total2)]
        #adds the new upload and download speend onto rate
        rate.append((upload, download))
        #gets a new time
        time1 = time.time()


def print_rate(speed):
    #this will try to print the download speed only if it has taken a measurement
    try:
        return 'Download speed is: {1:.0f} kB/s Upload speed is {0:.0f}'.format(*speed[-1])
    #if it failed to take a measurement it will throw and exception
    except IndexError:
        return print('Download speed is: - kB/s')

def Create_GUI():
    base = Tk()
    main = MainPage(base)

    main.pack(side="top", fill="both", expand=True)
    base.wm_geometry("800x400")

    ani = animation.FuncAnimation(f, animate, interval=1000)
    base.mainloop()

def animate(i):
    counter = xList[-1]

    try:
        #the below pops the lowest value in the time x varible
        if len(xList) > Graphlimit:
            xList.pop(0)

        #the below pops the lowest value in the download speed varible
        if len(yList) > Graphlimit:
            yList.pop(0)

        #the below pops the lowest value in the upload speed varible
        if len(yList2) > Graphlimit:
            yList2.pop(0)

        counter = counter +1
        #gets the download speed from the label at the bottom of the GUI and grabs the text varible
        text = status.cget("text")
        #splits the text varible up for every space there is
        text2 = text.split(" ")

        #adds the download speed to ylist
        yList.append(int(text2[3]))
        #adds the upload speed to lylist2
        yList2.append(int(text2[8]))
        #incraments the time varible
        xList.append(counter)

        #clears the old graph
        a.clear()

        #sets the titles, x and y label
        a.set_xlabel('Time(s)')
        a.set_ylabel('Speed(KB/s)')
        a.set_title('Network Speed')

        #plots the upload and download speed
        a.plot(xList, yList, color="red", label="download speed")
        a.plot(xList, yList2, color="blue", label="upload speed")

        #creates a legend
        a.legend()

    except IndexError:
        print("index error")

def severityAverage(sev):

        #the following will try and take the average of the severity
        try:
            level = reduce(lambda x, y: x + y, sev) / len(sev)
            return level
        #if it cannot calculate the average it returns calculating severity
        except:
            #returns calculating
            return "calculating severity..."

class Page(Frame):
    def __init__(self, *args, **kwargs):
        Frame.__init__(self, *args, **kwargs)

    def show(self):
        self.lift()

class MainPage(Frame):
    def __init__(self, *args, **kwargs):
        Frame.__init__(self, *args, **kwargs)

        NetworkPage = Network(self)
        PacketPage = Packet(self)
        ReadPacketPage = ReadPacket(self)
        AnalyzePage = Analyze(self)

        toolbar = Frame(self, bg="grey")

        container = Frame(self)
        container.pack(side="top", fill="both", expand=True)
        NetworkPage.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        PacketPage.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        ReadPacketPage.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        AnalyzePage.place(in_=container, x=0, y=0, relwidth=1, relheight=1)

        insertButton = Button(toolbar, text="inspect packets", command=PacketPage.lift)
        insertButton.pack(side=LEFT, padx=2, pady=2)

        NetworkButton = Button(toolbar, text="graph", command=NetworkPage.lift)
        NetworkButton.pack(side=LEFT, padx=2, pady=2)

        RecordButton = Button(toolbar, text="Record Packets", command=lambda: MainPage.Record(self))
        RecordButton.pack(side=LEFT, padx=2, pady=2)

        StopButton = Button(toolbar, text="Stop Recording", command=lambda: MainPage.Stop(self))
        StopButton.pack(side=LEFT, padx=2, pady=2)

        ReadButton = Button(toolbar, text="Read Packet", command=ReadPacketPage.lift)
        ReadButton.pack(side=LEFT, padx=2, pady=2)

        AnalyzeButton = Button(toolbar, text="Analyze Packets", command=AnalyzePage.analyzePackets  )
        AnalyzeButton.pack(side=LEFT, padx=2, pady=2)

        ExitButton = Button(toolbar, text="Exit", command=self.quit)
        ExitButton.pack(side=LEFT, padx=2, pady=2)

        toolbar.pack(side=TOP, fill=X)

        #label for network speed
        global status
        status = Label(self, bd=1, text="calclulating netowkr speed....", relief=SUNKEN, anchor=W)
        status.pack(side=BOTTOM, fill=X)

        #label for severity levels
        global severityLabel
        severityLabel = Label(self, bd=1, text="calculating severity....", relief=SUNKEN, anchor=W, bg = "white")
        severityLabel.pack(side=BOTTOM, fill=X)

        # mainbody


        PacketPage.show()

    def Record(self):

        global fileWrite
        global FileHead

        now = datetime.datetime.now()
        #counts the number of existing files
        fileCount = 0
        #creates a for loop to get the next number of attack
        while os.path.exists(str(now.strftime("%Y-%m-%d"))+" "+str(fileCount)+".txt"):
            fileCount += 1
        #sets file write to 1 to allow the rest of the program to write
        fileWrite = 1
        #sets the global file head to equal a file name depending on how many files exist
        #replace the number value with filecount to get incramental files
        FileHead = open(str(now.strftime("%Y-%m-%d"))+" "+str(fileCount)+".txt", "w")


    def Stop(self):

        global fileWrite
        global FileHead

        # change fileWrite to 0 to stop the packet function writing
        fileWrite = 0
        #closes the file header to save the file
        FileHead.close()


class Network(Page):

   def __init__(self, *args, **kwargs):

       Page.__init__(self, *args, **kwargs)
       #creates a canvas to draw the networking graph on
       canvas = FigureCanvasTkAgg(f, self)
        #draws the canvas
       canvas.draw()
       #sets the size of the canvas to fill both x and y at the bottom of the page and allow it to be expandable
       canvas.get_tk_widget().pack(side=BOTTOM, fill=BOTH, expand=True)
       canvas._tkcanvas.pack(side=TOP, fill=BOTH, expand=True)


class Packet(Page):

   def __init__(self, *args, **kwargs):

       Page.__init__(self, *args, **kwargs)

       global NetworkLabel
       NetworkLabel = Text(self, bg="white")
       NetworkLabel.pack(side=LEFT, fill=BOTH, expand=YES)

       Scroll = Scrollbar(self)

       Scroll.pack(side=RIGHT, fill=Y)
       Scroll.config(command=NetworkLabel.yview)

       NetworkLabel.config(yscrollcommand=Scroll.set)

       transfer_rate = deque(maxlen=1)
       thread3 = threading.Thread(target=Network_sniffer, args=(transfer_rate,))

       thread1 = threading.Thread(target=CalculateSpeed, args=(transfer_rate,))

       #program exits if daemon threads are the only ones left
       thread1.daemon = True
       thread1.start()

       thread3.daemon = True
       thread3.start()

class ReadPacket(Page):

   def __init__(self, *args, **kwargs):

       Page.__init__(self, *args, **kwargs)

       toolbar = Frame(self, bg="grey")

       ChooseButton = Button(toolbar,text="Choose File", command=lambda: ReadPacket.chooseFile(self), anchor ="w")
       ChooseButton.pack(side=LEFT, padx=2, pady=2)

       ChooseButton = Button(toolbar, text="Analyze File", command=lambda: ReadPacket.AnalyzeFile(self), anchor="w")
       ChooseButton.pack(side=LEFT, padx=2, pady=2)

       toolbar.pack(side=TOP, fill=X)

       global ReadNetworkLabel
       ReadNetworkLabel = Text(self, bg="white")
       ReadNetworkLabel.pack(side=LEFT, fill=BOTH, expand=YES)

       Scroll = Scrollbar(self)

       Scroll.pack(side=RIGHT, fill=Y)
       Scroll.config(command=ReadNetworkLabel.yview)

       ReadNetworkLabel.config(yscrollcommand=Scroll.set)

   def chooseFile(self):

       file = filedialog.askopenfile(parent=self, title='Choose a file to read', initialdir = "C:/Users/Andrew/PycharmProjects/untitled")
       if file != None:
            ReadFile = open(file.name, 'r')
            line = ReadFile.read()
            ReadNetworkLabel.delete('1.0', END)
            ReadNetworkLabel.insert(INSERT, line)

   def AnalyzeFile(self):
       # creates a list which contains a ethernet frame per spot
       ethernetFrameList = ReadNetworkLabel.get(1.0, END).split("Ethernet Frame:")

       # print(ethernetFrameList)

       # gets the time
       now = datetime.datetime.now()

       # gets the time 5 minutes again
       time = int(now.strftime("%M")) - 5

       # print(now.strftime("%H:%M"))
       # print(int(now.strftime("%M"))-5)

       # creates an empty list to store destination ip address
       dest = []

       # creates an empty source list to hold source addresses
       source = []

       #creates an emplty severity level list to hold all of the severity levels
       sev =[]

       # runs a for loop that goes through the list
       for i in range(len(ethernetFrameList)):
           # creates a new list which contains the ethernet frame split by each new line
           NewLineList = ethernetFrameList[i].split("\n")

           # if the lists is a blank continue to the next frame
           if len(NewLineList) == 1:
               continue

           # runs a for loop that goes through the list
           for i in range(len(NewLineList)):
               # if the slot is blank continue to the next slot
               if NewLineList[i] == "":
                   continue

               temp = NewLineList[i].split(":")
               #print(temp)
               flagdest = 0
               flagsrc = 0

               if temp[0] == 'Destination':
                   for i in range(len(dest)):
                       if dest[i][0] == temp[1].split(",")[0]:
                           dest[i][1] = dest[i][1] + 1
                           flagdest = 1

                   if flagdest == 0:
                       dest.append([(temp[1].split(",")[0]), 0])

                   for i in range(len(source)):
                       if source[i][0] == temp[2].split(",")[0]:
                           source[i][1] = source[i][1] + 1
                           flagsrc = 1

                   if flagsrc == 0:
                       source.append([(temp[2].split(",")[0]), 0])

               if temp[0] == 'Severity Level':
                   print(temp[1].split(" ")[0])
                   sev.append(float(temp[1].split(" ")[1]))
               flagdest = 0
               flagsrc = 0
               # print(NewLineList[i])

       ReadNetworkLabel.delete('1.0',END)
       if len(sev)>1:
           average = mean(sev)
           average = round(average, 2)

           if average<(maxSeverity/5)*1:
               ReadNetworkLabel.insert(END, "Server was being attacked please see details below about who could of commenced the attack \n\n")

           elif average<(maxSeverity/5)*2:
               ReadNetworkLabel.insert(END,"Likelehood of attack is high deploy denial of service countermeasures deatils of attack can be seen below and likely attackers \n\n")

           elif average<(maxSeverity/5)*3:
               ReadNetworkLabel.insert(END,"High traffic but no chance of being attacked see below for details\n\n")

           else:
               ReadNetworkLabel.insert(END,"normal traffic seel below for details \n\n")

           ReadNetworkLabel.insert(END, "Average Severity level: " + str(average) + " \n\n")

       else:
           ReadNetworkLabel.insert(END, "Need a severity level to determine if attack is taking place \n\n")

       for i in range(len(dest)):
           ReadNetworkLabel.insert(END, "Destination IP address: " + str(dest[i][0]) + " number of packets sent in the last 5 minutes: " + str(dest[i][1]) + "\n")

       for i in range(len(source)):
           ReadNetworkLabel.insert(END, "Source IP address: " + str(source[i][0]) + " number of packets sent in the last 5 minutes: " + str(source[i][1]) + "\n")



class Analyze(Page):

   def __init__(self, *args, **kwargs):

       Page.__init__(self, *args, **kwargs)


       global AnalyzeLabel
       AnalyzeLabel = Text(self, bg="white")
       AnalyzeLabel.pack(side=LEFT, fill=BOTH, expand=YES)


       Scroll = Scrollbar(self)

       Scroll.pack(side=RIGHT, fill=Y)
       Scroll.config(command=ReadNetworkLabel.yview)

       AnalyzeLabel.config(yscrollcommand=Scroll.set)


   def analyzePackets(self):
       #creates a list which contains a ethernet frame per spot
       ethernetFrameList = NetworkLabel.get(1.0, END).split("Ethernet Frame:")
       #print(ethernetFrameList)

       #gets the time
       now = datetime.datetime.now()

       #gets the time 5 minutes again
       time=int(now.strftime("%M"))-5

       #print(now.strftime("%H:%M"))
       #print(int(now.strftime("%M"))-5)

       #creates an empty list to store destination ip address
       dest = []

       #creates an empty source list to hold source addresses
       source =[]

       #runs a for loop that goes through the list
       for i in range(len(ethernetFrameList)):
            #creates a new list which contains the ethernet frame split by each new line
           NewLineList = ethernetFrameList[i].split("\n")

            #if the lists is a blank continue to the next frame
           if len(NewLineList) ==1:
               continue

           #print(NewLineList)
            #gets the time in minutes form the ethernet frame

           temp = NewLineList[1].split(":")

           #skips checking the ethernet frame if it was sent longer than the given amount of time
           if int(temp[1])< time:
               continue

            #runs a for loop that goes through the list
           for i in range(len(NewLineList)):

                #if the slot is blank continue to the next slot
               if NewLineList[i] == "":
                   continue

               temp = NewLineList[i].split(":")

               flagdest = 0
               flagsrc = 0

               if temp[0] =='Destination':
                   for i in range(len(dest)):
                        if dest[i][0] == temp[1].split(",")[0]:
                            dest[i][1] = dest[i][1] + 1
                            flagdest=1

                   if flagdest==0:
                        dest.append([(temp[1].split(",")[0]),0])

                   for i in range(len(source)):
                        if source[i][0] == temp[2].split(",")[0]:
                            source[i][1] = source[i][1] + 1
                            flagsrc = 1

                   if flagsrc == 0:
                        source.append([(temp[2].split(",")[0]), 0])

               flagdest = 0
               flagsrc = 0
               #print(NewLineList[i])

       self.lift()
       print(source)
       print(dest)

       AnalyzeLabel.delete('1.0',END)

       text = severityLabel.cget("text")
       level = text.split(" ")


       if level[0] == "Severity":
            if float(level[3])<(maxSeverity/5)*1:
                AnalyzeLabel.insert(END, "Server is being attacked please deploy denial of service countermeasures deatils of attack can be seen below and likely attackers \n\n")

            elif float(level[3])<(maxSeverity/5)*2:
                AnalyzeLabel.insert(END,"Likelehood of attack is high deploy denial of service countermeasures deatils of attack can be seen below and likely attackers \n\n")

            elif float(level[3]) < (maxSeverity/5)*3:
                AnalyzeLabel.insert(END, "High traffic but no chance of being attacked see below for details\n\n")

            else:
                AnalyzeLabel.insert(END, "normal traffic see below for details \n\n")

       else:
           AnalyzeLabel.insert(END, "need severity level before attack can be determined \n\n")

       if level[0] == "Severity":
            AnalyzeLabel.insert(END,"Average Severity level: "+ level[3]+" \n\n")

       else:
           AnalyzeLabel.insert(END, "Calculating Severity \n\n")

       for i in range(len(dest)):
            AnalyzeLabel.insert(END, "Destination IP address: " + str(dest[i][0]) +" number of packets sent in the last 5 minutes: "+ str(dest[i][1]) + "\n\n")

       for i in range(len(source)):
           AnalyzeLabel.insert(END, "Source IP address: " + str(source[i][0]) + " number of packets sent in the last 5 minutes: " + str(source[i][1]) + "\n")

       #AnalyzeLabel.insert(END, NetworkLabel.get(1.0, END))

main()
