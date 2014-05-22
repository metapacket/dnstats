#!/usr/bin/python
import sys,os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import math
import time
from optparse import OptionParser
import Queue
import threading
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import signal
import ip_sniff
import struct
import syslog



def signal_handler(signal, frame):
	os.kill(os.getpid(), 9)
        sys.exit(0)


def ChartServerThread(port):

	server = HTTPServer(("localhost",port), ChartServerHandler)
	server.serve_forever()


class ChartServerHandler(BaseHTTPRequestHandler):

	def do_GET(self):

		global metaDNSPacket

		
		if (self.path == "/jquery.js" or self.path == "/jquery.flot.js" or self.path == "/jquery.flot.pie.js" or self.path == "/chart.js" or self.path == "/favicon.ico"):
			self.send_response(200)
			self.end_headers()
			self.wfile.write(file(self.path[1:]).read())
			self.wfile.write('\n')
			return


		HTML_TEMPLATE = "html_template.html"
		htmlTemplateData = file(HTML_TEMPLATE).read()

		metaDNSPacket.mutex.acquire()

		self.send_response(200)
		self.end_headers()


		# no error, NX domain
		rcode = 0

		TIME_AXIS_STRING1 = 'labels : ['
		for i in xrange(len(metaDNSPacket.responseTimeChart.chart[rcode])):
			if (i % 2) == 1:
				TIME_AXIS_STRING1+="\"\""
			else:
				TIME_AXIS_STRING1 += str(metaDNSPacket.responseTimeChart.minResponseTime[rcode] + (i+0.5)*metaDNSPacket.responseTimeChart.histogramInterval[rcode])
			if i != len(metaDNSPacket.responseTimeChart.chart[rcode])-1:
				TIME_AXIS_STRING1 += ','
		TIME_AXIS_STRING1 += '],'
		RESPONSE_TIME_STRING1 = 'data : ['
		for i in xrange(len(metaDNSPacket.responseTimeChart.chart[rcode])):
			RESPONSE_TIME_STRING1 += str(metaDNSPacket.responseTimeChart.chart[rcode][i] + metaDNSPacket.responseTimeChart.chart[3][i])
			if i != len(metaDNSPacket.responseTimeChart.chart[rcode])-1:
				RESPONSE_TIME_STRING1 += ','
		RESPONSE_TIME_STRING1 += ']'


		# server failure
		rcode = 2

		TIME_AXIS_STRING2 = 'labels : ['
		for i in xrange(len(metaDNSPacket.responseTimeChart.chart[rcode])):
			if (i % 2) == 1:
				TIME_AXIS_STRING2+="\"\""
			else:
				TIME_AXIS_STRING2 += str(metaDNSPacket.responseTimeChart.minResponseTime[rcode] + (i+0.5)*metaDNSPacket.responseTimeChart.histogramInterval[rcode])
			if i != len(metaDNSPacket.responseTimeChart.chart[rcode])-1:
				TIME_AXIS_STRING2 += ','
		TIME_AXIS_STRING2 += '],'
		RESPONSE_TIME_STRING2 = 'data : ['
		for i in xrange(len(metaDNSPacket.responseTimeChart.chart[rcode])):
			RESPONSE_TIME_STRING2 += str(metaDNSPacket.responseTimeChart.chart[rcode][i])
			if i != len(metaDNSPacket.responseTimeChart.chart[rcode])-1:
				RESPONSE_TIME_STRING2 += ','
		RESPONSE_TIME_STRING2 += ']'


		PIE_CHART_DATA = "var data = ["
		first = True
		sumAll = 0

		for rcode in xrange(len(metaDNSPacket.responseTimeChart.chart)):
			sumAll += sum(metaDNSPacket.responseTimeChart.chart[rcode])

		for rcode in xrange(len(metaDNSPacket.responseTimeChart.chart)):

			if (sum(metaDNSPacket.responseTimeChart.chart[rcode]) == 0):
				continue

			if not first:
				PIE_CHART_DATA += ","
			first = False
			PIE_CHART_DATA += "{label:\""
			PIE_CHART_DATA += MetaDNSPacket.RCODES[rcode]
			PIE_CHART_DATA += ": %.02f%%" % (100 * float(sum(metaDNSPacket.responseTimeChart.chart[rcode])) / sumAll)
			PIE_CHART_DATA += "\",data:"
			PIE_CHART_DATA += str(sum(metaDNSPacket.responseTimeChart.chart[rcode]))
			PIE_CHART_DATA += "}"
		
		PIE_CHART_DATA += "]"
		
		GENERAL_STATISTICS = metaDNSPacket.GetStatistics()

		GENERAL_STATISTICS = GENERAL_STATISTICS.replace("\n","<br>")
		GENERAL_STATISTICS = GENERAL_STATISTICS.replace("\t","&nbsp&nbsp&nbsp&nbsp")
			
		htmlFileData = htmlTemplateData.replace('GENERAL_STATISTICS',GENERAL_STATISTICS)

		htmlFileData = htmlFileData.replace('PIE_CHART_DATA',PIE_CHART_DATA)

		htmlFileData = htmlFileData.replace('TIME_AXIS_STRING1',TIME_AXIS_STRING1)
		htmlFileData = htmlFileData.replace('RESPONSE_TIME_STRING1',RESPONSE_TIME_STRING1)

		htmlFileData = htmlFileData.replace('TIME_AXIS_STRING2',TIME_AXIS_STRING2)
		htmlFileData = htmlFileData.replace('RESPONSE_TIME_STRING2',RESPONSE_TIME_STRING2)


		#file(self.HTMLOutputFile, 'w').write(htmlFileData)


		self.wfile.write(htmlFileData)
		self.wfile.write('\n')

		metaDNSPacket.mutex.release()

		return

	def log_message(self, format, *args):
		return
		
		
		


class MetaDNSPacket(threading.Thread):

	RCODES = ["No Error","Format Error","DNS Lookup Failure","Non-Existent Domain","Not Implemented","Query Refused","Name Exists when it should not"
		"RR Set Exists when it should not",
		"RR Set that should exist does not",
		"Server Not Authoritative for zone",
		"Name not contained in zone",
		"Unassigned","Unassigned","Unassigned","Unassigned","Unassigned",
		"Bad OPT Version",
		"Signature Failure",
		"Key not recognized",
		"Signature out of time window",
		"Bad TKEY Mode",
		"Duplicate key name",
		"Algorithm not supported",
		"Bad Truncation"]

	DNS_PORT = 53
	MAX_UNANSWERED_REQUESTS = 1000

	def __init__(self, serverIPAddresses, packetQueue):

		threading.Thread.__init__(self)
		#self.NotDNSUDPPackets = []
		self.UnansweredRequestPackets = []
		#self.UnassociatedResponsePackets = []
		self.serverIPAddresses = serverIPAddresses
		self.creationTime = time.time()
		self.packetQueue = packetQueue
		self.responseTimeChart = ResponseTimeChart()
		self.mutex = threading.Lock()

		self.maxResponseTime = 0
		self.totalResponseTime = [0]*len(MetaDNSPacket.RCODES)
		self.totalResponseTimeSquare = [0]*len(MetaDNSPacket.RCODES)
		self.maxResponseTimePerRcode = [0]*len(MetaDNSPacket.RCODES)
		self.responseCount = [0]*len(MetaDNSPacket.RCODES)

	
		

	def ReceivePacket(self, dnsPacket):

		
		if dnsPacket.dstPort == MetaDNSPacket.DNS_PORT:
			# dns request packet

			# handle only dns requests to our server
			if dnsPacket.dstIP not in self.serverIPAddresses:
				return

			if len(self.UnansweredRequestPackets) > self.MAX_UNANSWERED_REQUESTS:
				self.UnansweredRequestPackets = self.UnansweredRequestPackets[1:]	
			self.UnansweredRequestPackets.append(dnsPacket)

		elif dnsPacket.srcPort == MetaDNSPacket.DNS_PORT:
			# dns response packet

			# handle only dns responses from our server
			if dnsPacket.srcIP not in self.serverIPAddresses:
				return

			foundRequest = False
			for requestPacket in self.UnansweredRequestPackets:
				if requestPacket.srcIP != dnsPacket.dstIP:
					continue
				if requestPacket.dstIP != dnsPacket.srcIP:
					continue
				if requestPacket.srcPort != dnsPacket.dstPort:
					continue
				if requestPacket.id != dnsPacket.id:
					continue
				foundRequest = True

				self.newRequestResponse(requestPacket,dnsPacket)
				self.responseTimeChart.addNewResponseTime(dnsPacket.time - requestPacket.time, dnsPacket.rcode)

				self.UnansweredRequestPackets.remove(requestPacket)
				break

			#if not foundRequest:
			#	self.UnassociatedResponsePackets.append(dnsPacket)
			
		else:
			pass
			#print 'ERROR, SHOULD NOT BE HERE, weird packet port:'
			#print dnsPacket.srcPort, dnsPacket.dstPort

	def newRequestResponse(self, request, response):

		if response.rcode not in xrange(len(MetaDNSPacket.RCODES)):
			#print 'unknown rcode: %d' % response.rcode
			return

		responseTime = (response.time-request.time)

		self.responseCount[response.rcode] += 1
		self.totalResponseTime[response.rcode] += responseTime
		self.totalResponseTimeSquare[response.rcode] += (responseTime*responseTime)
		self.maxResponseTimePerRcode[response.rcode] = max(self.maxResponseTimePerRcode[response.rcode], responseTime)

		if responseTime > self.maxResponseTime:
			self.maxResponseTime = responseTime

	
	def GetStatistics(self):

		statisticsString = ""

		
		
		totalRequestResponse = sum(self.responseCount)

		if totalRequestResponse == 0:
			statisticsString += 'No packets received yet\n'
			return statisticsString

		
		statisticsString += 'Number of DNS (UDP) requests: %d\n' % (totalRequestResponse + len(self.UnansweredRequestPackets))
		statisticsString += 'Number of DNS requests with response: %d\n' % totalRequestResponse
		statisticsString += 'Number of DNS requests per second: %f\n' % ((totalRequestResponse + len(self.UnansweredRequestPackets)) / float(time.time() - self.creationTime))
		statisticsString += 'Response time statistics (in seconds):\n'
		if totalRequestResponse > 0:
			avg = float(sum(self.totalResponseTime)) / totalRequestResponse
			avg2 = float(sum(self.totalResponseTimeSquare)) / totalRequestResponse
			std = math.sqrt(avg2 - (avg**2))
			statisticsString += 'Average of response time: %f\n' % (avg)
			statisticsString += 'Standard deviation response time: %f\n' % (std)
		statisticsString += 'Max response time: %.4f\n' % (self.maxResponseTime)
		statisticsString += 'DNS response rcode:\n'
		for i in xrange(len(MetaDNSPacket.RCODES)):
			if self.responseCount[i] > 0:
				statisticsString += MetaDNSPacket.RCODES[i] + ": %.02f%%\n" % (100 * float(self.responseCount[i]) / totalRequestResponse)
		statisticsString += 'Statistics for different rcodes:\n'
		for i in xrange(len(MetaDNSPacket.RCODES)):
			if self.responseCount[i] > 0:
				avg = float(self.totalResponseTime[i]) / self.responseCount[i]
				avg2 = float(self.totalResponseTimeSquare[i]) / self.responseCount[i]
				std = math.sqrt(avg2 - (avg**2))			
				statisticsString += MetaDNSPacket.RCODES[i] + ":\n"
				statisticsString += '\tCount: %20d' % (self.responseCount[i])
				statisticsString += '\tAverage: %.4f' % (avg)
				statisticsString += '\tStandard deviation: %.4f' % (std)
				statisticsString += '\tMax: %.4f\n' % (self.maxResponseTimePerRcode[i])
		statisticsString += "\n"
		return statisticsString

	def run(self):

		while True:
			packet = self.packetQueue.get()
			self.mutex.acquire()
			self.ReceivePacket(packet)
			self.mutex.release()


class ResponseTimeChart(object):
	
	__slots__ = ['minResponseTime', 'maxResponseTime', 'histogramInterval', 'chart']

	def __init__(self):
		
		self.minResponseTime = [0]*len(MetaDNSPacket.RCODES)
		self.maxResponseTime = [100]*len(MetaDNSPacket.RCODES)
		self.histogramInterval = [1]*len(MetaDNSPacket.RCODES)

		self.minResponseTime[0] = self.minResponseTime[3] = 0
		self.maxResponseTime[0] = self.maxResponseTime[3] = 2
		self.histogramInterval[0] = self.histogramInterval[3] = 0.02
	
		self.chart = []
		for i in xrange(len(MetaDNSPacket.RCODES)):
			self.chart.append([0]*(int((self.maxResponseTime[i]-self.minResponseTime[i])/self.histogramInterval[i])))

	def addNewResponseTime(self, responseTime, rcode):
		
		key = int((responseTime-self.minResponseTime[rcode])/self.histogramInterval[rcode])
		if (key < 0):
			key = 0
		if key >= len(self.chart[rcode]):
			key = len(self.chart[rcode]) - 1
		self.chart[rcode][key] += 1


	

class DNSPacket(object):

	__slots__ = ['srcIP', 'dstIP', 'srcPort', 'dstPort', 'id', 'rcode', 'time']

	def __init__(self, ScapyDNSPacket):
		self.time = ScapyDNSPacket.time
		self.srcIP = ScapyDNSPacket[IP].src
		self.dstIP = ScapyDNSPacket[IP].dst
		self.srcPort = ScapyDNSPacket[UDP].sport
		self.dstPort = ScapyDNSPacket[UDP].dport
		self.rcode = ScapyDNSPacket[DNS].rcode
		self.id = ScapyDNSPacket[DNS].id

	def __init__(self, time, srcIP, dstIP, srcPort, dstPort, rcode, id):
		self.time = time
		self.srcIP = srcIP
		self.dstIP = dstIP
		self.srcPort = srcPort
		self.dstPort = dstPort
		self.rcode = rcode
		self.id = id
		
		

def sniff_callback(src, dst, frame):

	global packetQueue
	
	
	try:
		IPversion = (struct.unpack('B',frame[0])[0] & 0xf0) >> 4
		if IPversion != 4:
			# not IPv4, throw packet
			return

		IHL = (struct.unpack('B',frame[0])[0] & 0xf)
		srcIP = str(struct.unpack('B',src[0])[0]) + '.' + str(struct.unpack('B',src[1])[0]) + '.' + str(struct.unpack('B',src[2])[0]) + '.' + str(struct.unpack('B',src[3])[0])
		dstIP = str(struct.unpack('B',dst[0])[0]) + '.' + str(struct.unpack('B',dst[1])[0]) + '.' + str(struct.unpack('B',dst[2])[0]) + '.' + str(struct.unpack('B',dst[3])[0])
		protocol = struct.unpack('B',frame[9])[0]

		if protocol != 17:
			# not UDP, throw packet
			return
	
		udp_frame = frame[IHL*4:]

		srcPort = struct.unpack('>H',udp_frame[0:2])[0]
		dstPort = struct.unpack('>H',udp_frame[2:4])[0]

		if srcPort != MetaDNSPacket.DNS_PORT and dstPort != MetaDNSPacket.DNS_PORT:
			# not DNS, throw packet
			return

		dns_frame = udp_frame[8:]

		id = struct.unpack('>H',dns_frame[0:2])[0]
		rcode = (struct.unpack('B',dns_frame[3])[0] & 0xf)


		dnsPacket = DNSPacket(time.time(), srcIP, dstIP, srcPort, dstPort, rcode, id)
		packetQueue.put(dnsPacket)
	
	except Exception, e:
		syslog.syslog(str(e))
		



def main():

	global packetQueue
	global metaDNSPacket

	signal.signal(signal.SIGINT, signal_handler)

	parser = OptionParser(usage='usage: %prog [options] -i interface -d dns_server_ip')
	parser.add_option("-f", dest="pcap_file", help="choose this option to get packets from a .pcap file instead of sniffing")
	parser.add_option("-d", dest="server_IP_addresses", help="dns server addresses")
	parser.add_option("-p", dest="webserver_port", help="web server port (for live statistics)", default = "8000")
	parser.add_option("-i", dest="interface", help="interface to bind")

	(options, args) = parser.parse_args()

	if not options.server_IP_addresses:
	    parser.error('dns server ip not given')

	if not options.interface:
	    parser.error('interface is not given')

	syslog.openlog("dnstats")

	threading.Thread(target=ChartServerThread, args = [int(options.webserver_port)]).start()

	
	packetQueue = Queue.Queue()
	pcapFile = options.pcap_file
	hostIPs = options.server_IP_addresses.split(' ')
	
	metaDNSPacket = MetaDNSPacket(hostIPs, packetQueue)
	
	if pcapFile is None:
		# start the thread, he will wait for packets to process
		metaDNSPacket.start()
		try:
			hostfilter = "" % hostIPs
			firstHost = True
			for host in hostIPs:
				if host == "":
					continue
				if not firstHost:
					hostfilter += " or"
				firstHost = False
				hostfilter += " host "
				hostfilter += host
			sniff = ip_sniff.IPSniff(options.interface, sniff_callback, sniff_callback)
			sniff.recv()
			#sniff(filter="udp port 53 and (%s)" % hostfilter, prn=lambda x:packetQueue.put(x))
		except socket.error, e:
			if e.errno == 1:
				print "not root? bitch please"
			elif e.errno == 19:
				print "interface %s not working" % options.interface
		except Exception, e:
			syslog.syslog(str(e))
			
	else:
		pcapRecords = rdpcap(pcapFile)
		i = 0
		for scapyPacket in pcapRecords:

			if i % 1000 == 0:
				print '#',
				sys.stdout.flush()
			i += 1

			if not scapyPacket.summary().startswith("Ether / IP / UDP / DNS"):
				return

			dnsPacket = DNSPacket(scapyPacket)

			
			metaDNSPacket.mutex.acquire()
			metaDNSPacket.ReceivePacket(dnsPacket)
			metaDNSPacket.mutex.release()

	
	signal_handler(signal.SIGINT,0)	

	



	

if __name__ == '__main__':
	main()

