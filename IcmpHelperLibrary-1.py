# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # sources: https://denizhalil.com/2024/04/06/sending-icmp-packets-with-python-socket-adventure-in-signaling/
            # https://denizhalil.com/2024/09/14/icmp-ping-python-tool/
            # Hint: Work through comparing each value and identify if this is a valid response.
            valid = True 

            # Validates the Sequence Number and prints expected and actual value
            expectedSequence = self.getPacketSequenceNumber()
            replySequence = icmpReplyPacket.getIcmpSequenceNumber()
            if replySequence == expectedSequence:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
                print(f"DEBUG: Sequence number valid: expected {expectedSequence}, got {replySequence}")
            else:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(False)
                print(f"DEBUG: Sequence number INVALID: expected {expectedSequence}, got {replySequence}")
                valid = False

            # Validates the Packet Identifier and prints expected and actual value
            expectedIdentifier = self.getPacketIdentifier()
            replyIdentifier = icmpReplyPacket.getIcmpIdentifier()
            if replyIdentifier == expectedIdentifier:
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
                print(f"DEBUG: Packet identifier valid: expected {expectedIdentifier}, got {replyIdentifier}")
            else:
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print(f"DEBUG: Packet identifier INVALID: expected {expectedIdentifier}, got {replyIdentifier}")
                valid = False

            # Validate the Raw Data and prints expected and actual value
            expectedData = self.getDataRaw()
            replyData = icmpReplyPacket.getIcmpData()
            if replyData == expectedData:
                icmpReplyPacket.setIcmpData_isValid(True)
                print(f"DEBUG: Raw data valid: expected {expectedData}, got {replyData}")
            else:
                icmpReplyPacket.setIcmpData_isValid(False)
                print(f"DEBUG: Raw data INVALID: expected {expectedData}, got {replyData}")
                valid = False

            # expected values for printing to console 
            icmpReplyPacket.setExpectedValues(expectedIdentifier, expectedSequence, expectedData)
            # Set the overall valid response flag
            icmpReplyPacket.setIsValidResponse(valid)
            # icmpReplyPacket.setIsValidResponse(True)
            # pass

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        # return      # Echo reply is the end and therefore should return
                        # returns the RTT (ms)
                        return (timeReceived - pingStartTime) * 1000

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
                # check
                return None
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        
        # Validation tracker variables 
        __icmpIdentifier_isValid = False
        __icmpSequenceNumber_isValid = False
        __icmpData_isValid = False

        # Expected values
        expectedIdentifier = None
        expectedSequence = None
        expectedData = None

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # New getter and setter for Identifier validitor
        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid

        def setIcmpIdentifier_isValid(self, value):
            self.__icmpIdentifier_isValid = value

        # New getter and setter for Sequence Number validitor
        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        def setIcmpSequenceNumber_isValid(self, value):
            self.__icmpSequenceNumber_isValid = value

        # New getter and setter for Data validitor
        def getIcmpData_isValid(self):
            return self.__icmpData_isValid

        def setIcmpData_isValid(self, value):
            self.__icmpData_isValid = value

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # Sets expected values 
        def setExpectedValues(self, expectedIdentifier, expectedSequence, expectedData):
            self.expectedIdentifier = expectedIdentifier
            self.expectedSequence = expectedSequence
            self.expectedData = expectedData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
        # Calculates RTT (ms)
            rtt = (timeReceived - self.getDateTimeSent()) * 1000

            # Gets ICMP type and code
            icmp_type = self.getIcmpType()
            icmp_code = self.getIcmpCode()
            error_dict = {
                (0, 0): "Echo Reply (Success)",
                (3, 0): "Destination Network Unreachable",
                (3, 1): "Destination Host Unreachable",
                (3, 2): "Destination Protocol Unreachable",
                (3, 3): "Destination Port Unreachable",
                (11, 0): "TTL Expired in Transit",
                (11, 1): "Fragment Reassembly Time Exceeded"
            }
            error_message = error_dict.get((icmp_type, icmp_code), "Unknown ICMP code")

            # Prints the results
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s    %s" %
                (ttl, rtt, icmp_type, icmp_code, error_message, addr[0]))

            # Prints error info
            if not self.isValidResponse():
                print("    Validation Error:")
                if not self.getIcmpIdentifier_isValid():
                    print("      Expected Identifier: %s, Actual Identifier: %s" %
                        (self.expectedIdentifier, self.getIcmpIdentifier()))
                if not self.getIcmpSequenceNumber_isValid():
                    print("      Expected Sequence Number: %s, Actual Sequence Number: %s" %
                        (self.expectedSequence, self.getIcmpSequenceNumber()))
                if not self.getIcmpData_isValid():
                    print("      Expected Data: %s, Actual Data: %s" %
                        (self.expectedData, self.getIcmpData()))

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
    # Sources: https://denizhalil.com/2024/09/14/icmp-ping-python-tool/, https://denizhalil.com/2024/04/06/sending-icmp-packets-with-python-socket-adventure-in-signaling/
    # https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        rtt_list = []       # List of RTT
        sent_count = 0      # Total pings sent
        received_count = 0  # Total echo replies received

        for i in range(4):
            sent_count += 1
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            rtt = icmpPacket.sendEchoRequest()                                                # Build IP

            if rtt is not None:
                rtt_list.append(rtt)
                received_count += 1

            if self.__DEBUG_IcmpHelperLibrary:
                icmpPacket.printIcmpPacketHeader_hex()
                icmpPacket.printIcmpPacket_hex()
        
        # Calculates the statistics for RTT
        if rtt_list:
            min_rtt = min(rtt_list)
            max_rtt = max(rtt_list)
            avg_rtt = sum(rtt_list) / len(rtt_list)
        else:
            min_rtt = max_rtt = avg_rtt = 0

        # percentage for packet loss
        packet_loss = ((sent_count - received_count) / sent_count) * 100

        print("\n---- Ping statistics ----")
        print("%d packets transmitted, %d packets received, %.1f%% packet loss" %
              (sent_count, received_count, packet_loss))
        print("round-trip min/avg/max = %.0f/%.0f/%.0f ms" % (min_rtt, avg_rtt, max_rtt))

    def __sendIcmpTraceRoute(self, host):
    # Sources: https://docs.python.org/3/library/socket.html, https://abdesol.medium.com/lets-make-a-trace-routing-tool-from-scratch-with-python-f2f6f78c3c55
    # https://rednafi.com/python/implement_traceroute_in_python/, https://python.plainenglish.io/python-traceroute-with-a-visualization-like-in-the-hacker-movie-scene-179abcb74dc8
        timeout = 2.0 

        # Check host
        try:
            destinationIp = gethostbyname(host.strip())
        except gaierror:
            print(f"Cannot resolve '{host}': Unknown host")
            return

        print(f"Tracing route to {host} [{destinationIp}].\n")

        ttl = 1
        try:
            while True:
                # Build a new ICMP packet for each TTL
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                icmpPacket.setIcmpTarget(host)
                icmpPacket.setTtl(ttl)

                # Use the process ID for the identifier, plus the current TTL as sequence number
                randomIdentifier = (os.getpid() & 0xffff)
                icmpPacket.buildPacket_echoRequest(
                    packetIdentifier=randomIdentifier,
                    packetSequenceNumber=ttl
                )

                # Create a raw socket and set its TTL
                mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                mySocket.settimeout(timeout)
                mySocket.bind(("", 0))
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))

                # Send the packet
                startTime = time.time()
                try:
                    mySocket.sendto(b''.join([icmpPacket._IcmpPacket__header,
                                            icmpPacket._IcmpPacket__data]),
                                    (destinationIp, 0))
                except Exception as e:
                    print(f"Failed to send ICMP packet: {e}")
                    mySocket.close()
                    return

                # Waiting for a reply
                addr = None
                icmpType = -1
                icmpCode = -1
                try:
                    ready = select.select([mySocket], [], [], timeout)
                    if ready[0] == []:
                        print(f"TTL={ttl}\t*        Request timed out.")
                    else:
                        recvPacket, addr = mySocket.recvfrom(1024)
                        endTime = time.time()

                        # Extract the ICMP type and code 
                        icmpType, icmpCode = recvPacket[20:22]
                        rtt_ms = (endTime - startTime) * 1000

                        # Print results depending on ICMP type
                        if icmpType == 0:
                            print(f"TTL={ttl}\tRTT={rtt_ms:.0f} ms\tType={icmpType}\tCode={icmpCode}\tDestination {addr[0]}")
                            print("\nTrace complete.")
                            mySocket.close()
                            return
                        elif icmpType == 11:
                            print(f"TTL={ttl}\tRTT={rtt_ms:.0f} ms\tType={icmpType}\tCode={icmpCode}\t(Time to Live exceeded in transit) {addr[0]}")
                        elif icmpType == 3:
                            print(f"TTL={ttl}\tRTT={rtt_ms:.0f} ms\tType={icmpType}\tCode={icmpCode}\t(Host Unreachable) {addr[0]}")
                            print("\nTrace ended: Destination unreachable.")
                            mySocket.close()
                            return
                        else:
                            print(f"TTL={ttl}\tRTT={rtt_ms:.0f} ms\tType={icmpType}\tCode={icmpCode}\t{addr[0]}")
                except timeout:
                    print(f"TTL={ttl}\t*        Request timed out.")
                finally:
                    mySocket.close()

                ttl += 1  # Increment TTL for the next hop

        # ctrl c exit
        except KeyboardInterrupt:
            print("\nTrace stopped by user.")


    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("192.0.2.1")
    # icmpHelperPing.traceRoute("122.56.99.243") # type 11 and type 3 (1)
    # icmpHelperPing.traceRoute("200.10.277.250")
    # icmpHelperPing.traceRoute("www.cam.ac.uk") www.ui.ac.id
    icmpHelperPing.traceRoute("www.ui.ac.id")


if __name__ == "__main__":
    main()
