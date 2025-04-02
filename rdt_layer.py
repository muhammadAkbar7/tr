from segment import Segment

    # Citation for the following code
    # Date: 02/26/25
    # Adopted/modifed/based code on:
    # https://gaia.cs.umass.edu/kurose_ross/index.php, https://scis.uohyd.ac.in/~atulcs/computernetworks/lab5.html, https://www.cs.swarthmore.edu/~chaganti/cs43/f19/labs/lab6.html, https://nehakaranjkar.github.io/ProtocolSimulation.html, https://wiki.eecs.yorku.ca/course_archive/2012-13/W/3214/_media/chapter_3_v6_jan2013_part3_4slide.pdf

# #################################################################################################################### #
# RDTLayer                                                                                                             #
#                                                                                                                      #
# Description:                                                                                                         #
# The reliable data transfer (RDT) layer is used as a communication layer to resolve issues over an unreliable         #
# channel.                                                                                                             #
#                                                                                                                      #
#                                                                                                                      #
# Notes:                                                                                                               #
# This file is meant to be changed.                                                                                    #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


class RDTLayer(object):
    # ################################################################################################################ #
    # Class Scope Variables                                                                                            #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    DATA_LENGTH = 4 # in characters                     # The length of the string data that will be sent per packet...
    FLOW_CONTROL_WIN_SIZE = 15 # in characters          # Receive window size for flow-control
    TIMEOUT_ITERATIONS = 2  # set timeout window to 2 iterations
    sendChannel = None
    receiveChannel = None
    dataToSend = ''
    currentIteration = 0                              

    # ################################################################################################################ #
    # __init__()                                                                                                       #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __init__(self):
        self.sendChannel = None
        self.receiveChannel = None
        self.dataToSend = ''
        self.currentIteration = 0
        # Add items as needed
        self.dataReceived = "" 
        # Sent
        self.nextSeqSend = 0         # Next character index to send
        self.lastAckReceived = -1    # Highest acknowledged index
        self.sentSegments = {}       # Cache of sent segments
        # Received
        self.nextSeqExpected = 0     # Next expected character index
        self.countSegmentTimeouts = 0


    # ################################################################################################################ #
    # setSendChannel()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable sending lower-layer channel                                                 #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setSendChannel(self, channel):
        self.sendChannel = channel

    # ################################################################################################################ #
    # setReceiveChannel()                                                                                              #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable receiving lower-layer channel                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setReceiveChannel(self, channel):
        self.receiveChannel = channel

    # ################################################################################################################ #
    # setDataToSend()                                                                                                  #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the string data to send                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setDataToSend(self,data):
        self.dataToSend = data

    # ################################################################################################################ #
    # getDataReceived()                                                                                                #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to get the currently received and buffered string data, in order                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def getDataReceived(self):
        # ############################################################################################################ #
        # Identify the data that has been received...

        print('getDataReceived():' + self.dataReceived)
        return self.dataReceived

    # ################################################################################################################ #
    # processData()                                                                                                    #Description:                                                                                                     #
    # "timeslice". Called by main once per iteration  ################################################################################################################ #
    def processData(self):
        self.currentIteration += 1

        # Check for timeouts
        for seq, seg in list(self.sentSegments.items()):
            if (self.currentIteration - seg.getStartIteration()) >= RDTLayer.TIMEOUT_ITERATIONS:
                print("Segment with seq", seq, "timed out. Retransmitting.")
                self.countSegmentTimeouts += 1
                # helps with checksum errors
                data_chunk = self.dataToSend[seq : seq + RDTLayer.DATA_LENGTH]
                new_seg = Segment()
                new_seg.setData(str(seq), data_chunk)
                new_seg.setStartIteration(self.currentIteration)
                # Update the cache with the new segment.
                self.sentSegments[seq] = new_seg
                self.sendChannel.send(new_seg)
        
        # Send segments
        self.processSend()
        
        self.processReceiveAndSendRespond()

    # ################################################################################################################ #
    # processSend()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment sending tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processSend(self):
        while (self.nextSeqSend < len(self.dataToSend) and 
            (self.nextSeqSend - (self.lastAckReceived + 1)) < RDTLayer.FLOW_CONTROL_WIN_SIZE):
            segmentSend = Segment()
            data_chunk = self.dataToSend[self.nextSeqSend : self.nextSeqSend + RDTLayer.DATA_LENGTH]
            seqnum_str = str(self.nextSeqSend)
            segmentSend.setData(seqnum_str, data_chunk)
            # keep track of iteration 
            segmentSend.setStartIteration(self.currentIteration)
            print("processSend(): Sending segment:", segmentSend.to_string())
            
            # save segment incase of timeout and retransmission 
            self.sentSegments[self.nextSeqSend] = segmentSend
            
            # Send the segment via the unreliable send channel.
            self.sendChannel.send(segmentSend)
            
            # Move the pointer forward by the number of characters sent
            self.nextSeqSend += len(data_chunk)

    def processReceiveAndSendRespond(self):
        segmentAck = Segment()  
        listIncomingSegments = self.receiveChannel.receive()

        for seg in listIncomingSegments:
            # Process segments with acknolegments 
            if seg.acknum != -1:
                ack_val = int(seg.acknum)
                if ack_val > self.lastAckReceived:
                    self.lastAckReceived = ack_val
                    keys_to_remove = [k for k in self.sentSegments if k < ack_val]
                    for key in keys_to_remove:
                        del self.sentSegments[key]
                continue

            # Process data segments
            elif seg.seqnum != -1:
                if not seg.checkChecksum():
                    print("Checksum error in received segment:", seg.to_string())
                    continue
                seg_seq = int(seg.seqnum)
                # meant to work only if no checksum error and in-order, adds to dataReceived (ouput)
                if seg_seq == self.nextSeqExpected:
                    self.dataReceived += seg.payload
                    self.nextSeqExpected += len(seg.payload)
                    print("Received in-order segment. Updated dataReceived:", self.dataReceived)
                else:
                    print("Discarding out-of-order segment. Expected:", self.nextSeqExpected, "Got:", seg_seq)

        acknum_str = str(self.nextSeqExpected)
        segmentAck.setAck(acknum_str)
        print("Sending ack:", segmentAck.to_string())
        self.sendChannel.send(segmentAck)