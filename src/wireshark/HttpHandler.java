/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

/**
 *
 * @author fadia
 */
import java.util.HashMap;

public class HttpHandler {
    private static final HashMap<String, HttpHelperData> httpPackets = new HashMap<>();
    
    public static void initiateHttpPacket(int tcpPacketNumber, long seqNumber, int tcpPacketLength, int httpContentLength, byte[] httpPayload) {
        httpPackets.put((seqNumber + tcpPacketLength) + "", new HttpHelperData(httpContentLength, tcpPacketNumber, httpPayload));
        //System.out.println("Expected seq No." + (seqNumber + tcpPacketLength));
    }

    public static String handleForHttpIfExpected(long expectedSeqNum, int tcpPacketLength, int num, byte[] contentPiece) {
        HttpHelperData httpData = httpPackets.get(expectedSeqNum + "");
        if (httpData != null) {
            String str = httpData.handleExpectedSeqNum(num, contentPiece);
            httpPackets.remove(expectedSeqNum + "");
            if (str.equals("more")) {
                httpPackets.put((expectedSeqNum + tcpPacketLength) + "", httpData);
                return null;
            }
            return str;
        } else {
            return null;
        }
    }
}
