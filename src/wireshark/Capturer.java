/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wireshark;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author Ahmed
 */
public class Capturer {

    private FXMLDocumentController controller;
    private List<PcapIf> alldevs;
    private StringBuilder errbuf;
    private Pcap pcap;
    private ArrayList<ArrayList<String>> rows;
    private ArrayList<String> detailedView;
    private ArrayList<String> hexaView;
    private int number = 0;
    private double startTimeInSeconds;
    private boolean captureStart = false;

    protected Capturer(FXMLDocumentController controller) {
        this.controller = controller;
        rows = new ArrayList<>();
        detailedView = new ArrayList<>();
        hexaView = new ArrayList<>();
    }

    private double getCurrentTime() {
        return System.currentTimeMillis() / 1000.0;
    }

    protected List getDevices() {

        List<String> devices = new ArrayList<String>();
        alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        errbuf = new StringBuilder(); // For any error msgs  
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.ERROR || alldevs.isEmpty()) {
            return null;
        }

        for (PcapIf device : alldevs) {
            String deviceName
                    = (device.getDescription() != null) ? device.getDescription()
                    : device.getName();
            devices.add(deviceName);
        }
        return devices;
    }

    protected void stopCapturing() {
        pcap.breakloop();
    }

    protected String getHex(int packetNum) {
        return hexaView.get(packetNum);
    }

    protected void startCapturing(int deviceNum) {
        
        PcapIf device = alldevs.get(deviceNum);
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 1000 * 1000;           // 1000 seconds in millis  
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            private Ethernet eth = new Ethernet();
            private Http http = new Http();
            private Tcp tcp = new Tcp();
            private Ip4 ip = new Ip4();
            private Arp arp = new Arp();
            private Udp udp = new Udp();

            @Override
            public void nextPacket(PcapPacket packet, String user) {
                try {
                    String protocol = null;
                    //http example  
                    ArrayList<String> row = new ArrayList<>();
                    rows.add(row);
                    if ((packet.hasHeader(arp) && packet.hasHeader(eth)) || (packet.hasHeader(ip) && (packet.hasHeader(tcp) || packet.hasHeader(udp)))) {
                        detailedView.add(packet.toString());
                        hexaView.add(packet.toHexdump());
                        row.add(number + "");
                        row.add((getCurrentTime() - startTimeInSeconds) + "");
                    }
                    if (packet.hasHeader(arp) && packet.hasHeader(eth)) {
                        row.add(FormatUtils.mac(eth.source()));
                        row.add(FormatUtils.mac(eth.destination()));
                        protocol = "ARP";
                    } else if (packet.hasHeader(ip)) {
                        row.add(FormatUtils.ip(ip.source()));
                        row.add(FormatUtils.ip(ip.destination()));
                        if (packet.hasHeader(udp)) {
                            protocol = "UDP";
                        } else if (packet.hasHeader(tcp)) {
                            protocol = "TCP";
                            if (packet.hasHeader(http)) {
                                if (!http.isResponse()) {
                                    protocol = "HTTP";
                                } else {
                                    int contentLength = Integer.parseInt((http.fieldValue(Http.Response.Content_Length) != null) ? http.fieldValue(Http.Response.Content_Length) : "5555555");
                                    if (http.getPayload().length < contentLength) {
                                        HttpHandler.initiateHttpPacket(number, tcp.seq(), tcp.getPayloadLength(), contentLength, http.getPayload());
                                    } else {
                                        protocol = "HTTP";
                                    }
                                }
                            }
                            String str = HttpHandler.handleForHttpIfExpected(tcp.seq(), tcp.getPayloadLength(), number, tcp.getPayload());
                            if (str != null) {
                                protocol = "HTTP";
                            }
                        }
                    }

                    row.add(protocol);
                    row.add(packet.getTotalSize() + "");
                    row.add("");
                    controller.addToTable(row);
                    number++;
                } catch (Exception e) {
                }
            }
        };

        startTimeInSeconds = getCurrentTime();
        pcap.loop(1000000, jpacketHandler, "");

    }

}
