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
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.pcap4j.core.*;
import org.pcap4j.util.*;
import org.pcap4j.sample.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.factory.*;
import org.pcap4j.packet.namednumber.NamedNumber;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.selector.*;
import ch.qos.logback.core.joran.spi.*;

/**
 *
 * @author Ahmed
 */
public class Capturer {

    private FXMLDocumentController controller;
    private List<PcapIf> alldevs;
    private StringBuilder errbuf;
    private Pcap pcap;
    private List detailedView;
    private List hexaView;
    private int number = 0;
    private double startTimeInSeconds;
    private boolean captureStart = false;

    protected Capturer(FXMLDocumentController controller) {
        this.controller = controller;
        detailedView = new ArrayList();
        hexaView = new ArrayList();
    }

    private double getCurrentTime() {
        return System.currentTimeMillis() / 1000.0;
    }

    private static DnsPacket getDnsPacket(PcapPacket p){
        Udp udp = new Udp();
        if(p.hasHeader(udp)){
            try{
                return DnsPacket.newPacket(udp.getPayload(), 0, udp.getPayloadLength());
            }catch(Exception e){
                return null;
            }
        }else return null;
    }
    protected List getDevices() {

        List devices = new ArrayList();
        alldevs = new ArrayList(); // Will be filled with NICs  
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
        return (String) hexaView.get(packetNum);
    }

    protected String getDetailedData(int packetNum) {
        return ((StringBuilder) detailedView.get(packetNum)).toString();
    }

    protected void startCapturing(int deviceNum) {

        PcapIf device = alldevs.get(deviceNum);
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 60 * 1000;           // 60 seconds in millis  
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
            private Icmp icmp = new Icmp();
            private DnsPacket dns;
            private boolean packetCaptured = false;

            @Override
            public void nextPacket(PcapPacket packet, String user) {

                if (!packetCaptured) {
                    pcap.setTimeout(Pcap.DEFAULT_TIMEOUT);
                    packetCaptured = true;
                }
                String protocol = null;
                List row = new ArrayList();
                dns = getDnsPacket(packet);
                if (packet.hasHeader(eth) && (packet.hasHeader(arp) || (packet.hasHeader(ip) && (packet.hasHeader(icmp) || packet.hasHeader(tcp) || packet.hasHeader(udp))))) {
                    detailedView.add(new StringBuilder(packet.toString()));
                    hexaView.add(packet.toHexdump());
                    row.add(number++);
                    row.add(((int) ((getCurrentTime() - startTimeInSeconds) * 10000)) / 10000.0);

                    if (packet.hasHeader(arp) && packet.hasHeader(eth)) {
                        row.add(FormatUtils.mac(eth.source()));
                        row.add(FormatUtils.mac(eth.destination()));
                        protocol = "ARP";
                    } else if (packet.hasHeader(ip)) {
                        row.add(FormatUtils.ip(ip.source()));
                        row.add(FormatUtils.ip(ip.destination()));
                        if (packet.hasHeader(udp)) {
                            protocol = "UDP";
                            if(dns != null){
                                protocol = "DNS";
                            }
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
                                StringBuilder detailedData = (StringBuilder) detailedView.get(detailedView.size()-1);
                                detailedData.append("HTTP-reassembly").append(str);
                                //System.out.println(str);
                            }
                        } else if (packet.hasHeader(icmp)) {
                            protocol = "ICMP";
                        }
                    }

                    row.add(protocol);
                    row.add(packet.getTotalSize());
                    row.add("");
                    controller.addToTable(row);
                }
                

                // JFormatterTextFormatter;
                //System.out.println(detailedData);
            }
        };

        startTimeInSeconds = getCurrentTime();
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");

    }

}
